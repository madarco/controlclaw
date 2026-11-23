//! Outside AI apps on the brain: the store (`clients.rs`) and the OAuth routes (`oauth.rs`).

use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use base64::Engine;
use cc_http::{Router, json as json_resp};
use cc_proc::{RecordingRunner, ok};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::*;
use crate::gbrain::gate::BrainGate;
use crate::gbrain::oauth::{self, Public};

const T1: &str = "gbrain_cccccccccccccccccccccccccccccccccccccccc";
const T2: &str = "gbrain_dddddddddddddddddddddddddddddddddddddddd";
const VERIFIER: &str = "a-verifier-that-is-long-enough-for-pkce-0123456789";
const NOW: i64 = 1_800_000_000_000;
/// The approval secret the Connect page that asked holds, and its sha256 the firewall passes on.
const APPROVAL: &str = "the-connect-pages-approval-secret";

fn approval_hash() -> String {
    hex::encode(Sha256::digest(APPROVAL.as_bytes()))
}

fn finish(c: &BrainClients, s: &Started, now: i64) -> Finish {
    c.finish(&s.req, Some(&s.browser), Some(APPROVAL), "https://b.example", now)
}

fn code_url(f: Finish) -> String {
    match f {
        Finish::Code(u) => u,
        other => panic!("no code: {other:?}"),
    }
}

fn challenge_of(v: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(v.as_bytes()))
}

/// The token helper: T1 on the first create, T2 after.
fn helper() -> RecordingRunner {
    let r = RecordingRunner::new();
    let n = Arc::new(AtomicUsize::new(0));
    r.answer_with(move |c| {
        (c.args.get(1).map(String::as_str) == Some("create")).then(|| {
            ok(&format!(
                "{}\n",
                if n.fetch_add(1, Ordering::SeqCst) == 0 { T1 } else { T2 }
            ))
        })
    });
    r.answer(&["sudo"], ok("revoked\n"));
    r
}

fn args(r: &RecordingRunner) -> Vec<Vec<String>> {
    r.calls().into_iter().map(|c| c.args[1..].to_vec()).collect()
}

fn code_of(url: &str) -> String {
    url::Url::parse(url)
        .expect("url")
        .query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.into_owned())
        .expect("code")
}

/// Register, sign in and approve: the store with one client `c1`, and the app's client id and code.
async fn approved(c: &BrainClients, scope: &str, expires: Option<&str>) -> (String, String) {
    let (reg, secret) = c
        .register(
            "Claude",
            vec!["https://claude.ai/api/mcp/auth_callback".into()],
            false,
            NOW,
        )
        .expect("register");
    assert!(secret.is_none());
    let s = c
        .begin(
            &reg.client_id,
            "https://claude.ai/api/mcp/auth_callback",
            &challenge_of(VERIFIER),
            Some("s1".into()),
            NOW,
        )
        .expect("begin");
    assert_eq!(
        c.request_info(&s.req, NOW),
        Some(json!({"name": "Claude", "site": "claude.ai", "approved": false}))
    );
    // Not approved yet: the browser waits.
    assert_eq!(finish(c, &s, NOW), Finish::Waiting);
    let input = parse_connect(
        json!({"id": "c1", "req": s.req, "approval": approval_hash(), "scope": scope, "expiresAt": expires})
            .as_object(),
        NOW,
    )
    .expect("input");
    c.connect(&input, NOW).await.expect("connect");
    // The sign-in's id alone, or with only one of the two secrets, gets no code.
    assert_eq!(c.finish(&s.req, None, None, "https://b.example", NOW), Finish::NotHere);
    assert_eq!(
        c.finish(&s.req, None, Some(APPROVAL), "https://b.example", NOW),
        Finish::NotHere
    );
    assert_eq!(
        c.finish(&s.req, Some(&s.browser), None, "https://b.example", NOW),
        Finish::Waiting
    );
    assert_eq!(
        c.finish(
            &s.req,
            Some("another-browser"),
            Some(APPROVAL),
            "https://b.example",
            NOW
        ),
        Finish::NotHere
    );
    assert_eq!(
        c.finish(&s.req, Some(&s.browser), Some("a-guess"), "https://b.example", NOW),
        Finish::Waiting
    );
    let to = code_url(finish(c, &s, NOW));
    assert!(to.starts_with("https://claude.ai/api/mcp/auth_callback?code="));
    assert!(to.contains("state=s1"));
    assert!(to.contains("iss=https%3A%2F%2Fb.example"));
    (reg.client_id, code_of(&to))
}

fn token_of(a: ClientAdmission) -> String {
    match a {
        ClientAdmission::Token { token, .. } => token,
        other => panic!("not admitted: {other:?}"),
    }
}

#[test]
fn redirect_uris() {
    for ok in [
        "https://claude.ai/api/mcp/auth_callback",
        "https://chatgpt.com/connector_platform_oauth_redirect",
        "http://127.0.0.1:33418/callback",
        "http://localhost:6274/oauth/callback",
        "cursor://anysphere.cursor-mcp/oauth/callback",
    ] {
        assert!(redirect_allowed(ok), "{ok}");
    }
    for bad in [
        "http://evil.example/cb",
        "javascript:alert(1)",
        "data:text/html,x",
        "https://claude.ai/cb#frag",
        "https://user:pw@claude.ai/cb",
        "file:///etc/passwd",
        "custom:/cb",
        "",
    ] {
        assert!(!redirect_allowed(bad), "{bad}");
    }
    let reg = vec![
        "http://127.0.0.1:1000/callback".to_string(),
        "https://a.example/cb".to_string(),
    ];
    assert!(redirect_matches(&reg, "http://127.0.0.1:5555/callback"));
    assert!(!redirect_matches(&reg, "http://127.0.0.1:5555/other"));
    assert!(!redirect_matches(&reg, "http://localhost:5555/callback"));
    assert!(redirect_matches(&reg, "https://a.example/cb"));
    assert!(!redirect_matches(&reg, "https://a.example/cb2"));
    assert_eq!(site_of("cursor://anysphere.cursor-mcp/oauth/callback"), "cursor://");
    assert_eq!(clean_name("  Claude\n\u{7}Desktop  "), "Claude Desktop");
    assert_eq!(clean_name(""), "MCP client");
    assert_eq!(clean_name(&"x".repeat(100)).len(), MAX_NAME);
}

#[test]
fn pkce_and_iso() {
    assert!(pkce_matches(VERIFIER, &challenge_of(VERIFIER)));
    assert!(!pkce_matches("short", &challenge_of("short")));
    assert!(!pkce_matches(
        VERIFIER,
        &challenge_of("another-verifier-that-is-long-enough-000000000")
    ));
    assert_eq!(iso(0), "1970-01-01T00:00:00.000Z");
    assert_eq!(iso(1_800_000_000_123), "2027-01-15T08:00:00.123Z");
    assert_eq!(parse_iso(&iso(NOW)), Some(NOW as f64));
}

#[test]
fn the_connect_body() {
    let b = |v: Value| v.as_object().cloned();
    assert!(parse_connect(b(json!({"id": "c1", "scope": "read"})).as_ref(), NOW).is_ok());
    assert!(parse_connect(b(json!({"id": "c1", "scope": "admin"})).as_ref(), NOW).is_err());
    assert!(parse_connect(b(json!({"id": "../c", "scope": "read"})).as_ref(), NOW).is_err());
    assert_eq!(
        parse_connect(
            b(json!({"id": "c1", "scope": "read", "expiresAt": iso(NOW - 1)})).as_ref(),
            NOW
        ),
        Err("expiresAt is in the past")
    );
    assert_eq!(
        parse_connect(
            b(json!({"id": "c1", "scope": "read", "expiresAt": iso(NOW + 1000)})).as_ref(),
            NOW
        )
        .expect("in")
        .expires_ms,
        Some(NOW + 1000)
    );
}

#[tokio::test]
async fn an_app_signs_in_uses_the_brain_and_is_removed() {
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("gbrain-clients.json");
    let r = helper();
    let c = BrainClients::new(&path, Arc::new(r.clone()));
    let (client_id, code) = approved(&c, "read_write", None).await;
    assert_eq!(args(&r)[0], ["create", "client-c1", "read_write"]);

    // The wrong verifier spends the code.
    assert_eq!(
        c.exchange_code(
            &code,
            &client_id,
            None,
            "wrong-verifier-that-is-long-enough-00000000000",
            None,
            NOW
        ),
        Err("invalid_grant")
    );
    assert_eq!(
        c.exchange_code(&code, &client_id, None, VERIFIER, None, NOW),
        Err("invalid_grant")
    );

    // A new sign-in for the same client, approved again (scope unchanged: no new GBrain token).
    let s = c
        .begin(
            &client_id,
            "https://claude.ai/api/mcp/auth_callback",
            &challenge_of(VERIFIER),
            None,
            NOW,
        )
        .expect("begin");
    c.connect(
        &parse_connect(
            json!({"id": "c1", "req": s.req, "approval": approval_hash(), "scope": "read_write"}).as_object(),
            NOW,
        )
        .expect("in"),
        NOW,
    )
    .await
    .expect("connect");
    assert_eq!(r.calls().len(), 1);
    let code = code_of(&code_url(finish(&c, &s, NOW)));
    // A second load of the return page hands back the same code, not a new one.
    assert_eq!(code_of(&code_url(finish(&c, &s, NOW))), code);
    let g = c
        .exchange_code(
            &code,
            &client_id,
            Some("https://claude.ai/api/mcp/auth_callback"),
            VERIFIER,
            None,
            NOW,
        )
        .expect("grant");
    assert_eq!(g.scope, "read write");
    assert_eq!(g.expires_in, ACCESS_MS / 1000);
    // A code is good once.
    assert_eq!(
        c.exchange_code(&code, &client_id, None, VERIFIER, None, NOW),
        Err("invalid_grant")
    );

    assert_eq!(token_of(c.admit(&g.access, false, NOW)), T1);
    // The emergency stop.
    assert_eq!(c.admit(&g.access, true, NOW), ClientAdmission::Stopped);
    // A refresh token is not an access token, and anything GBrain made is unknown here.
    assert_eq!(c.admit(&g.refresh, false, NOW), ClientAdmission::Unknown);
    assert_eq!(c.admit(T1, false, NOW), ClientAdmission::Unknown);
    // The access token runs out; the refresh token gives a new pair, once.
    assert_eq!(c.admit(&g.access, false, NOW + ACCESS_MS + 1), ClientAdmission::Unknown);
    let g2 = c
        .refresh(&g.refresh, &client_id, None, NOW + ACCESS_MS + 1)
        .expect("refresh");
    assert_eq!(
        c.refresh(&g.refresh, &client_id, None, NOW + ACCESS_MS + 2),
        Err("invalid_grant")
    );
    assert_eq!(c.refresh(&g2.refresh, "ccbc_other", None, NOW), Err("invalid_client"));
    assert_eq!(token_of(c.admit(&g2.access, false, NOW + ACCESS_MS + 2)), T1);

    // Kept 0600, hashes only: neither the app's tokens nor the code are in the file.
    assert_eq!(
        std::fs::metadata(&path).expect("meta").permissions().mode() & 0o777,
        0o600
    );
    let file = std::fs::read_to_string(&path).expect("file");
    assert!(!file.contains(&g2.access) && !file.contains(&g2.refresh));
    // The firewall's list has no tokens.
    let list = serde_json::to_string(&c.list()).expect("s");
    assert!(!list.contains(T1));
    assert_eq!(c.list()[0]["scope"], "read_write");

    // It survives a restart.
    let again = BrainClients::new(&path, Arc::new(r.clone()));
    assert_eq!(token_of(again.admit(&g2.access, false, NOW + ACCESS_MS + 3)), T1);

    // Read only: a new GBrain token with the narrower scope, same app tokens.
    c.connect(
        &parse_connect(json!({"id": "c1", "scope": "read"}).as_object(), NOW).expect("in"),
        NOW,
    )
    .await
    .expect("narrow");
    assert_eq!(args(&r).last().expect("call"), &["create", "client-c1", "read"]);
    assert_eq!(token_of(c.admit(&g2.access, false, NOW + ACCESS_MS + 3)), T2);

    assert_eq!(c.disconnect("c1").await, Ok(true));
    assert_eq!(args(&r).last().expect("call"), &["revoke", "client-c1"]);
    assert_eq!(
        c.admit(&g2.access, false, NOW + ACCESS_MS + 3),
        ClientAdmission::Unknown
    );
    assert!(c.list().is_empty());
}

#[tokio::test]
async fn the_end_date_caps_every_token() {
    let dir = tempfile::tempdir().expect("dir");
    let c = BrainClients::new(&dir.path().join("c.json"), Arc::new(helper()));
    let end = NOW + 10 * 60_000;
    let (client_id, code) = approved(&c, "read", Some(&iso(end))).await;
    let g = c
        .exchange_code(&code, &client_id, None, VERIFIER, None, NOW)
        .expect("grant");
    assert_eq!(g.expires_in, 600);
    assert!(matches!(
        c.admit(&g.access, false, end - 1),
        ClientAdmission::Token { .. }
    ));
    assert_eq!(c.admit(&g.access, false, end), ClientAdmission::Expired);
    assert_eq!(c.refresh(&g.refresh, &client_id, None, end), Err("invalid_grant"));

    // An earlier end date, set later, cuts the tokens already out.
    let (client_id, code) = {
        let c2 = &c;
        c2.disconnect("c1").await.expect("gone");
        approved(c2, "read", None).await
    };
    let g = c
        .exchange_code(&code, &client_id, None, VERIFIER, None, NOW)
        .expect("grant");
    c.connect(
        &parse_connect(
            json!({"id": "c1", "scope": "read", "expiresAt": iso(NOW + 1000)}).as_object(),
            NOW,
        )
        .expect("in"),
        NOW,
    )
    .await
    .expect("shorten");
    assert_eq!(c.admit(&g.access, false, NOW + 1000), ClientAdmission::Expired);
    assert_eq!(
        c.refresh(&g.refresh, &client_id, None, NOW + 1000),
        Err("invalid_grant")
    );
}

#[tokio::test]
async fn calls_are_rate_limited_per_client() {
    let dir = tempfile::tempdir().expect("dir");
    let c = BrainClients::new(&dir.path().join("c.json"), Arc::new(helper()));
    let (client_id, code) = approved(&c, "read", None).await;
    let g = c
        .exchange_code(&code, &client_id, None, VERIFIER, None, NOW)
        .expect("grant");
    for _ in 0..120 {
        assert!(matches!(c.admit(&g.access, false, NOW), ClientAdmission::Token { .. }));
    }
    assert_eq!(c.admit(&g.access, false, NOW), ClientAdmission::Limited(1));
    // Two a second come back.
    assert!(matches!(
        c.admit(&g.access, false, NOW + 1000),
        ClientAdmission::Token { .. }
    ));
}

#[tokio::test]
async fn a_sign_in_cannot_be_approved_late_or_twice_for_someone_else() {
    let dir = tempfile::tempdir().expect("dir");
    let c = BrainClients::new(&dir.path().join("c.json"), Arc::new(helper()));
    let (reg, _) = c
        .register(
            "Cursor",
            vec!["cursor://anysphere.cursor-mcp/oauth/callback".into()],
            true,
            NOW,
        )
        .expect("r");
    let s = c
        .begin(
            &reg.client_id,
            "cursor://anysphere.cursor-mcp/oauth/callback",
            &challenge_of(VERIFIER),
            None,
            NOW,
        )
        .expect("begin");
    let late = parse_connect(
        json!({"id": "c9", "req": s.req, "approval": approval_hash(), "scope": "read"}).as_object(),
        NOW,
    )
    .expect("in");
    assert!(c.connect(&late, NOW + PENDING_MS).await.is_err());
    // Another browser learns nothing, not even that it ran out.
    assert_eq!(
        c.finish(&s.req, None, None, "https://b.example", NOW + PENDING_MS),
        Finish::NotHere
    );
    // The app's redirect gets access_denied once the sign-in ran out.
    let Finish::Denied(denied) = finish(&c, &s, NOW + PENDING_MS) else {
        panic!("not denied")
    };
    assert!(denied.starts_with("cursor://anysphere.cursor-mcp/oauth/callback?error=access_denied"));
    // A confidential client must send its secret.
    let s = c
        .begin(
            &reg.client_id,
            "cursor://anysphere.cursor-mcp/oauth/callback",
            &challenge_of(VERIFIER),
            None,
            NOW,
        )
        .expect("begin");
    // A sign-in is never approved without the approval secret's hash.
    assert!(parse_connect(json!({"id": "c9", "req": s.req, "scope": "read"}).as_object(), NOW).is_err());
    c.connect(
        &parse_connect(
            json!({"id": "c9", "req": s.req, "approval": approval_hash(), "scope": "read"}).as_object(),
            NOW,
        )
        .expect("in"),
        NOW,
    )
    .await
    .expect("connect");
    let other = parse_connect(
        json!({"id": "c10", "req": s.req, "approval": approval_hash(), "scope": "read"}).as_object(),
        NOW,
    )
    .expect("in");
    assert!(c.connect(&other, NOW).await.is_err());
    let code = code_of(&code_url(finish(&c, &s, NOW)));
    assert_eq!(
        c.exchange_code(&code, &reg.client_id, None, VERIFIER, None, NOW),
        Err("invalid_client")
    );
}

#[test]
fn registration_is_checked_and_capped() {
    let dir = tempfile::tempdir().expect("dir");
    let c = BrainClients::new(&dir.path().join("c.json"), Arc::new(helper()));
    assert!(c.register("x", vec![], false, NOW).is_err());
    assert!(
        c.register("x", vec!["http://evil.example/cb".into()], false, NOW)
            .is_err()
    );
    // The first app's sign-in is waiting for a person: its registration must survive the flood.
    let (waiting, _) = c
        .register("Waiting app", vec!["https://w.example/cb".into()], false, NOW - 1)
        .expect("register");
    c.begin(
        &waiting.client_id,
        "https://w.example/cb",
        &challenge_of(VERIFIER),
        None,
        NOW,
    )
    .expect("begin");
    for i in 0..(MAX_REGISTRATIONS + 5) {
        c.register(
            &format!("app {i}"),
            vec!["https://a.example/cb".into()],
            false,
            NOW + i as i64,
        )
        .expect("register");
    }
    // The oldest unused ones went first; one whose sign-in waits is kept.
    assert!(c.registration("nope").is_none());
    assert_eq!(c.st().registrations.len(), MAX_REGISTRATIONS);
    assert_eq!(c.st().registrations[0].name, "Waiting app");
    assert_eq!(c.st().registrations[1].name, "app 6");
    // Each public endpoint has its own bucket: a flood of registrations leaves refreshes alone.
    let mut n = 0;
    while c.take_public(PublicCall::Register, NOW).is_ok() {
        n += 1;
    }
    assert_eq!(n, 20);
    assert!(c.take_token("", None, None, NOW).is_ok());
}

#[tokio::test]
async fn junk_cannot_starve_a_connected_apps_refresh_or_sign_ins() {
    let dir = tempfile::tempdir().expect("dir");
    let c = BrainClients::new(&dir.path().join("c.json"), Arc::new(helper()));
    let (client_id, code) = approved(&c, "read", None).await;
    let g = c
        .exchange_code(&code, &client_id, None, VERIFIER, None, NOW)
        .expect("grant");
    // Junk empties the shared token bucket...
    while c.take_token("ccbc_nobody", Some("ccbr_junk"), None, NOW).is_ok() {}
    assert!(c.take_token(&client_id, Some("ccbr_junk"), None, NOW).is_err());
    // ...but a live refresh token is charged to its app's own.
    assert!(c.take_token(&client_id, Some(&g.refresh), None, NOW).is_ok());
    assert!(c.refresh(&g.refresh, &client_id, None, NOW).is_ok());

    // Sign-ins: each app has its own bucket, and its own few waiting places.
    let (other, _) = c
        .register("Other", vec!["https://o.example/cb".into()], false, NOW)
        .expect("register");
    while c.take_authorize(&other.client_id, NOW).is_ok() {}
    assert!(c.take_authorize(&client_id, NOW).is_ok());
    let first = c
        .begin(
            &other.client_id,
            "https://o.example/cb",
            &challenge_of(VERIFIER),
            None,
            NOW,
        )
        .expect("begin");
    for i in 1..=MAX_PENDING_PER_APP as i64 {
        c.begin(
            &other.client_id,
            "https://o.example/cb",
            &challenge_of(VERIFIER),
            None,
            NOW + i,
        )
        .expect("a new sign-in replaces the app's oldest");
    }
    assert!(c.request_info(&first.req, NOW).is_none());
    assert_eq!(
        c.st()
            .pending
            .values()
            .filter(|p| p.client_id == other.client_id)
            .count(),
        MAX_PENDING_PER_APP
    );
    // One a person opened is never the one pushed out; with all of them opened, a new one waits.
    let opened_reqs: Vec<String> = c
        .st()
        .pending
        .iter()
        .filter(|(_, p)| p.client_id == other.client_id)
        .map(|(k, _)| k.clone())
        .collect();
    for r in &opened_reqs {
        assert!(c.request_info(r, NOW).is_some());
    }
    assert!(
        c.begin(
            &other.client_id,
            "https://o.example/cb",
            &challenge_of(VERIFIER),
            None,
            NOW + 9
        )
        .is_err()
    );
    assert!(opened_reqs.iter().all(|r| c.request_info(r, NOW).is_some()));

    // A full list: the app with the most unopened sign-ins gives up its oldest, so a flood pushes
    // out its own; a person's sign-in on its way to the Connect page (older, not opened yet) stays,
    // and so does one a person opened.
    let on_its_way = c
        .begin(
            &client_id,
            "https://claude.ai/api/mcp/auth_callback",
            &challenge_of(VERIFIER),
            None,
            NOW - 20,
        )
        .expect("begin");
    // A person who retried: as many unopened sign-ins as a flood's apps, but registered before them.
    let (retry, _) = c
        .register("Retried", vec!["https://r.example/cb".into()], false, NOW - 1000)
        .expect("register");
    let retried: Vec<String> = (0..MAX_PENDING_PER_APP as i64)
        .map(|i| {
            c.begin(
                &retry.client_id,
                "https://r.example/cb",
                &challenge_of(VERIFIER),
                None,
                NOW - 30 + i,
            )
            .expect("begin")
            .req
        })
        .collect();
    let opened = c
        .begin(
            &client_id,
            "https://claude.ai/api/mcp/auth_callback",
            &challenge_of(VERIFIER),
            None,
            NOW - 10,
        )
        .expect("begin");
    assert!(c.request_info(&opened.req, NOW).is_some());
    for i in 0..(MAX_PENDING / MAX_PENDING_PER_APP + 20) {
        let (r, _) = c
            .register(&format!("flood {i}"), vec!["https://f.example/cb".into()], false, NOW)
            .expect("register");
        for j in 0..MAX_PENDING_PER_APP {
            let at = NOW + (i * MAX_PENDING_PER_APP + j) as i64;
            c.begin(&r.client_id, "https://f.example/cb", &challenge_of(VERIFIER), None, at)
                .expect("begin");
        }
    }
    assert_eq!(c.st().pending.len(), MAX_PENDING);
    assert!(c.request_info(&opened.req, NOW).is_some());
    assert!(c.st().pending.contains_key(&on_its_way.req));
    assert!(retried.iter().all(|r| c.st().pending.contains_key(r)));
}

#[tokio::test]
async fn token_bodies_are_read_only_as_many_at_once_as_the_drain_allows() {
    let body = || http_body_util::Full::new(bytes::Bytes::from_static(b"grant_type=refresh_token"));
    let none = tokio::sync::Semaphore::new(0);
    let r = oauth::token_body(&none, body()).await.expect_err("no slot");
    assert_eq!(r.status(), 429);
    assert_eq!(r.headers()["connection"], "close");
    let one = tokio::sync::Semaphore::new(1);
    assert_eq!(
        oauth::token_body(&one, body()).await.ok().as_deref(),
        Some(&b"grant_type=refresh_token"[..])
    );
    // The slot is given back once the body is read.
    assert_eq!(one.available_permits(), 1);
    // Too large: refused, and the half-read connection is not kept.
    let big = http_body_util::Full::new(bytes::Bytes::from(vec![b'x'; 32 * 1024]));
    let r = oauth::token_body(&one, big).await.expect_err("too large");
    assert_eq!(r.status(), 400);
    assert_eq!(r.headers()["connection"], "close");
    assert_eq!(one.available_permits(), 1);
}

// ---- over HTTP ----

/// The path and the Authorization each call reached GBrain with, and whether a cookie or a
/// forwarding header came along.
type Seen = Arc<std::sync::Mutex<Vec<(String, Option<String>, bool)>>>;

struct Upstream {
    addr: String,
    seen: Seen,
}

/// GBrain on a random port: records the path and the Authorization it got.
async fn gbrain() -> Upstream {
    let seen: Seen = Arc::default();
    let s = seen.clone();
    let mut router = Router::new(&["all"]);
    router.route(
        "all",
        |_, _| true,
        move |req, _| {
            let s = s.clone();
            async move {
                let auth = req
                    .headers()
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .map(String::from);
                let extra = req
                    .headers()
                    .keys()
                    .any(|k| k == "cookie" || k == "forwarded" || k.as_str().starts_with("x-forwarded-"));
                s.lock().expect("seen").push((req.uri().to_string(), auth, extra));
                json_resp(200, &json!({"jsonrpc": "2.0", "result": {}}))
            }
        },
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr").to_string();
    tokio::spawn(cc_http::serve(listener, Arc::new(router)));
    Upstream { addr, seen }
}

async fn brain(clients: Arc<BrainClients>, gate: Arc<BrainGate>, target: String) -> String {
    let public = Arc::new(Public {
        clients,
        gate,
        host: Arc::new(|| Some("brain-x.ccl.bot".into())),
        console: Arc::new(|| Some("https://console.example".into())),
        target,
    });
    let mut router = Router::new(&["brain-open"]);
    router.route(
        "brain-open",
        |_, p| oauth::is_public_path(p),
        move |req, ctx| {
            let p = public.clone();
            async move { oauth::handle(&p, req, ctx).await }
        },
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr").to_string();
    tokio::spawn(cc_http::serve(listener, Arc::new(router)));
    format!("http://{addr}")
}

fn no_redirects() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("client")
}

#[tokio::test]
async fn the_whole_flow_over_http() {
    let dir = tempfile::tempdir().expect("dir");
    let r = helper();
    let clients = Arc::new(BrainClients::new(&dir.path().join("c.json"), Arc::new(r.clone())));
    let gate = Arc::new(BrainGate::new(&dir.path().join("g.json"), Arc::new(r.clone())));
    let up = gbrain().await;
    let base = brain(clients.clone(), gate.clone(), up.addr.clone()).await;
    let http = no_redirects();

    // No token: 401 with where to sign in.
    let res = http.post(format!("{base}/mcp")).body("{}").send().await.expect("send");
    assert_eq!(res.status(), 401);
    assert_eq!(
        res.headers()["www-authenticate"],
        "Bearer resource_metadata=\"https://brain-x.ccl.bot/.well-known/oauth-protected-resource\""
    );
    // A short refused body is read and the connection kept; a long one is not read, and closed.
    assert!(res.headers().get("connection").is_none());
    let res = http
        .post(format!("{base}/mcp"))
        .body(vec![b'x'; 256 * 1024])
        .send()
        .await
        .expect("send");
    assert_eq!(res.status(), 401);
    assert_eq!(res.headers()["connection"], "close");
    let meta: Value = http
        .get(format!("{base}/.well-known/oauth-authorization-server"))
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert_eq!(meta["token_endpoint"], "https://brain-x.ccl.bot/oauth/token");
    assert_eq!(meta["code_challenge_methods_supported"], json!(["S256"]));

    let reg: Value = http
        .post(format!("{base}/oauth/register"))
        .json(&json!({"client_name": "Claude Code", "redirect_uris": ["http://localhost:4000/callback"]}))
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    let client_id = reg["client_id"].as_str().expect("id").to_string();
    assert_eq!(reg["token_endpoint_auth_method"], "none");

    // The sign-in goes to the console, with the app's name and site.
    let res = http
        .get(format!("{base}/oauth/authorize"))
        .query(&[
            ("response_type", "code"),
            ("client_id", &client_id),
            ("redirect_uri", "http://localhost:51234/callback"),
            ("code_challenge", &challenge_of(VERIFIER)),
            ("code_challenge_method", "S256"),
            ("state", "xyz"),
            ("resource", "https://brain-x.ccl.bot/mcp"),
        ])
        .send()
        .await
        .expect("send");
    assert_eq!(res.status(), 302);
    let to = url::Url::parse(res.headers()["location"].to_str().expect("loc")).expect("url");
    assert_eq!(
        to.as_str().split('?').next(),
        Some("https://console.example/dashboard/brain/connect")
    );
    let q: std::collections::HashMap<String, String> = to.query_pairs().into_owned().collect();
    assert_eq!(q["brain"], "brain-x.ccl.bot");
    assert_eq!(q["name"], "Claude Code");
    assert_eq!(q["site"], "localhost");
    let req = q["req"].clone();
    // The browser that started it gets a host-only cookie; the console link carries no secret.
    let set = res.headers()["set-cookie"].to_str().expect("cookie").to_string();
    assert!(set.starts_with(&format!("{}=", browser_cookie(&req))));
    for part in ["Path=/", "Secure", "HttpOnly", "SameSite=Lax"] {
        assert!(set.contains(part), "{set}");
    }
    assert!(!set.contains("Domain"));
    let browser_cookie_kv = set.split(';').next().expect("kv").to_string();

    // An unregistered redirect is never followed.
    let res = http
        .get(format!("{base}/oauth/authorize"))
        .query(&[
            ("response_type", "code"),
            ("client_id", &client_id),
            ("redirect_uri", "https://evil.example/cb"),
        ])
        .send()
        .await
        .expect("send");
    assert_eq!(res.status(), 400);
    // No PKCE, or a response type it does not offer: a page, never a redirect to the app (an app
    // that registered evil.example would make this an open redirector).
    for extra in [
        vec![("state", "s")],
        vec![
            ("response_type", "x"),
            ("code_challenge", "c"),
            ("code_challenge_method", "S256"),
        ],
    ] {
        let mut q = vec![
            ("client_id", client_id.as_str()),
            ("redirect_uri", "http://localhost:4000/callback"),
        ];
        if !extra.iter().any(|(k, _)| *k == "response_type") {
            q.push(("response_type", "code"));
        }
        q.extend(extra);
        let res = http
            .get(format!("{base}/oauth/authorize"))
            .query(&q)
            .send()
            .await
            .expect("send");
        assert_eq!(res.status(), 400);
        assert!(res.headers().get("location").is_none());
    }

    // Before approval the page says so.
    let done = format!("{base}/oauth/authorize/done?req={req}&approval={APPROVAL}");
    let res = http
        .get(&done)
        .header("cookie", &browser_cookie_kv)
        .send()
        .await
        .expect("send");
    assert_eq!(res.status(), 409);

    // The firewall approves it (after the code).
    clients
        .connect(
            &parse_connect(
                json!({"id": "c1", "req": req, "approval": approval_hash(), "scope": "read"}).as_object(),
                super::super::now_ms(),
            )
            .expect("in"),
            super::super::now_ms(),
        )
        .await
        .expect("connect");
    // Whoever has only the sign-in's id (it is in the console link) gets no code, however often
    // they ask; nor does the starting browser without the Connect page's approval secret.
    for (url, cookie) in [
        (format!("{base}/oauth/authorize/done?req={req}"), None),
        (done.clone(), None),
        (
            format!("{base}/oauth/authorize/done?req={req}"),
            Some(browser_cookie_kv.as_str()),
        ),
        (done.clone(), Some("__Host-cc_signin_0000000000000000=forged")),
    ] {
        let mut r = http.get(&url);
        if let Some(c) = cookie {
            r = r.header("cookie", c);
        }
        let res = r.send().await.expect("send");
        assert!(res.headers().get("location").is_none(), "{url} {cookie:?}");
        assert!(matches!(res.status().as_u16(), 403 | 409));
    }
    let res = http
        .get(&done)
        .header("cookie", format!("other=1; {browser_cookie_kv}"))
        .send()
        .await
        .expect("send");
    assert_eq!(res.status(), 302);
    let back = res.headers()["location"].to_str().expect("loc").to_string();
    assert!(back.starts_with("http://localhost:51234/callback?code="));
    assert!(back.contains("state=xyz"));
    let code = code_of(&back);

    let tok: Value = http
        .post(format!("{base}/oauth/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("client_id", &client_id),
            ("redirect_uri", "http://localhost:51234/callback"),
            ("code_verifier", VERIFIER),
        ])
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    let access = tok["access_token"].as_str().expect("access").to_string();
    assert_eq!(tok["token_type"], "Bearer");
    assert_eq!(tok["scope"], "read");

    // The call reaches GBrain with the client's own GBrain token, never the app's.
    let res = http
        .post(format!("{base}/mcp?x=1"))
        .bearer_auth(&access)
        .header("cookie", &browser_cookie_kv)
        .header("x-forwarded-for", "10.0.0.1")
        .header("x-forwarded-host", "evil.example")
        .body("{}")
        .send()
        .await
        .expect("send");
    assert_eq!(res.status(), 200);
    assert_eq!(
        up.seen.lock().expect("seen").last().cloned(),
        Some(("/mcp?x=1".to_string(), Some(format!("Bearer {T1}")), false))
    );
    // A token GBrain made itself gets nothing.
    let res = http
        .post(format!("{base}/mcp"))
        .bearer_auth(T1)
        .body("{}")
        .send()
        .await
        .expect("send");
    assert_eq!(res.status(), 401);
    assert!(
        res.headers()["www-authenticate"]
            .to_str()
            .expect("h")
            .contains("invalid_token")
    );

    // The organization-wide emergency stop.
    gate.set_lock(crate::gbrain::gate::Lock {
        all: true,
        vm_ids: vec![],
    })
    .expect("lock");
    let res = http
        .post(format!("{base}/mcp"))
        .bearer_auth(&access)
        .body("{}")
        .send()
        .await
        .expect("send");
    assert_eq!(res.status(), 403);
    // A stop on one agent does not touch the apps.
    gate.set_lock(crate::gbrain::gate::Lock {
        all: false,
        vm_ids: vec!["vm-a".into()],
    })
    .expect("lock");
    let res = http
        .post(format!("{base}/mcp"))
        .bearer_auth(&access)
        .body("{}")
        .send()
        .await
        .expect("send");
    assert_eq!(res.status(), 200);

    // A stopped brain: GBrain is not there.
    let stopped = brain(clients.clone(), gate.clone(), "127.0.0.1:9".into()).await;
    let res = http
        .post(format!("{stopped}/mcp"))
        .bearer_auth(&access)
        .body("{}")
        .send()
        .await
        .expect("send");
    assert_eq!(res.status(), 503);

    // Removed: nothing works any more.
    clients.disconnect("c1").await.expect("disconnect");
    let res = http
        .post(format!("{base}/mcp"))
        .bearer_auth(&access)
        .body("{}")
        .send()
        .await
        .expect("send");
    assert_eq!(res.status(), 401);
    // GBrain's own OAuth and admin are not here.
    let res = http.get(format!("{base}/admin")).send().await.expect("send");
    assert_eq!(res.status(), 404);
}
