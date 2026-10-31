//! The parts of the sign-in shim the conformance cases cannot reach: the CLI's answers, the
//! pairing run's retry and sharing, the sandbox's way back and loop guard, and the brain's options.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use base64::Engine;
use cc_testkit::Signer;
use futures_util::FutureExt;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::*;

const HOSTNAME: &str = "agent-1.vm.controlclaw.com";
const BOOT: &str =
    "http://127.0.0.1:18789/#bootstrapToken=abc123&bootstrapProfile=owner&gatewayUrl=ws%3A%2F%2F127.0.0.1%3A18789";

fn failed(reason: &str, retryable: bool) -> DashboardAttempt {
    DashboardAttempt::Failed {
        reason: reason.into(),
        retryable,
    }
}

#[test]
fn a_bootstrap_link_is_rebased_onto_the_box_public_origin() {
    let out = json!({"ok": true, "browserUrl": BOOT}).to_string();
    let DashboardAttempt::Url(u) = parse_dashboard_output(&out, HOSTNAME, &CliEnd::Ok) else {
        panic!("no url");
    };
    assert_eq!(
        u,
        "/#bootstrapToken=abc123&bootstrapProfile=owner&gatewayUrl=wss%3A%2F%2Fagent-1.vm.controlclaw.com"
    );
    let no_token = json!({"ok": true, "browserUrl": "http://127.0.0.1:18789/#x=1"}).to_string();
    assert_eq!(
        parse_dashboard_output(&no_token, HOSTNAME, &CliEnd::Ok),
        failed("the pairing link had no bootstrap token", false)
    );
    let bad = json!({"browserUrl": "not a url"}).to_string();
    assert_eq!(
        parse_dashboard_output(&bad, HOSTNAME, &CliEnd::Ok),
        failed("the pairing link had no bootstrap token", false)
    );
}

#[test]
fn openclaw_own_reason_is_kept_and_a_not_ready_gateway_is_worth_another_try() {
    let end = CliEnd::Failed("Command failed: openclaw dashboard --json --no-open".into());
    let out = json!({"ok": false, "reason": "Gateway is not reachable"}).to_string();
    assert_eq!(
        parse_dashboard_output(&out, HOSTNAME, &end),
        failed("Gateway is not reachable", true)
    );
    assert_eq!(
        parse_dashboard_output(r#"{"ok":false}"#, HOSTNAME, &end),
        failed("OpenClaw could not issue a pairing link", true)
    );
    assert_eq!(
        parse_dashboard_output("garbage", HOSTNAME, &end),
        failed(
            "the OpenClaw CLI failed: Command failed: openclaw dashboard --json --no-open",
            false
        )
    );
    assert_eq!(
        parse_dashboard_output("", HOSTNAME, &CliEnd::Ok),
        failed("the OpenClaw CLI printed nothing usable", false)
    );
}

#[test]
fn a_cli_killed_by_the_clock_is_retried_one_not_installed_is_not() {
    assert_eq!(
        parse_dashboard_output("", HOSTNAME, &CliEnd::Killed),
        failed("the OpenClaw CLI did not answer in time", true)
    );
    assert_eq!(
        parse_dashboard_output("", HOSTNAME, &CliEnd::NotFound),
        failed("the OpenClaw CLI is not installed", false)
    );
}

#[test]
fn the_install_id_follows_the_gateway_token_not_the_hostname() {
    assert_eq!(install_id(Some("token-a"), "vm1"), install_id(Some("token-a"), "vm2"));
    assert_ne!(install_id(Some("token-a"), "vm1"), install_id(Some("token-b"), "vm1"));
    assert_eq!(install_id(None, "vm1"), install_id(None, "vm1"));
    assert_ne!(install_id(None, "vm1"), install_id(None, "vm2"));
    let id = install_id(Some("token-a"), "vm1");
    assert_eq!(id.len(), 16);
    assert!(id.bytes().all(|b| b.is_ascii_hexdigit()));
}

#[test]
fn same_site_by_the_last_two_labels() {
    assert!(same_site(
        Some("https://a.vm.controlclaw.com"),
        Some("https://controlclaw.com")
    ));
    assert!(!same_site(Some("https://a.ccl.bot"), Some("https://controlclaw.com")));
    assert!(same_site(Some("https://a.ccl.bot"), Some("https://b.ccl.bot")));
    assert!(!same_site(None, Some("https://controlclaw.com")));
    assert!(!same_site(Some("not a url"), Some("not a url")));
}

#[test]
fn the_way_back_is_the_sandbox_shell_and_nothing_else() {
    assert_eq!(
        sandbox_return(Some("/mcp-app-sandbox?a=1&b=2")).as_deref(),
        Some("/mcp-app-sandbox?a=1&b=2")
    );
    assert_eq!(
        sandbox_return(Some("/mcp-app-sandbox?")).as_deref(),
        Some("/mcp-app-sandbox")
    );
    for bad in [
        "",
        "//evil.example/mcp-app-sandbox",
        "https://evil.example/mcp-app-sandbox",
        "/mcp-app-sandbox/x",
        "/other",
    ] {
        assert_eq!(sandbox_return(Some(bad)), None, "{bad}");
    }
    assert_eq!(
        sandbox_return(Some(&format!("/mcp-app-sandbox?{}", "a".repeat(4000)))),
        None
    );
}

#[test]
fn bindings_are_43_characters_and_at_most_eight() {
    let v = "a".repeat(43);
    let mut header: Vec<String> = (0..10).map(|i| format!("__Host-cc_bind_{i}={v}")).collect();
    header.push("__Host-cc_bind_short=abc".into());
    header.push(format!("other={v}"));
    let got = bindings(Some(&header.join("; ")));
    assert_eq!(got.len(), 8);
    assert_eq!(got[0].0, "__Host-cc_bind_2");
    assert!(bindings(None).is_empty());
}

#[test]
fn fill_is_one_pass() {
    assert_eq!(fill("a ${x} b ${y}", &[("x", "${y}"), ("y", "2")]), "a ${y} b 2");
    assert_eq!(fill("${unknown} ${", &[]), "${unknown} ${");
}

use crate::boxside::testing::test_box;

#[tokio::test]
async fn two_opens_at_once_share_one_dashboard_run_and_it_is_never_cached() {
    let b = test_box();
    let access = crate::boxside::access(&b.app, None);
    let runs = Arc::new(AtomicUsize::new(0));
    let (tx, rx) = tokio::sync::watch::channel(false);
    let r = runs.clone();
    access.set_dashboard_run(
        Arc::new(move |_h: String, _t: Duration| {
            let (r, mut rx) = (r.clone(), rx.clone());
            async move {
                let n = r.fetch_add(1, Ordering::SeqCst);
                let _ = rx.wait_for(|go| *go).await;
                DashboardAttempt::Url(format!("/#bootstrapToken={n}"))
            }
            .boxed()
        }),
        30_000,
        1,
    );
    let (a1, a2) = (access.clone(), access.clone());
    let both = tokio::spawn(async move {
        tokio::join!(
            a1.dashboard_bootstrap_url("shared.example"),
            a2.dashboard_bootstrap_url("shared.example")
        )
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    tx.send(true).expect("release");
    let (x, y) = both.await.expect("join");
    assert_eq!(runs.load(Ordering::SeqCst), 1, "one process, not two");
    assert_eq!(x, y);
    let again = access.dashboard_bootstrap_url("shared.example").await;
    assert_eq!(again, DashboardAttempt::Url("/#bootstrapToken=1".into()));
    assert_eq!(runs.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_gateway_still_starting_gets_a_second_chance_inside_the_budget() {
    let b = test_box();
    let access = crate::boxside::access(&b.app, None);
    let seen = Arc::new(Mutex::new(Vec::new()));
    let s = seen.clone();
    access.set_dashboard_run(
        Arc::new(move |_h: String, t: Duration| {
            let s = s.clone();
            async move {
                let mut v = s.lock().expect("lock");
                v.push(t);
                if v.len() == 1 {
                    failed("Gateway is not reachable", true)
                } else {
                    DashboardAttempt::Url("/#bootstrapToken=x".into())
                }
            }
            .boxed()
        }),
        30_000,
        1,
    );
    assert_eq!(
        access.dashboard_bootstrap_url(HOSTNAME).await,
        DashboardAttempt::Url("/#bootstrapToken=x".into())
    );
    let seen = seen.lock().expect("lock");
    assert_eq!(seen.len(), 2);
    assert!(
        seen[0] > Duration::from_secs(20),
        "the first attempt gets more than the old 20 s"
    );
}

#[tokio::test]
async fn a_failure_that_will_not_change_is_asked_once() {
    let b = test_box();
    let access = crate::boxside::access(&b.app, None);
    let runs = Arc::new(AtomicUsize::new(0));
    let r = runs.clone();
    access.set_dashboard_run(
        Arc::new(move |_h: String, _t: Duration| {
            r.fetch_add(1, Ordering::SeqCst);
            async { failed("the OpenClaw CLI is not installed", false) }.boxed()
        }),
        30_000,
        1,
    );
    assert_eq!(
        access.dashboard_bootstrap_url(HOSTNAME).await,
        failed("the OpenClaw CLI is not installed", false)
    );
    assert_eq!(runs.load(Ordering::SeqCst), 1);
}

#[test]
fn the_sandbox_loop_guard_allows_ten_tickets_a_minute_per_frame() {
    let b = test_box();
    let access = crate::boxside::access(&b.app, None);
    let cookie = Some("__Host-cc_session=s1");
    for i in 0..10 {
        assert!(access.sandbox_ticket_allowed(cookie, "/mcp-app-sandbox?w=1", 1_000 + i));
    }
    assert!(!access.sandbox_ticket_allowed(cookie, "/mcp-app-sandbox?w=1", 1_100));
    // Another widget of the same board, or another browser, has its own count.
    assert!(access.sandbox_ticket_allowed(cookie, "/mcp-app-sandbox?w=2", 1_100));
    assert!(access.sandbox_ticket_allowed(Some("__Host-cc_session=s2"), "/mcp-app-sandbox?w=1", 1_100));
    // A minute later the frame may sign in again.
    assert!(access.sandbox_ticket_allowed(cookie, "/mcp-app-sandbox?w=1", 1_000 + 60_011));
}

/// The brain's use of the shim (`gbrain.ts`): the login routes only, writers only, GBrain's link.
#[tokio::test]
async fn the_brain_serves_the_login_routes_only_to_writers() {
    let b = test_box();
    let access = crate::boxside::access(&b.app, Some("/dashboard/brain".into()));
    let landing_ok = Arc::new(AtomicBool::new(true));
    let l = landing_ok.clone();
    let opts = AccessOptions {
        only: Some(&["/__cc/login", "/__cc/session", "/__cc/verify", "/__cc/logout"]),
        require_write: Some("Only owners and admins can open the brain.".into()),
        landing: Some(Arc::new(move || {
            let ok = l.load(Ordering::SeqCst);
            async move {
                if ok {
                    Ok("/admin/auth/abc123".to_string())
                } else {
                    Err("The brain did not give a sign-in link.".to_string())
                }
            }
            .boxed()
        })),
        steps: Some(("Signing you in to GBrain".into(), "Loading the brain".into())),
    };
    let mut router = cc_http::Router::new(&["cc", "prefixed"]);
    crate::boxside::register_access(&mut router, &b.app, &access, opts, "cc", "prefixed");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let url = format!("http://{}", listener.local_addr().expect("addr"));
    tokio::spawn(cc_http::serve(listener, Arc::new(router)));
    let c = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("client");

    for p in [
        "/__cc/browser",
        "/__cc/files",
        "/__cc/view-session",
        "/__cc/verify-view",
        "/__cc/sandbox/verify",
    ] {
        let r = c.get(format!("{url}{p}")).send().await.expect("get");
        assert_eq!(r.status(), 404, "{p}");
    }
    let page = c.get(format!("{url}/__cc/login")).send().await.expect("login");
    let body = page.text().await.expect("text");
    assert!(body.contains("Signing you in to GBrain"));
    assert!(!body.contains("Loading OpenClaw"));
    assert!(body.contains("https://controlclaw.com/dashboard/brain"));
    assert_eq!(
        c.get(format!("{url}/__cc/shell.js")).send().await.expect("js").status(),
        200
    );

    let bind = "b".repeat(43);
    let c_claim = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(bind.as_bytes()));
    let n = AtomicUsize::new(0);
    let post = |can_write: bool| {
        let jti = format!("j{}", n.fetch_add(1, Ordering::SeqCst));
        let t = b.keys.sign_with(
            Signer::Firewall,
            json!({"vmId": "vm_1", "purpose": "browser-login", "iss": "fw:x", "jti": jti, "c": c_claim,
                   "deviceId": "d1", "canWrite": can_write}),
            Some(60),
        );
        c.post(format!("{url}/__cc/session"))
            .header("origin", "https://box.example")
            .header("cookie", format!("__Host-cc_bind_a={bind}"))
            .json(&json!({"token": t}))
            .send()
    };
    let r = post(false).await.expect("member");
    assert_eq!(r.status(), 403);
    // No session; the spent bind cookie is cleared (Rust only: the TS left it until it expired).
    assert_bind_cleared(&r);
    assert!(r.text().await.expect("text").contains("owners and admins"));

    let r = post(true).await.expect("owner");
    assert_eq!(r.status(), 200);
    assert!(
        r.headers()
            .get_all("set-cookie")
            .iter()
            .any(|v| v.to_str().unwrap_or_default().starts_with("__Host-cc_session="))
    );
    assert_eq!(
        r.json::<Value>().await.expect("json"),
        json!({"next": "/admin/auth/abc123", "view": "direct", "paired": true})
    );

    landing_ok.store(false, Ordering::SeqCst);
    let r = post(true).await.expect("no link");
    assert_eq!(r.status(), 502);
    // No session, and the spent bind cookie goes (Rust only).
    assert_bind_cleared(&r);
}

/// The answer set one cookie: the bind cookie, cleared.
fn assert_bind_cleared(r: &reqwest::Response) {
    let set: Vec<String> = r
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap_or_default().to_string())
        .collect();
    assert!(
        set.len() == 1 && set[0].starts_with("__Host-cc_bind_a=;") && set[0].contains("Max-Age=0"),
        "{set:?}"
    );
}
