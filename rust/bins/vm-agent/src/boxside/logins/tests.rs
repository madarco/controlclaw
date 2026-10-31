//! `logins.test.ts`: the inputs, which cookies reach a site, sign-out, opening a tab, the turn an
//! answered request gives, and typing only into a focused password field on the login's sites.

use std::sync::{Arc, Mutex};

use futures_util::{SinkExt, StreamExt};
use serde_json::{Map, Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::Message;

use super::*;

fn obj(v: Value) -> Map<String, Value> {
    v.as_object().cloned().expect("object")
}

#[test]
fn inputs_are_https_sites_and_plain_host_lists() {
    let open = |u: &str| parse_open_tab(Some(&obj(json!({"url": u}))));
    assert_eq!(
        open("https://app.example.com/").as_deref(),
        Some("https://app.example.com/")
    );
    assert_eq!(open("javascript:alert(1)"), None);
    assert_eq!(open("http://app.example.com/"), None);
    assert_eq!(open("https://127.0.0.1:9222/json"), None);
    assert_eq!(
        parse_clear_cookies(Some(&obj(json!({"sites": ["App.Example.com", "*.acme.io"]})))),
        Some(vec!["app.example.com".to_string(), "*.acme.io".to_string()])
    );
    assert_eq!(parse_clear_cookies(Some(&obj(json!({"sites": []})))), None);
    assert_eq!(parse_clear_cookies(Some(&obj(json!({"sites": ["a b"]})))), None);
    assert_eq!(parse_clear_cookies(None), None);
}

#[test]
fn which_cookies_reach_a_site() {
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    assert!(
        cookie_reaches(".example.com", &s(&["app.example.com"])),
        "a parent-domain cookie"
    );
    assert!(cookie_reaches("app.example.com", &s(&["app.example.com"])));
    assert!(!cookie_reaches("other.example.com", &s(&["app.example.com"])));
    assert!(!cookie_reaches(".example.com.evil.io", &s(&["example.com"])));
    assert!(cookie_reaches("a.acme.io", &s(&["*.acme.io"])));
    assert!(!cookie_reaches("acme.io", &s(&["*.acme.io"])));
    assert!(host_is_site("login.x.com", &s(&["*.x.com"])));
    assert!(!host_is_site("x.com", &s(&["*.x.com"])));
    assert!(host_is_site("X.com.", &s(&["x.com"])));
}

#[test]
fn an_answered_request_wakes_the_agent_with_a_turn_this_box_writes() {
    let a = |v: Value| parse_answered(Some(&obj(v)));
    assert_eq!(
        a(json!({"requestId": "lr_abcdefgh12", "site": "a.example", "login": "x\ny", "kind": "password"})),
        None
    );
    assert_eq!(
        a(json!({"requestId": "nope", "site": "a.example", "login": "x", "kind": "password"})),
        None
    );
    let p =
        a(json!({"requestId": "lr_abcdefgh12", "site": "a.example", "login": "Acme", "kind": "password"})).expect("ok");
    let m = answered_message(&p);
    assert!(m.contains("login \"Acme\" is ready. Open https://a.example/ in your browser"));
    assert!(m.contains("never ask for the password") && m.ends_with("one sentence on what you did."));
    let mut s = p.clone();
    s.kind = "session".into();
    assert!(answered_message(&s).starts_with("A person signed you in to a.example themselves"));
    let t = a(
        json!({"requestId": "lr_abcdefgh12", "site": "a.example", "login": "Acme", "kind": "password",
                     "url": "https://a.example/login", "task": "Download\nthe March invoice"}),
    )
    .expect("ok");
    assert_eq!(
        t.task.as_deref().map(String::from_utf16_lossy).as_deref(),
        Some("Download the March invoice")
    );
    // Cut at 300 UTF-16 units through an emoji: the lone half is written as JavaScript writes it.
    let long = format!("{}😀", "a".repeat(299));
    let e =
        a(json!({"requestId": "lr_abcdefgh12", "site": "a.example", "login": "A", "kind": "session", "task": long}))
            .expect("ok");
    assert!(answered_message(&e).contains(&format!("\"{}\\ud83d\".", "a".repeat(299))));
    let m = answered_message(&t);
    assert!(m.contains("Open https://a.example/login") && m.contains("\"Download the March invoice\""));
    let bad = a(
        json!({"requestId": "lr_abcdefgh12", "site": "a.example", "login": "A", "kind": "password", "url": "javascript:x"}),
    );
    assert_eq!(bad.expect("ok").url, None);
    assert_eq!(
        parse_type(Some(&obj(json!({"password": "a\nb", "sites": ["x.com"]})))),
        None
    );
    assert_eq!(
        parse_type(Some(&obj(json!({"password": "Pw!", "sites": ["X.com"]})))),
        Some((zeroize::Zeroizing::new("Pw!".to_string()), vec!["x.com".to_string()]))
    );
}

type Calls = Arc<Mutex<Vec<Value>>>;

/// A cookie jar behind `Storage.getCookies` and `Network.deleteCookies`. With `strict`, a
/// partitioned cookie is deleted only when its partition is named, as Chrome does.
fn cookie_jar(jar: Arc<Mutex<Value>>, strict: bool) -> Answer {
    Arc::new(move |m: &Value| {
        Ok(match m["method"].as_str().unwrap_or("") {
            "Storage.getCookies" => json!({"cookies": jar.lock().expect("l").clone()}),
            "Network.deleteCookies" => {
                let p = &m["params"];
                let mut j = jar.lock().expect("l");
                if let Some(a) = j.as_array_mut() {
                    a.retain(|c| {
                        let same = c["name"] == p["name"] && c["domain"] == p["domain"] && c["path"] == p["path"];
                        let partition_ok = !strict || c.get("partitionKey") == p.get("partitionKey");
                        !(same && partition_ok)
                    });
                }
                json!({})
            }
            "Target.createTarget" => json!({"targetId": "T1"}),
            "Target.attachToTarget" => json!({"sessionId": "S1"}),
            _ => json!({}),
        })
    })
}
type Answer = Arc<dyn Fn(&Value) -> Result<Value, String> + Send + Sync>;

/// A DevTools endpoint: `/json/version` over HTTP, everything else a WebSocket answered by `answer`.
async fn devtools(answer: Answer) -> (String, Calls) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let calls: Calls = Arc::new(Mutex::new(Vec::new()));
    let c2 = calls.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else {
                return;
            };
            let (answer, calls) = (answer.clone(), c2.clone());
            tokio::spawn(async move {
                let mut head = [0u8; 64];
                let n = s.peek(&mut head).await.unwrap_or(0);
                if head[..n].starts_with(b"GET /json/version") {
                    let mut buf = [0u8; 4096];
                    let _ = s.read(&mut buf).await;
                    let body = json!({"webSocketDebuggerUrl": format!("ws://127.0.0.1:{port}/devtools/browser/x")})
                        .to_string();
                    let _ = s
                        .write_all(format!("HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len()).as_bytes())
                        .await;
                    return;
                }
                let Ok(mut ws) = tokio_tungstenite::accept_async(s).await else {
                    return;
                };
                while let Some(Ok(Message::Text(t))) = ws.next().await {
                    let msg: Value = serde_json::from_str(&t).expect("json");
                    calls.lock().expect("l").push(msg.clone());
                    let reply = match answer(&msg) {
                        Ok(result) => json!({"id": msg["id"], "result": result}),
                        Err(e) => json!({"id": msg["id"], "error": {"message": e}}),
                    };
                    let _ = ws.send(Message::text(reply.to_string())).await;
                }
            });
        }
    });
    (format!("http://127.0.0.1:{port}"), calls)
}

#[tokio::test]
async fn sign_out_deletes_matching_cookies_through_a_page_session_and_open_tab_makes_a_target() {
    let jar = Arc::new(Mutex::new(json!([
        {"name": "sid", "domain": ".example.com", "path": "/"},
        {"name": "keep", "domain": "other.org", "path": "/"},
        {"name": "pref", "domain": "app.example.com", "path": "/x"}])));
    let (base, calls) = devtools(cookie_jar(jar, false)).await;
    let b = BrowserLogins::new(base);
    assert_eq!(b.clear_cookies(&["app.example.com".into()]).await, Ok(2));
    let all = calls.lock().expect("l").clone();
    let deleted: Vec<Value> = all
        .iter()
        .filter(|c| c["method"] == "Network.deleteCookies")
        .map(|c| {
            json!([
                c["params"]["name"],
                c["params"]["domain"],
                c["params"]["path"],
                c["sessionId"]
            ])
        })
        .collect();
    assert_eq!(
        deleted,
        [
            json!(["sid", ".example.com", "/", "S1"]),
            json!(["pref", "app.example.com", "/x", "S1"])
        ]
    );
    let tail: Vec<&str> = all
        .iter()
        .rev()
        .take(2)
        .map(|c| c["method"].as_str().unwrap_or(""))
        .collect();
    assert_eq!(
        tail,
        ["Storage.getCookies", "Target.closeTarget"],
        "closed, then the jar read back"
    );
    calls.lock().expect("l").clear();
    b.open_tab("https://app.example.com/").await.expect("open");
    let all = calls.lock().expect("l").clone();
    assert_eq!(all.len(), 1);
    assert_eq!(
        (all[0]["method"].clone(), all[0]["params"]["url"].clone()),
        (json!("Target.createTarget"), json!("https://app.example.com/"))
    );
}

#[tokio::test]
async fn type_only_into_a_focused_password_field_on_the_logins_own_https_sites() {
    let page = Arc::new(Mutex::new(
        json!({"focus": true, "field": true, "host": "steam.example", "https": true}),
    ));
    let inserted = Arc::new(Mutex::new(Vec::<String>::new()));
    let (p2, i2) = (page.clone(), inserted.clone());
    let (base, _calls) = devtools(Arc::new(move |m: &Value| {
        let method = m["method"].as_str().unwrap_or("");
        let typing = method == "Runtime.callFunctionOn"
            && m["params"]["functionDeclaration"].as_str().is_some_and(|f| f.contains("insertText"));
        if typing {
            i2.lock().expect("l").push(m["params"]["arguments"][0]["value"].as_str().unwrap_or("").into());
        }
        match method {
            "Target.getTargets" => Ok(json!({"targetInfos": [{"targetId": "W", "type": "service_worker"}, {"targetId": "STUCK", "type": "page"}, {"targetId": "P", "type": "page"}]})),
            // A tab stuck on a dialog answers with an error, and must not end the search.
            "Target.attachToTarget" if m["params"]["targetId"] == "STUCK" => Err("stuck".into()),
            "Target.attachToTarget" => Ok(json!({"sessionId": "S"})),
            "Runtime.evaluate" => Ok(json!({"result": {"type": "object", "subtype": "node", "objectId": "EL"}})),
            _ if typing => Ok(json!({"result": {"value": "typed"}})),
            "Runtime.callFunctionOn" => Ok(json!({"result": {"value": p2.lock().expect("l").clone()}})),
            _ => Ok(json!({})),
        }
    }))
    .await;
    let b = BrowserLogins::new(base);
    let sites = vec!["steam.example".to_string()];
    assert_eq!(b.type_password("Pw!", &sites).await, Ok(Typed::Ok));
    assert_eq!(*inserted.lock().expect("l"), ["Pw!"]);
    page.lock().expect("l")["host"] = json!("steam-login.evil");
    assert_eq!(b.type_password("Pw!", &sites).await, Ok(Typed::Not("site")));
    {
        let mut p = page.lock().expect("l");
        p["host"] = json!("steam.example");
        p["https"] = json!(false);
    }
    assert_eq!(b.type_password("Pw!", &sites).await, Ok(Typed::Not("site")));
    {
        let mut p = page.lock().expect("l");
        p["https"] = json!(true);
        p["field"] = json!(false);
    }
    assert_eq!(b.type_password("Pw!", &sites).await, Ok(Typed::Not("field")));
    assert_eq!(inserted.lock().expect("l").len(), 1);
}

#[tokio::test]
async fn a_page_that_changed_between_the_look_and_the_typing_gets_nothing() {
    let (base, calls) = devtools(Arc::new(|m: &Value| {
        let method = m["method"].as_str().unwrap_or("");
        let f = m["params"]["functionDeclaration"].as_str().unwrap_or("");
        Ok(match method {
            "Target.getTargets" => json!({"targetInfos": [{"targetId": "P", "type": "page"}]}),
            "Target.attachToTarget" => json!({"sessionId": "S"}),
            "Runtime.evaluate" => json!({"result": {"objectId": "EL"}}),
            "Runtime.callFunctionOn" if f.contains("insertText") => json!({"result": {"value": "changed"}}),
            "Runtime.callFunctionOn" => {
                json!({"result": {"value": {"focus": true, "field": true, "host": "a.example", "https": true}}})
            }
            _ => json!({}),
        })
    }))
    .await;
    let b = BrowserLogins::new(base);
    assert_eq!(
        b.type_password("Pw!", &["a.example".into()]).await,
        Ok(Typed::Not("changed"))
    );
    let all = calls.lock().expect("l").clone();
    assert!(!all.iter().any(|c| c["method"] == "Input.insertText"));
    assert_eq!(all.last().expect("l")["method"], "Target.detachFromTarget");
    // The password is never anywhere but the one call's arguments.
    let with_pw = all.iter().filter(|c| c.to_string().contains("Pw!")).count();
    assert_eq!(with_pw, 1);
}

#[tokio::test]
async fn no_browser_is_an_error_the_route_words_itself() {
    let b = BrowserLogins::new("http://127.0.0.1:1".into());
    assert!(b.open_tab("https://a.example/").await.is_err());
}

#[test]
fn a_parent_domain_cookie_goes_with_a_wildcard_site() {
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    // Intentional difference: the TS kept these, though the browser sends them to every subdomain.
    assert!(cookie_reaches(".example.com", &s(&["*.example.com"])));
    assert!(cookie_reaches(".example.com", &s(&["*.app.example.com"])));
    assert!(cookie_reaches("a.example.com", &s(&["*.example.com"])));
    assert!(!cookie_reaches(".other.com", &s(&["*.example.com"])));
    assert!(!cookie_reaches(".com.evil.io", &s(&["*.example.com"])));
}

#[tokio::test]
async fn a_partitioned_cookie_is_deleted_with_its_partition_and_only_what_went_is_counted() {
    let partition = json!({"topLevelSite": "https://shop.test", "hasCrossSiteAncestor": false});
    let jar = Arc::new(Mutex::new(json!([
        {"name": "sid", "domain": "app.example.com", "path": "/", "partitionKey": partition},
        {"name": "pref", "domain": "app.example.com", "path": "/"}])));
    let (base, calls) = devtools(cookie_jar(jar.clone(), true)).await;
    let b = BrowserLogins::new(base);
    assert_eq!(b.clear_cookies(&["app.example.com".into()]).await, Ok(2));
    assert_eq!(*jar.lock().expect("l"), json!([]));
    let sent: Vec<Value> = calls
        .lock()
        .expect("l")
        .iter()
        .filter(|c| c["method"] == "Network.deleteCookies")
        .map(|c| c["params"].get("partitionKey").cloned().unwrap_or(Value::Null))
        .collect();
    assert_eq!(sent, [partition, Value::Null]);

    // A cookie the browser keeps is not counted as removed.
    let jar = Arc::new(Mutex::new(
        json!([{"name": "sid", "domain": "app.example.com", "path": "/"}]),
    ));
    let stubborn: Answer = {
        let inner = cookie_jar(jar.clone(), true);
        Arc::new(move |m: &Value| {
            if m["method"] == "Network.deleteCookies" {
                Ok(json!({}))
            } else {
                inner(m)
            }
        })
    };
    let (base, _) = devtools(stubborn).await;
    assert_eq!(
        BrowserLogins::new(base)
            .clear_cookies(&["app.example.com".into()])
            .await,
        Ok(0)
    );
}

#[tokio::test]
async fn typing_has_an_overall_limit() {
    // Each call answers, but slowly: no single call times out, the whole does.
    let (base, _) = devtools(Arc::new(|m: &Value| {
        std::thread::sleep(std::time::Duration::from_millis(60));
        Ok(match m["method"].as_str().unwrap_or("") {
            "Target.getTargets" => json!({"targetInfos": [{"targetId": "A", "type": "page"}, {"targetId": "B", "type": "page"}, {"targetId": "C", "type": "page"}]}),
            "Target.attachToTarget" => json!({"sessionId": "S"}),
            _ => json!({}),
        })
    }))
    .await;
    let b = BrowserLogins::new(base).with_type_limit(std::time::Duration::from_millis(150));
    assert_eq!(
        b.type_password("Pw!", &["a.example".into()]).await,
        Err("the browser took too long".into())
    );
}

#[test]
fn the_password_in_a_devtools_call_is_wiped_once_sent() {
    let mut v = json!({"arguments": [{"value": "Pw!"}, {"value": ["a.example"]}]});
    wipe(&mut v);
    assert!(!v.to_string().contains("Pw!"));
}

#[tokio::test]
async fn the_limit_never_cuts_off_typing_once_the_field_is_found() {
    let (base, calls) = devtools(Arc::new(|m: &Value| {
        let f = m["params"]["functionDeclaration"].as_str().unwrap_or("");
        Ok(match m["method"].as_str().unwrap_or("") {
            "Target.getTargets" => json!({"targetInfos": [{"targetId": "P", "type": "page"}]}),
            "Target.attachToTarget" => json!({"sessionId": "S"}),
            "Runtime.evaluate" => json!({"result": {"objectId": "EL"}}),
            "Runtime.callFunctionOn" if f.contains("insertText") => {
                // Slower than the whole search limit: the typing is under way and is not cut.
                std::thread::sleep(std::time::Duration::from_millis(300));
                json!({"result": {"value": "typed"}})
            }
            "Runtime.callFunctionOn" => {
                json!({"result": {"value": {"focus": true, "field": true, "host": "a.example", "https": true}}})
            }
            _ => json!({}),
        })
    }))
    .await;
    let b = BrowserLogins::new(base).with_type_limit(std::time::Duration::from_millis(200));
    assert_eq!(b.type_password("Pw!", &["a.example".into()]).await, Ok(Typed::Ok));
    assert!(
        calls
            .lock()
            .expect("l")
            .iter()
            .any(|c| c["method"] == "Runtime.callFunctionOn")
    );
}

#[tokio::test]
async fn one_refused_delete_does_not_stop_the_rest() {
    let jar = Arc::new(Mutex::new(json!([
        {"name": "odd", "domain": "app.example.com", "path": "/", "partitionKey": "https://shop.test"},
        {"name": "sid", "domain": "app.example.com", "path": "/"}])));
    let inner = cookie_jar(jar.clone(), true);
    let picky: Answer = Arc::new(move |m: &Value| {
        if m["method"] == "Network.deleteCookies" && m["params"]["name"] == "odd" {
            return Err("Invalid parameters".into());
        }
        inner(m)
    });
    let (base, _) = devtools(picky).await;
    assert_eq!(
        BrowserLogins::new(base)
            .clear_cookies(&["app.example.com".into()])
            .await,
        Ok(1)
    );
    assert_eq!(
        jar.lock().expect("l").as_array().map(Vec::len),
        Some(1),
        "the refused one is still there"
    );
}
