//! `doctor-gateway.test.ts`: the model bridge against a fake provider on loopback.

use std::sync::atomic::AtomicBool;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::integrations::testing::{Answer, FakeServer, Got};

fn cred(models: Arc<Mutex<Vec<String>>>) -> CredentialFn {
    Arc::new(move || {
        let m = models.lock().expect("lock").clone();
        Box::pin(async move {
            Some(GatewayCredential {
                key: "real-key".into(),
                allowed_models: m,
            })
        })
    })
}

async fn provider() -> FakeServer {
    FakeServer::start(|_: &Got| {
        let mut a = Answer::typed(200, "text/event-stream", b"data: allowed\n\n".to_vec());
        a.headers.push(("set-cookie".into(), "upstream-cookie".into()));
        a
    })
    .await
}

fn http() -> reqwest::Client {
    reqwest::Client::builder().no_proxy().build().expect("client")
}

#[tokio::test]
async fn a_final_checks_bridge_uses_the_orgs_key_on_a_unix_socket_for_the_one_model() {
    let up = provider().await;
    let dir = tempfile::tempdir().expect("dir");
    let models = Arc::new(Mutex::new(vec!["claude-haiku-4-5".to_string()]));
    let g = DoctorGateway::new(Options {
        active: Arc::new(|| true),
        credential: cred(models),
        upstream: Some(ANTHROPIC),
        strict: None,
        base_override: Some(up.url()),
    });
    let path = dir.path().join("model.sock");
    assert_eq!(g.start(Some(&path)).await.expect("start"), path.display().to_string());
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).expect("meta").permissions().mode() & 0o777,
            0o660
        );
    }
    let post = |model: &str, token: &str| {
        let (path, body, token) = (
            path.clone(),
            format!(r#"{{"model":"{model}","messages":[]}}"#),
            token.to_string(),
        );
        async move {
            let mut s = tokio::net::UnixStream::connect(&path).await.expect("connect");
            let req = format!(
                "POST /v1/messages HTTP/1.1\r\nhost: x\r\nx-api-key: {token}\r\ncontent-type: application/json\r\nanthropic-version: 2023-06-01\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            s.write_all(req.as_bytes()).await.expect("write");
            let mut out = String::new();
            s.read_to_string(&mut out).await.expect("read");
            out.split(' ').nth(1).unwrap_or("").parse::<u16>().unwrap_or(0)
        }
    };
    let token = g.token.clone();
    assert_eq!(post("claude-haiku-4-5", &token).await, 200);
    let got = up.got()[0].clone();
    assert_eq!(got.path, "/v1/messages");
    assert_eq!(
        (
            got.headers["x-api-key"].to_str().ok(),
            got.headers["anthropic-version"].to_str().ok()
        ),
        (Some("real-key"), Some("2023-06-01"))
    );
    assert!(got.headers.get("authorization").is_none());
    assert_eq!(post("claude-opus-5-5", &token).await, 403, "another model is refused");
    assert_eq!(
        post("claude-haiku-4-5", "real-key").await,
        403,
        "the real key is not the session's token"
    );
    assert_eq!(up.got().len(), 1);
    g.close();
}

#[tokio::test]
async fn a_final_checks_bridge_passes_nothing_that_runs_at_the_provider_and_stops_after_its_share() {
    let up = provider().await;
    let models = Arc::new(Mutex::new(vec!["anthropic/claude-haiku-4.5".to_string()]));
    let g = DoctorGateway::new(Options {
        active: Arc::new(|| true),
        credential: cred(models),
        upstream: None,
        strict: Some(3),
        base_override: Some(up.url()),
    });
    let base = g.start(None).await.expect("start");
    let post = |body: Value, path: &str| {
        let mut b = crate::integrations::as_map(json!({"model": "anthropic/claude-haiku-4.5"}));
        b.extend(crate::integrations::as_map(body));
        http()
            .post(format!("{base}{path}"))
            .header("x-api-key", &g.token)
            .header("content-type", "application/json")
            .header("anthropic-version", "2023-06-01")
            .header("anthropic-beta", "mcp-client-2025-04-04")
            .body(js::stringify(&Value::Object(b)))
            .send()
    };
    let ours = json!({"name": "mcp__tplcheck__run", "description": "x", "input_schema": {"type": "object"}});
    let first = post(
        json!({"tools": [ours, {"type": "web_search_20250305", "name": "web_search"}, {"type": "custom", "name": "also-ours", "input_schema": {}}, {"type": "bash_20250124", "name": "bash"}],
            "mcp_servers": [{"type": "url", "url": "https://evil.example/mcp"}], "container": {"id": "c1"}, "some_future_field": true, "system": "s", "max_tokens": 100, "messages": [], "stream": true}),
        "/v1/messages?beta=true",
    )
    .await
    .expect("send");
    assert_eq!(first.status(), 200);
    let got = up.got()[0].clone();
    assert_eq!(got.path, "/v1/messages", "no beta marker");
    assert!(got.headers.get("anthropic-beta").is_none());
    let body: Value = serde_json::from_slice(&got.body).expect("json");
    let names: Vec<Value> = body["tools"]
        .as_array()
        .expect("tools")
        .iter()
        .map(|t| t["name"].clone())
        .collect();
    assert_eq!(names, [json!("mcp__tplcheck__run"), json!("also-ours")]);
    let mut keys: Vec<String> = body.as_object().expect("object").keys().cloned().collect();
    keys.sort();
    assert_eq!(keys, ["max_tokens", "messages", "model", "stream", "system", "tools"]);
    assert_eq!(
        post(json!({}), "/v1/responses").await.expect("send").status(),
        403,
        "the Messages API only"
    );
    assert_eq!(post(json!({}), "/v1/messages").await.expect("send").status(), 200);
    assert_eq!(post(json!({}), "/v1/messages").await.expect("send").status(), 200);
    assert_eq!(
        post(json!({}), "/v1/messages").await.expect("send").status(),
        429,
        "no more than its share"
    );
    assert_eq!(up.got().len(), 3);
    g.close();
}

#[tokio::test]
async fn included_tokens_are_checked_on_every_request_against_the_current_list() {
    let up = provider().await;
    let active = Arc::new(AtomicBool::new(true));
    let models = Arc::new(Mutex::new(vec![
        "openai/gpt-5.4-mini".to_string(),
        "anthropic/claude-haiku-4.5".to_string(),
    ]));
    let a = active.clone();
    let g = DoctorGateway::new(Options {
        active: Arc::new(move || a.load(Ordering::SeqCst)),
        credential: cred(models.clone()),
        upstream: None,
        strict: None,
        base_override: Some(up.url()),
    });
    let base = g.start(None).await.expect("start");
    assert!(
        regex::Regex::new(r"^http://127\.0\.0\.1:\d+$")
            .expect("re")
            .is_match(&base)
    );
    let post = |model: &str, path: &str, token: &str, extra: &[(&str, &str)]| {
        let mut r = http()
            .post(format!("{base}{path}"))
            .bearer_auth(token)
            .header("content-type", "application/json")
            .body(js::stringify(&json!({"model": model})));
        for (k, v) in extra {
            r = r.header(*k, *v);
        }
        r.send()
    };
    let t = g.token.clone();
    assert_eq!(
        post("openai/gpt-5.4-mini", "/v1/responses", "real-key", &[])
            .await
            .expect("send")
            .status(),
        403
    );
    assert_eq!(
        post("openai/not-included", "/v1/responses", &t, &[])
            .await
            .expect("send")
            .status(),
        403
    );
    assert_eq!(
        post("openai/gpt-5.4-mini", "/v1/models", &t, &[])
            .await
            .expect("send")
            .status(),
        403
    );
    assert_eq!(
        post(
            "openai/gpt-5.4-mini",
            "/v1/responses",
            &t,
            &[("origin", "https://example.com")]
        )
        .await
        .expect("send")
        .status(),
        403
    );
    assert!(up.got().is_empty());
    let ok = post(
        "openai/gpt-5.4-mini",
        "/v1/responses",
        &t,
        &[
            ("cookie", "private-browser-cookie"),
            ("x-forwarded-host", "evil.example"),
        ],
    )
    .await
    .expect("send");
    assert_eq!(ok.status(), 200);
    assert!(ok.headers().get("set-cookie").is_none());
    assert_eq!(ok.text().await.expect("text"), "data: allowed\n\n");
    let got = up.got()[0].clone();
    assert_eq!(got.headers["authorization"], "Bearer real-key");
    assert!(got.headers.get("cookie").is_none() && got.headers.get("x-forwarded-host").is_none());
    let beta = post(
        "anthropic/claude-haiku-4.5",
        "/v1/messages?beta=true",
        &t,
        &[("anthropic-version", "2023-06-01"), ("anthropic-beta", "test-beta")],
    )
    .await
    .expect("send");
    beta.text().await.expect("text");
    let got = up.got()[1].clone();
    assert_eq!(
        (got.path.as_str(), got.headers["anthropic-beta"].to_str().ok()),
        ("/v1/messages?beta=true", Some("test-beta"))
    );
    models.lock().expect("lock").clear();
    assert_eq!(
        post("openai/gpt-5.4-mini", "/v1/responses", &t, &[])
            .await
            .expect("send")
            .status(),
        403,
        "list changes take effect now"
    );
    active.store(false, Ordering::SeqCst);
    assert_eq!(
        post("openai/gpt-5.4-mini", "/v1/responses", &t, &[])
            .await
            .expect("send")
            .status(),
        403
    );
    assert_eq!(up.got().len(), 2);
    g.close();
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    assert!(http().get(&base).send().await.is_err());
}

#[tokio::test]
async fn routing_overrides_are_refused_and_only_the_checked_object_goes_on() {
    let up = provider().await;
    let model = "anthropic/claude-haiku-4.5";
    let g = DoctorGateway::new(Options {
        active: Arc::new(|| true),
        credential: cred(Arc::new(Mutex::new(vec![model.to_string()]))),
        upstream: None,
        strict: None,
        base_override: Some(up.url()),
    });
    let base = g.start(None).await.expect("start");
    let post = |path: &str, body: String| {
        http()
            .post(format!("{base}{path}"))
            .header("x-api-key", &g.token)
            .header("content-type", "application/json")
            .body(body)
            .send()
    };
    for path in [
        "/v1/messages",
        "/v1/messages/count_tokens",
        "/v1/responses",
        "/v1/chat/completions",
    ] {
        for o in [
            json!({"providerOptions": {"gateway": {"models": ["anthropic/not-included"]}}}),
            json!({"provider_options": {"gateway": {"models": ["x"]}}}),
            json!({"gateway": {"models": ["x"]}}),
            json!({"models": ["x"]}),
            json!({"routing": {"model": "x"}}),
            json!({"providerOptions": null}),
        ] {
            let mut b = crate::integrations::as_map(json!({"model": model}));
            b.extend(crate::integrations::as_map(o.clone()));
            assert_eq!(
                post(path, js::stringify(&Value::Object(b)))
                    .await
                    .expect("send")
                    .status(),
                403,
                "{path} {o}"
            );
        }
    }
    assert!(up.got().is_empty());
    let messages = json!([{"role": "user", "content": "Explain providerOptions.gateway.models"}]);
    let valid = post(
        "/v1/messages",
        js::stringify(&json!({"model": model, "messages": messages, "max_tokens": 1024, "stream": true})),
    )
    .await
    .expect("send");
    assert_eq!(valid.status(), 200);
    assert_eq!(
        serde_json::from_slice::<Value>(&up.got()[0].body).expect("json"),
        json!({"model": model, "messages": messages, "max_tokens": 1024, "stream": true})
    );
    let dup = post(
        "/v1/chat/completions",
        format!(r#"{{"model":"excluded","model":"{model}","messages":[]}}"#),
    )
    .await
    .expect("send");
    assert_eq!(dup.status(), 200);
    assert_eq!(
        String::from_utf8_lossy(&up.got()[1].body),
        js::stringify(&json!({"model": model, "messages": []})),
        "one checked model field"
    );
    let last = post("/v1/responses", format!(r#"{{"model":"{model}","model":"excluded"}}"#))
        .await
        .expect("send");
    assert_eq!(last.status(), 403);
    assert_eq!(up.got().len(), 2);
    g.close();
}

#[tokio::test]
async fn closing_the_bridge_ends_a_request_whose_credential_is_still_being_read() {
    let up = provider().await;
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let rx = Arc::new(tokio::sync::Mutex::new(Some(rx)));
    let g = DoctorGateway::new(Options {
        active: Arc::new(|| true),
        credential: Arc::new(move || {
            let rx = rx.clone();
            Box::pin(async move {
                if let Some(r) = rx.lock().await.take() {
                    let _ = r.await;
                }
                Some(GatewayCredential {
                    key: "secret".into(),
                    allowed_models: vec!["allowed".into()],
                })
            })
        }),
        upstream: None,
        strict: None,
        base_override: Some(up.url()),
    });
    let base = g.start(None).await.expect("start");
    let req = http()
        .post(format!("{base}/v1/responses"))
        .bearer_auth(&g.token)
        .header("content-type", "application/json")
        .body(r#"{"model":"allowed"}"#)
        .send();
    let pending = tokio::spawn(req);
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    g.close();
    let _ = tx.send(());
    let r = pending.await.expect("joined");
    assert!(r.is_err() || r.is_ok_and(|r| r.status() == 403));
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    assert!(up.got().is_empty(), "nothing goes on after the bridge closed");
}
