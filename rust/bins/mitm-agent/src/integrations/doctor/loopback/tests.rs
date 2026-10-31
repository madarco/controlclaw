use super::*;

type Seen = Arc<Mutex<Vec<(String, Option<String>)>>>;

fn tools(hold: Option<tokio::sync::oneshot::Receiver<()>>) -> (Listener, Seen) {
    let seen: Seen = Arc::default();
    let s = seen.clone();
    let hold = Arc::new(Mutex::new(hold));
    let t = LoopbackTools::new(Options {
        active: Arc::new(|| true),
        help: "the help".into(),
        what: Some("test"),
        arg_max: Some(10),
        run: Arc::new(move |verb, arg, _| {
            s.lock().expect("lock").push((verb.clone(), arg));
            let h = hold.lock().expect("lock").take();
            Box::pin(async move {
                if let Some(h) = h {
                    let _ = h.await;
                }
                ToolAnswer::new(verb != "bad", format!("ran {verb}"))
            })
        }),
    });
    (Listener(t), seen)
}

async fn post(url: &str, token: &str, ct: Option<&str>, body: String) -> (u16, String) {
    let mut r = reqwest::Client::new()
        .post(format!("{url}/run"))
        .header("authorization", format!("Bearer {token}"));
    if let Some(c) = ct {
        r = r.header("content-type", c);
    }
    let r = r.body(body).send().await.expect("send");
    (r.status().as_u16(), r.text().await.expect("text"))
}

#[tokio::test]
async fn refusals_bounds_and_one_command_at_a_time() {
    let (rx_tx, rx) = tokio::sync::oneshot::channel();
    let (t, seen) = tools(Some(rx));
    let url = t.start(None).await.expect("start");
    let token = t.token();
    let json = Some("application/json");
    assert_eq!(
        post(&url, "bad", json, "{}".into()).await,
        (
            403,
            r#"{"ok":false,"text":"This test session is no longer active."}"#.into()
        )
    );
    assert_eq!(
        post(&url, &token, None, r#"{"verb":"a"}"#.into()).await.0,
        403,
        "no content type"
    );
    let other = reqwest::Client::new()
        .post(format!("{url}/other"))
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body("{}")
        .send()
        .await
        .expect("send");
    assert_eq!(other.status().as_u16(), 403);
    assert_eq!(post(&url, &token, json, "x".repeat(5000)).await.0, 413);
    assert_eq!(post(&url, &token, json, "{".into()).await.0, 400);
    assert_eq!(
        post(&url, &token, json, "null".into()).await.0,
        500,
        "the TS's null.verb throws"
    );
    assert_eq!(
        post(&url, &token, json, r#"{"verb":"far-too-long-a-verb"}"#.into()).await,
        (400, r#"{"ok":false,"text":"the help"}"#.into())
    );
    // An argument past the limit is left out, not refused.
    let first = {
        let (url, token) = (url.clone(), token.clone());
        tokio::spawn(async move {
            post(
                &url,
                &token,
                Some("application/json"),
                r#"{"verb":"a","arg":"much-too-long"}"#.into(),
            )
            .await
        })
    };
    while seen.lock().expect("lock").is_empty() {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        post(&url, &token, json, r#"{"verb":"b"}"#.into()).await,
        (
            429,
            r#"{"ok":false,"text":"Another command is still running. Wait for it."}"#.into()
        )
    );
    let _ = rx_tx.send(());
    assert_eq!(
        first.await.expect("join"),
        (200, r#"{"ok":true,"text":"ran a"}"#.into())
    );
    assert_eq!(*seen.lock().expect("lock"), vec![("a".to_string(), None)]);
    assert_eq!(post(&url, &token, json, r#"{"verb":"bad"}"#.into()).await.0, 400);
    t.close().await;
    assert!(post_fails(&url).await, "closed");
}

async fn post_fails(url: &str) -> bool {
    reqwest::Client::new()
        .post(format!("{url}/run"))
        .timeout(Duration::from_secs(2))
        .send()
        .await
        .is_err()
}

#[tokio::test]
async fn a_unix_socket_for_a_session_with_no_network_mode_0660_removed_on_close() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("tools.sock").display().to_string();
    let (t, _) = tools(None);
    assert_eq!(t.start(Some(path.clone())).await.expect("start"), path);
    let mode = std::fs::metadata(&path).expect("meta").permissions().mode() & 0o777;
    assert_eq!(mode, 0o660);
    // A request over the socket.
    let stream = tokio::net::UnixStream::connect(&path).await.expect("connect");
    let (mut send, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
        .await
        .expect("handshake");
    tokio::spawn(conn);
    let req = http::Request::post("/run")
        .header("authorization", format!("Bearer {}", t.token()))
        .header("content-type", "application/json")
        .body(http_body_util::Full::new(bytes::Bytes::from(r#"{"verb":"x"}"#)))
        .expect("req");
    let r = send.send_request(req).await.expect("send");
    assert_eq!(r.status(), 200);
    t.close().await;
    assert!(!std::path::Path::new(&path).exists());
}
