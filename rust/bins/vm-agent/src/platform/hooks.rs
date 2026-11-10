//! `/hooks/*` (`routes/hooks.ts`): an inbound webhook delivery the org firewall already checked,
//! replayed to a listener bound to loopback here, and the Gmail watch and wake (W7's services).
//!
//! Every route takes only the firewall's token with purpose `hooks`, reads included: a control
//! plane that could feed the agent input of its own choosing is what ingress on the firewall exists
//! to prevent. `/hooks/deliver` does not know what Gmail is; it replays bytes to a port in
//! 8700-8799 and nothing else (not the agent's own 3102 or 3100, not the browser's debugger).

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use cc_http::{FirewallBody, FirewallRequest, ReadBody, Router, send_json};
use http_body_util::{BodyExt, Full};
use hyper::Method;
use serde_json::{Map, Value, json};

use crate::app::App;
use crate::stages;

pub const HOOK_TARGET_PORT_MIN: i64 = 8700;
pub const HOOK_TARGET_PORT_MAX: i64 = 8799;
/// Shorter than the firewall's own budget for the whole call (8 s), which also covers its hops.
pub const HOOK_DELIVER_TIMEOUT: Duration = Duration::from_secs(3);
/// The firewall's 1 MB as base64, with room for the headers around it.
const MAX_ENVELOPE_BYTES: usize = (1024usize * 1024 * 4).div_ceil(3) + 64 * 1024;
/// What a listener may answer with: a status line, never a page.
const MAX_REPLY_BYTES: usize = 8 * 1024;
const MAX_BOUNDED_REPLY_BYTES: usize = 65_536;
const JSON_LIMIT: usize = 16_384;

#[derive(Debug, PartialEq)]
pub struct Delivery {
    pub port: u16,
    pub path: String,
    pub method: String,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
    pub bounded: bool,
}

/// `hookPortAllowed`: an integer in the hooks' range.
pub fn port_allowed(v: Option<&Value>) -> Option<u16> {
    let f = v?.as_f64()?;
    (f.fract() == 0.0 && f >= HOOK_TARGET_PORT_MIN as f64 && f <= HOOK_TARGET_PORT_MAX as f64).then_some(f as u16)
}

/// `parse`: the envelope, or the 400's message.
pub fn parse(body: &Map<String, Value>) -> Result<Delivery, String> {
    let Some(port) = port_allowed(body.get("port")) else {
        return Err(format!(
            "port must be between {HOOK_TARGET_PORT_MIN} and {HOOK_TARGET_PORT_MAX}"
        ));
    };
    let Some(path) = body.get("path").and_then(Value::as_str).filter(|p| p.starts_with('/')) else {
        return Err("path must start with /".into());
    };
    let method = body
        .get("method")
        .and_then(Value::as_str)
        .map_or("POST".to_string(), str::to_uppercase);
    if method != "POST" && method != "PUT" {
        return Err("method must be POST or PUT".into());
    }
    let Some(b64) = body.get("bodyB64").and_then(Value::as_str) else {
        return Err("bodyB64 required".into());
    };
    // `Buffer.from(…, "base64")` never throws: what is not base64 is skipped.
    let decoded = super::templates::node_base64(b64);
    let mut headers: Vec<(String, String)> = Vec::new();
    if let Some(Value::Object(raw)) = body.get("headers") {
        for (name, value) in raw {
            // A forwarded header never rewrites the framing of the request made here.
            let lower = name.to_lowercase();
            if matches!(
                lower.as_str(),
                "content-length" | "host" | "connection" | "transfer-encoding"
            ) {
                continue;
            }
            if let Some(v) = value.as_str() {
                headers.retain(|(n, _)| *n != lower);
                headers.push((lower, v.to_string()));
            }
        }
    }
    let bounded = body.get("responseMode").and_then(Value::as_str) == Some("bounded");
    let query = body.get("query").and_then(Value::as_str);
    if bounded {
        let ok = query.is_some_and(|q| {
            q.encode_utf16().count() <= 2048 && (q.is_empty() || q.starts_with('?')) && !q.contains(['\r', '\n', '#'])
        });
        if !ok {
            return Err("invalid query".into());
        }
    }
    if path.contains('?') || path.contains('#') || path.starts_with("//") || path.contains(['\r', '\n']) {
        return Err("invalid path".into());
    }
    Ok(Delivery {
        port,
        path: format!("{path}{}", if bounded { query.unwrap_or("") } else { "" }),
        method,
        headers,
        body: Bytes::from(decoded),
        bounded,
    })
}

/// `replayHook`: the delivery to `127.0.0.1:<port>`, over a new connection, with a hard deadline.
pub async fn replay(d: &Delivery) -> Result<Value, String> {
    tokio::time::timeout(HOOK_DELIVER_TIMEOUT, replay_inner(d))
        .await
        .map_err(|_| "listener deadline exceeded".to_string())?
}

async fn replay_inner(d: &Delivery) -> Result<Value, String> {
    let stream = tokio::net::TcpStream::connect(("127.0.0.1", d.port))
        .await
        .map_err(|e| e.to_string())?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
        .await
        .map_err(|e| e.to_string())?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let method = Method::from_bytes(d.method.as_bytes()).map_err(|e| e.to_string())?;
    let mut req = hyper::Request::builder()
        .method(method)
        .uri(&d.path)
        .header("host", format!("127.0.0.1:{}", d.port));
    for (n, v) in &d.headers {
        req = req.header(n.as_str(), v.as_str());
    }
    let req = req
        .header("content-length", d.body.len().to_string())
        .body(Full::new(d.body.clone()))
        .map_err(|e| e.to_string())?;
    let res = sender.send_request(req).await.map_err(|e| e.to_string())?;
    let status = res.status().as_u16();
    let content_type = res
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let max = if d.bounded {
        MAX_BOUNDED_REPLY_BYTES
    } else {
        MAX_REPLY_BYTES
    };
    let mut body = res.into_body();
    let mut kept = Vec::new();
    let mut read = 0;
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| "listener reply truncated".to_string())?;
        if let Ok(chunk) = frame.into_data() {
            read += chunk.len();
            if read > max {
                return Err("listener reply too large".into());
            }
            if d.bounded {
                kept.extend_from_slice(&chunk);
            }
        }
    }
    use base64::Engine;
    Ok(if d.bounded {
        json!({ "status": status, "bodyB64": base64::engine::general_purpose::STANDARD.encode(&kept), "contentType": content_type })
    } else {
        json!({ "status": status })
    })
}

pub fn register(router: &mut Router, app: &Arc<App>) {
    const PATHS: [&str; 4] = [
        "/hooks/deliver",
        "/hooks/gmail",
        "/hooks/gmail/status",
        "/hooks/gmail-wake",
    ];
    let a = app.clone();
    router.prefix(stages::PREFIXED, "/hooks/", move |req, _| {
        let app = a.clone();
        async move {
            let path = cc_http::pathname(&req.uri().to_string());
            if !PATHS.contains(&path.as_str()) {
                return send_json(404, &json!({ "error": "Not found" }));
            }
            let read = if req.method() == Method::GET {
                ReadBody::No
            } else {
                ReadBody::Json {
                    limit: if path == "/hooks/deliver" { MAX_ENVELOPE_BYTES } else { JSON_LIMIT },
                }
            };
            let (parts, body) = match cc_http::firewall_request(&app.firewall_auth, req, "hooks", 0, read).await {
                FirewallRequest::Accepted { parts, body, .. } => (parts, body),
                FirewallRequest::Refused { .. } => {
                    return send_json(401, &json!({ "error": "a webhook delivery must come from the org firewall" }));
                }
            };
            let post = parts.method == Method::POST;
            let json_body = match body {
                FirewallBody::Json(b) => Some(b),
                _ => None,
            };
            if path == "/hooks/gmail-wake" {
                let Some(wake) = app.contracts.gmail_wake.get() else {
                    return send_json(501, &json!({ "error": "This agent cannot be woken by email yet. Update it." }));
                };
                if !post {
                    return send_json(405, &json!({ "error": "Use POST." }));
                }
                let Some(b) = json_body else { return send_json(400, &json!({ "error": "Invalid JSON" })) };
                let answer = if b.get("configure") == Some(&json!(true)) {
                    wake.ensure_hooks().await.map(|v| (200, v))
                } else {
                    let Some(input) = crate::boxside::gmail::GmailWake::parse(&b) else {
                        return send_json(400, &json!({ "error": "Invalid wake" }));
                    };
                    wake.wake(&input).await.map(|v| (if v.get("ok") == Some(&json!(true)) { 200 } else { 502 }, v))
                };
                return match answer {
                    Ok((status, v)) => send_json(status, &v),
                    Err(e) => {
                        tracing::error!("[gmail-wake] failed: {e}");
                        send_json(502, &json!({ "error": "The agent could not be woken." }))
                    }
                };
            }
            if path == "/hooks/gmail/status" {
                let Some(gmail) = app.contracts.gmail_watch.get() else {
                    return send_json(501, &json!({ "error": "This agent does not have gog yet." }));
                };
                return send_json(200, &gmail.status().await);
            }
            if path == "/hooks/gmail" {
                let Some(gmail) = app.contracts.gmail_watch.get() else {
                    return send_json(
                        501,
                        &json!({ "error": "This agent does not have gog yet, so it cannot watch a mailbox. Update it." }),
                    );
                };
                if !post {
                    return send_json(405, &json!({ "error": "Use POST." }));
                }
                let Some(b) = json_body else { return send_json(400, &json!({ "error": "Invalid JSON" })) };
                if b.get("stop") == Some(&json!(true)) {
                    return send_json(200, &gmail.clear().await);
                }
                if b.get("renew") == Some(&json!(true)) {
                    return send_json(200, &gmail.renew().await);
                }
                let cfg = match crate::boxside::gmail::GmailWatch::parse(&b) {
                    Ok(c) => c,
                    Err(e) => return send_json(400, &json!({ "error": e })),
                };
                return match gmail.apply(&cfg).await {
                    Ok(v) => send_json(200, &v),
                    Err(e) => {
                        tracing::error!("[gmail-watch] apply failed: {e}");
                        send_json(500, &json!({ "error": "The watcher could not be started on this box." }))
                    }
                };
            }
            if !post {
                return send_json(405, &json!({ "error": "Use POST." }));
            }
            let Some(b) = json_body else { return send_json(400, &json!({ "error": "Invalid JSON" })) };
            let d = match parse(&b) {
                Ok(d) => d,
                Err(e) => return send_json(400, &json!({ "error": e })),
            };
            match replay(&d).await {
                Ok(reply) => send_json(200, &reply),
                Err(e) => {
                    // Generic outward, detail in the log: the firewall turns this into a 503.
                    tracing::error!("[hooks] delivery to 127.0.0.1:{} failed: {e}", d.port);
                    send_json(502, &json!({ "error": "the listener on this box did not take that delivery" }))
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(v: Value) -> Result<Delivery, String> {
        parse(v.as_object().expect("o"))
    }

    #[test]
    fn only_a_hook_port_and_a_plain_path() {
        assert_eq!(
            p(json!({ "port": 3102, "path": "/", "bodyB64": "" })).expect_err("e"),
            "port must be between 8700 and 8799"
        );
        assert_eq!(
            p(json!({ "port": 3100, "path": "/", "bodyB64": "" })).expect_err("e"),
            "port must be between 8700 and 8799"
        );
        assert_eq!(
            p(json!({ "port": 8788.5, "path": "/", "bodyB64": "" })).expect_err("e"),
            "port must be between 8700 and 8799"
        );
        assert_eq!(
            p(json!({ "port": 8788, "path": "x", "bodyB64": "" })).expect_err("e"),
            "path must start with /"
        );
        assert_eq!(
            p(json!({ "port": 8788, "path": "/", "method": "get", "bodyB64": "" })).expect_err("e"),
            "method must be POST or PUT"
        );
        assert_eq!(
            p(json!({ "port": 8788, "path": "/" })).expect_err("e"),
            "bodyB64 required"
        );
        assert_eq!(
            p(json!({ "port": 8788, "path": "//evil", "bodyB64": "" })).expect_err("e"),
            "invalid path"
        );
        assert_eq!(
            p(json!({ "port": 8788, "path": "/a?b", "bodyB64": "" })).expect_err("e"),
            "invalid path"
        );
        assert_eq!(
            p(json!({ "port": 8788, "path": "/a", "bodyB64": "", "responseMode": "bounded", "query": "x" }))
                .expect_err("e"),
            "invalid query"
        );
        let d = p(json!({ "port": 8788, "path": "/gmail", "method": "put", "bodyB64": "aGk=", "responseMode": "bounded", "query": "?q=1",
                          "headers": { "Content-Length": "9", "X-Goog-Id": "1", "Host": "evil" } }))
        .expect("ok");
        assert_eq!(
            (d.port, d.path.as_str(), d.method.as_str(), &d.body[..]),
            (8788, "/gmail?q=1", "PUT", &b"hi"[..])
        );
        assert_eq!(d.headers, vec![("x-goog-id".to_string(), "1".to_string())]);
    }

    #[tokio::test]
    async fn the_delivery_reaches_the_listener_and_its_answer_comes_back() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let server = tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let (mut s, _) = listener.accept().await.expect("accept");
            let mut buf = vec![0u8; 4096];
            let n = s.read(&mut buf).await.expect("read");
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            s.write_all(b"HTTP/1.1 204 No Content\r\ncontent-type: text/plain\r\ncontent-length: 2\r\n\r\nok")
                .await
                .expect("w");
            req
        });
        let d = Delivery {
            port,
            path: "/push?x=1".into(),
            method: "POST".into(),
            headers: vec![("x-a".into(), "1".into())],
            body: Bytes::from_static(b"payload"),
            bounded: true,
        };
        let reply = replay(&d).await.expect("reply");
        assert_eq!(reply["status"], json!(204));
        let req = server.await.expect("server");
        assert!(req.starts_with("POST /push?x=1 HTTP/1.1"));
        assert!(req.contains("x-a: 1") && req.ends_with("payload"));
        // Nobody on the port: an error, never a hang.
        let closed = Delivery { port: 1, ..d };
        assert!(replay(&closed).await.is_err());
    }
}
