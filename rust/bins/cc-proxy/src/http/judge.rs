//! The inline AI review's call to the firewall agent's judge (addon.py `ai_judge`, `_judge_sync`,
//! `_body_start`): `POST MITM_AI_JUDGE_URL` (default `http://127.0.0.1:3101/judge`) on loopback, never
//! through a proxy, with at most `MITM_AI_JUDGE_TIMEOUT` seconds (default 3). A judge that is off,
//! slow, failing or saying anything but allow, ask or block has no opinion: the rule's effect stands.

use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};

use crate::flow::Flow;
use crate::log::record::redact_path;
use crate::net::Ctx;
use crate::net::rules::RuleView;

/// Hosts whose requests never go to the judge: mail and phone content stays on the firewall.
const NOT_JUDGED: &[&str] = &["api.agentmail.to", "ws.agentmail.to", "api.twilio.com"];
/// What the judge sees of a body: the start of a text body only.
const BODY_CHARS: usize = 300;
const TEXT_TYPES: &[&str] = &[
    "text/",
    "application/json",
    "application/x-www-form-urlencoded",
    "application/xml",
    "application/graphql",
];

pub struct Judge {
    /// `host:port` and path; `None` when `MITM_AI_JUDGE_URL` is set empty.
    target: Option<(String, String)>,
    /// `MITM_AI_JUDGE_URL` is set but cannot be used: every review is a block, not skipped.
    broken: bool,
    timeout: Duration,
}

impl Judge {
    pub fn from_env() -> Self {
        let url = std::env::var("MITM_AI_JUDGE_URL").unwrap_or_else(|_| "http://127.0.0.1:3101/judge".into());
        let timeout = std::env::var("MITM_AI_JUDGE_TIMEOUT")
            .ok()
            .and_then(|v| v.trim().parse::<f64>().ok())
            .filter(|t| t.is_finite() && *t > 0.0)
            .unwrap_or(3.0);
        let target = parse_url(url.trim());
        let broken = target.is_none() && !url.trim().is_empty();
        if broken {
            tracing::error!(
                "[mitm] MITM_AI_JUDGE_URL is not a plain http:// URL; requests on AI-reviewed rules are blocked"
            );
        }
        Self {
            target,
            broken,
            timeout: Duration::from_secs_f64(timeout),
        }
    }

    /// Ask about one request. `approve` holds `permission_id` and `scope` for an Ask rule.
    pub async fn ask(&self, ctx: &Ctx, flow: &Flow, rule: &RuleView, approve: Option<&Value>) -> Option<Value> {
        let host = crate::log::record::record_host(flow);
        if NOT_JUDGED.contains(&host.as_str()) {
            return None;
        }
        if self.broken {
            // Fail closed: a review that was asked for and cannot be made is a block.
            return Some(json!({"decision": "block", "category": "judge_unavailable"}));
        }
        let (addr, path) = self.target.as_ref()?;
        let req = flow.request.as_ref()?;
        let raw_path = req.uri().path_and_query().map_or("/", |p| p.as_str());
        let query = raw_path.split_once('?').map_or("", |(_, q)| q);
        let mut keys: Vec<&str> = query
            .split('&')
            .filter(|kv| !kv.is_empty())
            .map(|kv| kv.split_once('=').map_or(kv, |(k, _)| k))
            .collect();
        keys.sort_unstable();
        keys.dedup();
        keys.truncate(20);
        let ctype = req
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        // `rule.get("name") or rule.get("match_domain") or ""`.
        let label = match crate::http::policy::rule_label(rule) {
            Value::String(s) => s,
            _ => String::new(),
        };
        let mut payload = json!({
            "rule": label,
            "vm_id": flow.vm_id,
            "method": req.method().as_str(),
            "host": host,
            "path": crate::net::target::truncate(&redact_path(raw_path, &host), 200),
            "query_keys": keys,
            "content_type": Some(crate::net::target::truncate(ctype, 100)).filter(|c| !c.is_empty()),
            "body_start": body_start(ctype, req.body()),
            "recent": ctx.log.recent(flow.vm_id.as_deref()),
            "policy": rule.raw.get("ai_policy").cloned().unwrap_or(Value::Null),
        });
        if let Some(o) = payload.as_object_mut() {
            match approve.and_then(Value::as_object) {
                Some(extra) => {
                    o.insert("mode".into(), "approve".into());
                    for (k, v) in extra {
                        o.insert(k.clone(), v.clone());
                    }
                }
                None => {
                    o.insert("mode".into(), "review".into());
                }
            }
        }
        let out = match tokio::time::timeout(self.timeout, post(addr, path, &payload)).await {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => {
                tracing::warn!("[mitm] ai judge unavailable: {e}");
                return None;
            }
            Err(_) => {
                tracing::warn!("[mitm] ai judge unavailable: timed out");
                return None;
            }
        };
        let decision = out.get("decision").and_then(Value::as_str)?;
        ["allow", "ask", "block"].contains(&decision).then_some(out)
    }
}

/// addon.py `_body_start`: the first characters of a text body, control characters made spaces.
fn body_start(ctype: &str, body: &Bytes) -> Option<String> {
    let ct = ctype.to_ascii_lowercase();
    if body.is_empty() || !TEXT_TYPES.iter().any(|t| ct.starts_with(t)) {
        return None;
    }
    let text = String::from_utf8_lossy(&body[..body.len().min(BODY_CHARS * 4)]);
    let clean: String = text
        .chars()
        .map(|c| match c {
            '\u{00}'..='\u{08}' | '\u{0b}'..='\u{1f}' | '\u{7f}' => ' ',
            c => c,
        })
        .take(BODY_CHARS)
        .collect();
    Some(clean)
}

/// `http://host:port/path` → (`host:port`, `/path`). Only plain HTTP: the judge is on loopback.
fn parse_url(url: &str) -> Option<(String, String)> {
    let rest = url.strip_prefix("http://")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.is_empty() {
        return None;
    }
    // A port after the host (`[v6]:p`, `name:p`), else 80.
    let has_port = match authority.strip_prefix('[') {
        Some(rest) => rest.split_once(']').is_some_and(|(_, after)| after.starts_with(':')),
        None => authority.contains(':'),
    };
    let authority = if has_port {
        authority.to_owned()
    } else {
        format!("{authority}:80")
    };
    Some((authority, path.to_owned()))
}

async fn post(addr: &str, path: &str, payload: &Value) -> anyhow::Result<Value> {
    let tcp = tokio::net::TcpStream::connect(addr).await?;
    let (mut send, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp)).await?;
    tokio::spawn(conn);
    let body = serde_json::to_vec(payload)?;
    let req = http::Request::post(path)
        .header(http::header::HOST, addr)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(body)))?;
    let resp = send.send_request(req).await?;
    // Only a 2xx answer is a decision: a 500 whose body says `allow` must not approve anything.
    if !resp.status().is_success() {
        anyhow::bail!("the judge answered {}", resp.status());
    }
    let bytes = http_body_util::Limited::new(resp.into_body(), 64 * 1024)
        .collect()
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .to_bytes();
    Ok(serde_json::from_slice(&bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn only_a_2xx_answer_is_a_decision() -> anyhow::Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?.to_string();
        tokio::spawn(async move {
            for status in ["500 Internal Server Error", "200 OK"] {
                let Ok((mut s, _)) = listener.accept().await else {
                    return;
                };
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf).await;
                let body = r#"{"decision": "allow"}"#;
                let resp = format!(
                    "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
                    body.len()
                );
                let _ = s.write_all(resp.as_bytes()).await;
            }
        });
        assert!(post(&addr, "/judge", &json!({})).await.is_err());
        assert_eq!(post(&addr, "/judge", &json!({})).await?["decision"], "allow");
        Ok(())
    }

    #[tokio::test]
    async fn a_judge_url_that_cannot_be_used_fails_closed() -> anyhow::Result<()> {
        let vars: std::collections::HashMap<String, String> = [("MITM_CA_DIR".to_owned(), "/nonexistent".to_owned())]
            .into_iter()
            .collect();
        let ctx = Ctx::new(crate::config::Config::from_vars("127.0.0.1:0".parse()?, &vars)?);
        let j = Judge {
            target: parse_url("https://judge.example/judge"),
            broken: true,
            timeout: Duration::from_secs(1),
        };
        let flow = crate::flow::testing::request_flow("GET", "https://example.com/x", b"");
        let rule =
            RuleView::from_value(&json!({"name": "r", "ai_review": true})).ok_or_else(|| anyhow::anyhow!("rule"))?;
        let v = j.ask(&ctx, &flow, &rule, None).await;
        assert_eq!(v.as_ref().and_then(|v| v.get("decision")), Some(&json!("block")));
        Ok(())
    }

    #[test]
    fn reads_the_judge_url_and_the_body_start() {
        assert_eq!(
            parse_url("http://127.0.0.1:3101/judge"),
            Some(("127.0.0.1:3101".into(), "/judge".into()))
        );
        assert_eq!(parse_url(""), None);
        assert_eq!(
            parse_url("http://[::1]/judge"),
            Some(("[::1]:80".into(), "/judge".into()))
        );
        assert_eq!(parse_url("https://x/judge"), None);
        let b = Bytes::from_static(b"{\"a\":\"x\x01y\"}");
        assert_eq!(
            body_start("application/json; charset=utf-8", &b).as_deref(),
            Some("{\"a\":\"x y\"}")
        );
        assert_eq!(body_start("image/png", &b), None);
        let long = Bytes::from("é".repeat(400));
        assert_eq!(body_start("text/plain", &long).map(|s| s.chars().count()), Some(300));
    }
}
