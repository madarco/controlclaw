//! The content rules' loopback service on 8794 (`contentRulesAdmission`), like the email and
//! code-button services; the agent's egress cannot reach it. `POST /hold` answers once the people who
//! get codes were asked (at most `HOLD_ASK_MS`); `POST /notice` answers at once; `POST /cancel` drops
//! a hold the proxy stopped waiting for; `POST /stopped` keeps a text the proxy stopped for the
//! firewall's own page; `POST /own` takes the firewall's own text out of a message an agent sends
//! for it. Anything else, or anything that does not read: 403 `{"ok":false}`.

use std::sync::Arc;

use serde_json::{Value, json};

use super::firewall::ContentRulesFirewall;
use crate::channels::js::js_len;

const PATHS: &[&str] = &["/hold", "/notice", "/cancel", "/stopped", "/own"];

pub fn router(rules: Arc<ContentRulesFirewall>) -> cc_http::Router {
    let mut router = cc_http::Router::new(&["content"]);
    router.route(
        "content",
        |_, _| true,
        move |req, _| {
            let rules = rules.clone();
            async move {
                use http_body_util::BodyExt;
                let refused = || cc_http::full(hyper::StatusCode::FORBIDDEN, "application/json", "{\"ok\":false}");
                let ok = |body: String| cc_http::full(hyper::StatusCode::OK, "application/json", body);
                let (parts, body) = req.into_parts();
                let target = parts
                    .uri
                    .path_and_query()
                    .map(|p| p.as_str())
                    .unwrap_or("/")
                    .to_string();
                if parts.method != hyper::Method::POST || !PATHS.contains(&target.as_str()) {
                    return refused();
                }
                // 300,000 characters, as the TS counts them; never more than four bytes each.
                let Ok(raw) = http_body_util::Limited::new(body, 1_200_000).collect().await else {
                    return refused();
                };
                let raw = raw.to_bytes();
                let Ok(text) = std::str::from_utf8(&raw) else {
                    return refused();
                };
                if js_len(text) > 300_000 {
                    return refused();
                }
                let Ok(payload) = serde_json::from_str::<Value>(text) else {
                    return refused();
                };
                match target.as_str() {
                    "/cancel" => match rules.cancel(&payload) {
                        Ok(()) => ok("{\"ok\":true}".into()),
                        Err(()) => refused(),
                    },
                    "/own" => {
                        let Some(t) = payload
                            .get("text")
                            .and_then(Value::as_str)
                            .filter(|t| js_len(t) <= 600_000)
                        else {
                            return refused();
                        };
                        ok(json!({"rest": crate::core::own_messages::own_rest(t)}).to_string())
                    }
                    "/stopped" => match rules.stopped(&payload) {
                        Ok(()) => ok("{\"ok\":true}".into()),
                        Err(()) => refused(),
                    },
                    "/notice" => {
                        // Answered at once; a notice that does not read is dropped, as the TS's
                        // rejected promise is.
                        if let Ok(n) = rules.notice_input(&payload) {
                            tokio::spawn(async move { rules.notice(n).await });
                        }
                        ok("{\"ok\":true}".into())
                    }
                    _ => match rules.hold(&payload).await {
                        Ok(answer) => ok(answer.to_string()),
                        Err(()) => refused(),
                    },
                }
            }
        },
    );
    router
}
