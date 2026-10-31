//! The checks on intercepted traffic. Owner: W2.
//!
//! Each check is a `flow::Step` registered in its `flow::order` slot: website logins, email
//! (AgentMail, Gmail), content rules on every channel, Telegram taps, Slack, MCP, Twilio, and the
//! meeting and phone voice. The loopback calls they make are typed in `cc_contracts::loopback`.
//!
//! **The traffic record.** The addon writes a record itself when a check answers (`_http_record`
//! plus fields, `_log_once`). Here a check that answers leaves what the record needs on the flow
//! ([`answer`]): `cc_effect`, `cc_rule` and `cc_record` (the extra fields, `status` included). The
//! plumbing (W1, feature 28) writes the record from them once, as it does for its own steps.

pub mod body;
pub mod content;
pub mod creds;
pub mod email;
pub mod env;
pub mod html_entities;
pub mod json;
pub mod logins;
pub mod loopback;
pub mod mcp;
pub mod mime;
pub mod pyjson;
pub mod record;
pub mod slack;
pub mod telegram;
pub mod twilio;
pub mod voice;
pub mod web;

#[cfg(test)]
mod streaming_tests;
#[cfg(test)]
pub mod testkit;

use bytes::Bytes;
use serde_json::{Map, Value, json};

use crate::flow::{Flow, Hook, Pipeline, Verdict, order};

/// A tool call the MCP check read under the Integrations channel: the web check does not read it again.
pub const META_MCP_CHECKED: &str = "cc_mcp_checked";

/// Set to `true` by the plumbing (W1) on a flow whose bodies reach the checks as the server will
/// read them: chunked transfer undone, `content-encoding` decoded. A check that reads a body
/// refuses a flow without it ([`body_ready`]): a body it cannot read as sent could carry a message
/// past it, so until the plumbing says so, the checks fail closed.
pub const META_BODY_DECODED: &str = "cc_body_decoded";

/// Set by the plumbing (W1) before the response steps: the answer's body alone is decoded (at the
/// response steps [`META_BODY_DECODED`] says both are).
pub const META_RESPONSE_BODY_DECODED: &str = "cc_response_body_decoded";

/// Set to `true` by the plumbing (W1) on a flow whose request body no step said it reads
/// (`Step::reads_body`): it went to the site as it came, and the flow's request has an empty body.
/// At the response steps [`META_BODY_DECODED`] then speaks for the answer alone; a step that reads
/// the request's body there checks [`request_body_ready`], which refuses such a flow.
pub const META_REQUEST_STREAMED: &str = "cc_request_streamed";

/// Whether this flow's bodies are decoded for the checks (see [`META_BODY_DECODED`]).
pub fn body_ready(flow: &Flow) -> bool {
    flow.meta.get(META_BODY_DECODED) == Some(&Value::Bool(true))
}

/// Whether the request's own body is there and decoded: [`body_ready`], and not streamed past the
/// checks ([`META_REQUEST_STREAMED`]).
pub fn request_body_ready(flow: &Flow) -> bool {
    body_ready(flow) && flow.meta.get(META_REQUEST_STREAMED) != Some(&Value::Bool(true))
}

/// Whether the request may have a body, by what is known before it is read: bytes already in the
/// flow, a transfer coding, or a length that is not 0. With no length, HTTP/1.x has none, but an
/// HTTP/2 or HTTP/3 request can still send DATA frames, so it counts as having one. A body streamed
/// past the checks (#625) is not in the flow; this still says.
pub fn request_has_body(flow: &Flow) -> bool {
    flow.request.as_ref().is_some_and(|r| {
        let h = r.headers();
        if !r.body().is_empty() || h.contains_key(http::header::TRANSFER_ENCODING) {
            return true;
        }
        match h.get(http::header::CONTENT_LENGTH) {
            Some(v) => v.to_str().ok().and_then(|v| v.trim().parse::<u64>().ok()) != Some(0),
            None => r.version() >= http::Version::HTTP_2,
        }
    })
}

/// Whether the request's body went to the site past the checks (#625: no step said it reads it).
pub fn request_streamed(flow: &Flow) -> bool {
    flow.meta.get(META_REQUEST_STREAMED) == Some(&Value::Bool(true))
}

/// A request body a check must read and cannot: there is one, and it is not decoded or went past
/// the checks unread (`reads_body` said no, and the flow came to concern a check after all). Such a
/// request is refused, never passed unread.
pub fn request_body_unread(flow: &Flow) -> bool {
    request_has_body(flow) && !request_body_ready(flow)
}

/// Flow metadata the record is written from: the names W1's record reads (`flow::Flow::meta`),
/// the addon's `cc_effect` and `cc_rule`. `record`: the fields a check adds to its record (its
/// status, a hold's id), for a flow it answered.
pub const META_EFFECT: &str = "effect";
pub const META_RULE: &str = "rule";
pub const META_RECORD: &str = "record";

/// Add W2's steps to the pipeline. Called once at start, after W1's own steps.
pub fn register(pipeline: &mut Pipeline) {
    register_with(pipeline, env::Settings::from_env());
}

/// [`register`] with explicit settings, for tests.
pub fn register_with(pipeline: &mut Pipeline, settings: env::Settings) {
    pipeline.push(DESTINATION_GATE, std::sync::Arc::new(DestinationGate));
    let buttons = settings.code_buttons_url.clone();
    let control_plane_host = settings.control_plane_host.clone();
    let control_plane_for_logins = control_plane_host.clone();
    let login_targets_path = settings.login_targets_path.clone();
    let mcp_url = settings.mcp_admission_url.clone();
    let creds = std::sync::Arc::new(creds::Creds::new(settings.credentials_path.clone()));
    let creds_for_logins = creds.clone();
    let email = std::sync::Arc::new(email::Email {
        admission_url: settings.email_admission_url.clone(),
        pending: email::Pending::new(settings.pending_path.clone()),
        agentmail_base: "https://api.agentmail.to".into(),
        creds: creds.clone(),
        http: reqwest::Client::new(),
        content: content::Content::new(settings),
    });
    let content = email.content.clone();
    let content_for_voice = content.clone();
    let web = std::sync::Arc::new(web::Web {
        content: content.clone(),
        control_plane_host,
        creds,
    });
    email::register(pipeline, email);
    telegram::register(pipeline, content.clone(), buttons);
    slack::register(pipeline, content);
    let logins = logins::Logins::new(creds_for_logins.clone(), control_plane_for_logins, login_targets_path);
    mcp::register(
        pipeline,
        std::sync::Arc::new(mcp::Mcp {
            url: mcp_url,
            creds: creds_for_logins.clone(),
            web: web.clone(),
            logins: Some(logins.clone()),
        }),
    );
    twilio::register(pipeline, twilio::Phone::new(creds_for_logins.clone()));
    voice::register(pipeline, voice::Voice::new(creds_for_logins, content_for_voice));
    web::register(pipeline, web);
    logins::register(pipeline, logins);
}

/// The host a check matches on: the checked destination. A request without one never reaches the
/// checks ([`DestinationGate`] refuses it first); the name the request claims is the fallback only
/// for a step a test calls on its own.
pub fn check_host(flow: &Flow) -> String {
    let name = flow
        .destination()
        .map(|d| d.name.clone())
        .or_else(|| flow.claimed_host())
        .unwrap_or_default();
    // The root's dot, as the network layer drops it from a destination.
    name.to_lowercase().trim_end_matches('.').to_owned()
}

/// Answer the agent here with a JSON body (`http.Response.make(status, json.dumps(body),
/// {"Content-Type": "application/json"})`), and leave the record's effect, rule and fields.
pub fn answer(
    flow: &mut Flow,
    status: u16,
    body: &Value,
    effect: &str,
    rule: &str,
    record: Map<String, Value>,
) -> Verdict {
    note(flow, effect, rule, status, record);
    Verdict::Answer(Box::new(json_response(status, body)))
}

/// The record's effect, rule and fields, for a flow answered here or rewritten on its way back.
pub fn note(flow: &mut Flow, effect: &str, rule: &str, status: u16, record: Map<String, Value>) {
    flow.meta.insert(META_EFFECT, json!(effect));
    flow.meta.insert(META_RULE, json!(rule));
    let mut rec = Map::new();
    rec.insert("status".into(), json!(status));
    rec.extend(record);
    flow.meta.insert(META_RECORD, Value::Object(rec));
}

/// A response with a body written by `json.dumps`.
pub fn json_response(status: u16, body: &Value) -> http::Response<Bytes> {
    raw_response(status, pyjson::dumps(body).into_bytes(), "application/json")
}

pub fn raw_response(status: u16, body: Vec<u8>, content_type: &str) -> http::Response<Bytes> {
    let mut r = http::Response::new(Bytes::from(body));
    *r.status_mut() = http::StatusCode::from_u16(status).unwrap_or(http::StatusCode::FORBIDDEN);
    if let Ok(v) = http::HeaderValue::from_str(content_type) {
        r.headers_mut().insert(http::header::CONTENT_TYPE, v);
    }
    let len = r.body().len();
    r.headers_mut()
        .insert(http::header::CONTENT_LENGTH, http::HeaderValue::from(len));
    r
}

/// Replace a request's body as the server will read it: its length fixed, no transfer or content
/// encoding left on it.
pub fn set_request_body(req: &mut http::Request<Bytes>, body: Vec<u8>) {
    let len = body.len();
    *req.body_mut() = Bytes::from(body);
    req.headers_mut().remove(http::header::CONTENT_ENCODING);
    req.headers_mut().remove(http::header::TRANSFER_ENCODING);
    req.headers_mut()
        .insert(http::header::CONTENT_LENGTH, http::HeaderValue::from(len));
}

/// Replace a response's body, fixing its length (`flow.response.set_content`).
pub fn set_body(resp: &mut http::Response<Bytes>, body: Vec<u8>) {
    let len = body.len();
    *resp.body_mut() = Bytes::from(body);
    resp.headers_mut().remove(http::header::CONTENT_ENCODING);
    resp.headers_mut().remove(http::header::TRANSFER_ENCODING);
    resp.headers_mut()
        .insert(http::header::CONTENT_LENGTH, http::HeaderValue::from(len));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::testing::request_flow;

    #[test]
    fn every_w2_slot_has_a_number_of_its_own() {
        // A slot is found by its number alone: two W2 slots on one number, or a W2 slot on a number
        // another hook's step uses, would let one stand in for the other in the startup check.
        let required = order::W2_REQUIRED;
        let mut seen = std::collections::HashSet::new();
        for slot in required {
            assert!(seen.insert(*slot), "slot {slot} twice");
        }
        for other in [
            order::MODEL_ANSWERS,
            order::RESIDENTIAL_RECORD,
            order::RESPONSE_LOG,
            order::ERROR_LOG,
            order::SWAPS,
            order::REQUEST_TAIL,
        ] {
            assert!(!required.contains(&other), "slot {other} is W1's");
        }
        // The real registration fills every one of them.
        let mut p = crate::flow::Pipeline::new();
        register(&mut p);
        for slot in required {
            assert!(p.has_slot(*slot), "slot {slot} empty");
        }
    }

    #[test]
    fn an_answer_leaves_its_record() {
        let mut flow = request_flow("POST", "https://api.telegram.org/bot1:x/sendMessage", b"");
        let mut extra = Map::new();
        extra.insert("hold".into(), json!("h1"));
        let v = answer(&mut flow, 200, &json!({"ok": true}), "hold", "content: iban", extra);
        let Verdict::Answer(r) = v else { panic!("an answer") };
        assert_eq!(r.status(), 200);
        assert_eq!(r.body().as_ref(), br#"{"ok": true}"#);
        assert_eq!(r.headers()["content-type"], "application/json");
        assert_eq!(r.headers()["content-length"], "12");
        assert_eq!(flow.meta[META_EFFECT], "hold");
        assert_eq!(flow.meta[META_RECORD], json!({"status": 200, "hold": "h1"}));
    }
}

/// Just before the first of W2's request steps.
pub const DESTINATION_GATE: u16 = order::LOGIN_TRIPWIRE - 1;

/// A request whose destination the network layer has not checked is refused before any of W2's
/// checks: each keys on the destination, and a name the agent claims could take it past one (a
/// `Host: example.com` on a connection to the mail API). Fails closed while W1's slot is empty.
pub struct DestinationGate;

impl crate::flow::Step for DestinationGate {
    fn name(&self) -> &'static str {
        "destination-gate"
    }
    fn hooks(&self) -> &'static [crate::flow::Hook] {
        &[crate::flow::Hook::Request]
    }
    /// The destination only.
    fn reads_body(&self, _: Hook, _: &mut Flow) -> bool {
        false
    }
    fn run<'a>(&'a self, _: crate::flow::Hook, flow: &'a mut Flow) -> crate::flow::StepFuture<'a> {
        Box::pin(async move {
            if flow.destination().is_some() {
                return Verdict::Continue;
            }
            answer(
                flow,
                503,
                &json!({"error": "The firewall could not check where this request goes, so it did not send it."}),
                "block",
                "unchecked destination",
                Map::new(),
            )
        })
    }
}

#[cfg(test)]
mod gate_tests {
    use super::*;
    use crate::flow::{Authority, Hook, Step};

    #[tokio::test]
    async fn a_request_with_no_checked_destination_is_refused() {
        let mut f = Flow::new(
            std::net::IpAddr::from([10, 0, 0, 3]),
            Authority {
                host: "203.0.113.5".into(),
                port: 443,
            },
        );
        f.request = http::Request::builder()
            .method("POST")
            .uri("https://example.com/v0/inboxes/a/messages/send")
            .header("host", "example.com")
            .body(Bytes::new())
            .ok();
        assert!(matches!(DestinationGate.run(Hook::Request, &mut f).await, Verdict::Answer(r) if r.status() == 503));
        let mut ok = crate::flow::testing::request_flow("GET", "https://api.agentmail.to/v0/inboxes", b"");
        assert!(matches!(
            DestinationGate.run(Hook::Request, &mut ok).await,
            Verdict::Continue
        ));
    }
}
