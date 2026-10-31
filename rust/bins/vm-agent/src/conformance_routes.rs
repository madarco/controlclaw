//! Routes for the conformance rig only: `/__conformance/firewall`, firewall-signed (purpose
//! `channels`), so the token binding (replay, unbound after the latch, wrong host, the restart
//! floor, a body other than the one signed) can be tested on the running binary before any
//! workstream has ported a real firewall route. `POST` reads a JSON body, `GET` reads none.
//! Registered only with `CC_CONFORMANCE_ROUTES=1`, which the rig sets and no systemd unit does. They
//! do nothing but say what they saw.

use std::sync::Arc;

use cc_http::{FirewallBody, FirewallRequest, ReadBody, Resp, Router, json};
use hyper::Method;
use serde_json::{Value, json as j};

use crate::app::App;
use crate::stages;

pub const PATH: &str = "/__conformance/firewall";

/// The pattern every firewall route follows: refused is a 401, a rejected body a 400.
fn answer(r: FirewallRequest) -> Resp {
    match r {
        FirewallRequest::Refused { reason, .. } => json(
            401,
            &j!({"error": "Unauthorized", "refused": reason.map(|r| r.as_str())}),
        ),
        FirewallRequest::Accepted {
            body: FirewallBody::Rejected,
            ..
        } => json(400, &j!({"error": "Bad request"})),
        FirewallRequest::Accepted { accepted, body, .. } => {
            let body = match body {
                FirewallBody::Json(m) => Value::Object(m),
                _ => Value::Null,
            };
            json(200, &j!({"ok": true, "bound": accepted.bound, "body": body}))
        }
    }
}

pub fn register(router: &mut Router, app: &Arc<App>) {
    let a = app.clone();
    router.exact(stages::PREFIXED, Method::POST, PATH, move |req, _| {
        let app = a.clone();
        async move {
            answer(
                cc_http::firewall_request(&app.firewall_auth, req, "channels", 0, ReadBody::Json { limit: 16_384 })
                    .await,
            )
        }
    });
    let a = app.clone();
    router.exact(stages::PREFIXED, Method::GET, PATH, move |req, _| {
        let app = a.clone();
        async move { answer(cc_http::firewall_request(&app.firewall_auth, req, "channels", 0, ReadBody::No).await) }
    });
}
