//! A standalone firewall relays the brain's own pages to the browser (docs/plans/standalone-brain.md,
//! "the brain's own pages"). The brain sits on the firewall's private side (a WireGuard address, a
//! Docker network, a LAN address that lets only the firewall in), so a browser cannot reach it. This
//! listener, `BRAIN_PAGES_BIND` (default `127.0.0.1:8803`, `off` to close it), forwards to the brain's
//! vm-agent at its paired address, where the firewall already calls it.
//!
//! A listener of its own is an origin of its own: the person puts a name in front of it (Caddy,
//! Tailscale Serve), and the brain's sign-in, its `__Host-` cookies, its Origin checks and its
//! absolute `/__cc/brain` paths work as on the SaaS, apart from the firewall's own `/__cc/*`.
//!
//! Only what a browser uses goes through: `/__cc/*` (the sign-in exchange, the pages and their API,
//! the page bundle) and GBrain's `/admin` when the brain serves it. The routes the firewall signs
//! (`/gbrain/*`, `/llm/*`, `/access/*`) and the console's (`/status`, `/health`, `/logs`) are a 404
//! here, whatever token a request carries. Bodies are streamed both ways (an import, an export).

use std::sync::Arc;
use std::time::Duration;

use cc_http::{Body, Req, Resp};
use http_body_util::BodyExt;

use super::Core;

pub const DEFAULT_BIND: &str = "127.0.0.1:8803";
/// Connecting to the brain; after that the answer streams for as long as it takes.
const CONNECT: Duration = Duration::from_secs(15);
/// Headers that belong to one connection, never passed on.
const HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// The headers of one connection: the fixed ones, and every one `Connection` names.
fn strip_hop(headers: &mut http::HeaderMap) {
    let named: Vec<String> = headers
        .get_all(http::header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|n| n.trim().to_ascii_lowercase())
        .filter(|n| !n.is_empty())
        .collect();
    for n in named {
        headers.remove(n.as_str());
    }
    for h in HOP {
        headers.remove(*h);
    }
}

/// Whether a browser's request may go on to the brain. The path is read as sent and decoded once,
/// so `%2e%2e` or `%2f` cannot reach a route the relay keeps out; something still encoded after
/// that (`%252e`) is refused.
pub fn allowed(path: &str) -> bool {
    let decoded: String = url::form_urlencoded::parse(format!("p={}", path.replace('+', "%2B")).as_bytes())
        .next()
        .map(|(_, v)| v.into_owned())
        .unwrap_or_default();
    let bad = |p: &str| p.contains("..") || p.contains('\\') || p.contains("//");
    !bad(path) && !bad(&decoded) && !decoded.contains('%') && allowed_plain(path) && allowed_plain(&decoded)
}

fn allowed_plain(path: &str) -> bool {
    let cc = path.starts_with("/__cc/") && path != "/__cc/agent" && !path.starts_with("/__cc/agent/");
    cc || path == "/admin" || path.starts_with("/admin/")
}

fn plain(status: u16, text: &'static str) -> Resp {
    cc_http::full(
        http::StatusCode::from_u16(status).unwrap_or(http::StatusCode::BAD_GATEWAY),
        "text/plain; charset=utf-8",
        text,
    )
}

/// Where the brain's vm-agent is: its paired address, never a hostname.
fn brain_addr(core: &Core) -> Option<std::net::SocketAddr> {
    let vm = core.brain.get()?.brain_vm()?;
    let route = core.agents.route_for(&vm)?;
    route.base.strip_prefix("http://")?.parse().ok()
}

async fn relay(core: Arc<Core>, req: Req) -> Resp {
    let path = req.uri().path().to_string();
    if !allowed(&path) {
        return plain(404, "Not found");
    }
    let Some(addr) = brain_addr(&core) else {
        return plain(503, "This firewall has no brain to show, or no address for it yet.");
    };
    match forward(addr, req).await {
        Ok(r) => r,
        Err(e) => {
            tracing::info!("[brain-pages] the brain did not answer: {e}");
            plain(
                502,
                "The brain is not answering. It may be starting; try again in a minute.",
            )
        }
    }
}

/// Aborts the connection's task when the answer is dropped (the browser went away).
struct AbortOnDrop(tokio::task::AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn forward(addr: std::net::SocketAddr, req: Req) -> Result<Resp, String> {
    let (mut parts, body) = req.into_parts();
    let tcp = tokio::time::timeout(CONNECT, tokio::net::TcpStream::connect(addr))
        .await
        .map_err(|_| "timeout".to_string())?
        .map_err(|e| e.to_string())?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tcp))
        .await
        .map_err(|e| e.to_string())?;
    let guard = AbortOnDrop(
        tokio::spawn(async move {
            let _ = conn.await;
        })
        .abort_handle(),
    );
    strip_hop(&mut parts.headers);
    // What the browser says of where it came from is not the brain's to read: this relay is.
    let forwarded: Vec<http::HeaderName> = parts
        .headers
        .keys()
        .filter(|k| {
            let k = k.as_str();
            k.starts_with("x-forwarded-") || k == "forwarded" || k == "x-real-ip"
        })
        .cloned()
        .collect();
    for k in forwarded {
        parts.headers.remove(k);
    }
    // The Host the browser used stays: the brain's pages build nothing from it, and its Origin
    // checks read Origin. The target is the path and query only.
    let pq = parts
        .uri
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".into());
    parts.uri = pq.parse().map_err(|e: http::uri::InvalidUri| e.to_string())?;
    let up = sender
        .send_request(http::Request::from_parts(parts, body))
        .await
        .map_err(|e| e.to_string())?;
    let (mut parts, body) = up.into_parts();
    strip_hop(&mut parts.headers);
    let frames = futures_util::stream::unfold((body, guard), |(mut body, guard)| async move {
        match body.frame().await {
            Some(Ok(f)) => Some((Ok(f), (body, guard))),
            Some(Err(e)) => Some((Err(std::io::Error::other(e)), (body, guard))),
            None => None,
        }
    });
    let body: Body = http_body_util::StreamBody::new(frames).boxed();
    Ok(http::Response::from_parts(parts, body))
}

/// The listener, on a standalone firewall with a brain module.
pub fn start(core: &Arc<Core>) {
    let bind = std::env::var("BRAIN_PAGES_BIND").unwrap_or_else(|_| DEFAULT_BIND.into());
    if bind.trim().eq_ignore_ascii_case("off") {
        return;
    }
    let Ok(addr) = bind.parse::<std::net::SocketAddr>() else {
        tracing::error!(
            "[brain-pages] BRAIN_PAGES_BIND={bind} is not an address and port; the brain's pages are not served"
        );
        return;
    };
    let mut router = cc_http::Router::new(&["all"]);
    let c = core.clone();
    router.route(
        "all",
        |_, _| true,
        move |req, _| {
            let c = c.clone();
            async move { relay(c, req).await }
        },
    );
    let router = Arc::new(router);
    tokio::spawn(async move {
        match tokio::net::TcpListener::bind(addr).await {
            Ok(l) => {
                tracing::info!("[brain-pages] the brain's pages on {addr}");
                cc_http::serve(l, router).await;
            }
            Err(e) => tracing::error!("[brain-pages] could not listen on {addr}: {e}"),
        }
    });
}

#[cfg(test)]
mod tests {
    use super::{allowed, forward, strip_hop};
    use std::sync::Arc;

    /// What reaches the brain from a browser through the relay: never the browser's own word on
    /// where it came from, nor a header its `Connection` names.
    #[tokio::test]
    async fn the_relay_drops_forwarded_and_hop_headers() {
        let mut brain = cc_http::Router::new(&["all"]);
        brain.route(
            "all",
            |_, _| true,
            |req: cc_http::Req, _| async move {
                let names: Vec<String> = req.headers().keys().map(|k| k.as_str().to_string()).collect();
                cc_http::json(200, &serde_json::json!({ "headers": names }))
            },
        );
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let brain_addr = l.local_addr().expect("addr");
        tokio::spawn(cc_http::serve(l, Arc::new(brain)));
        let mut relay = cc_http::Router::new(&["all"]);
        relay.route(
            "all",
            |_, _| true,
            move |req: cc_http::Req, _| async move { forward(brain_addr, req).await.expect("forward") },
        );
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let relay_addr = l.local_addr().expect("addr");
        tokio::spawn(cc_http::serve(l, Arc::new(relay)));
        let got: serde_json::Value = reqwest::Client::new()
            .get(format!("http://{relay_addr}/__cc/brain"))
            .header("x-forwarded-for", "6.6.6.6")
            .header("x-forwarded-host", "evil.example")
            .header("forwarded", "for=6.6.6.6")
            .header("x-real-ip", "6.6.6.6")
            .header("connection", "x-secret-hop")
            .header("x-secret-hop", "1")
            .header("cookie", "a=b")
            .send()
            .await
            .expect("send")
            .json()
            .await
            .expect("json");
        let names: Vec<&str> = got["headers"]
            .as_array()
            .expect("list")
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        for gone in [
            "x-forwarded-for",
            "x-forwarded-host",
            "forwarded",
            "x-real-ip",
            "x-secret-hop",
            "connection",
        ] {
            assert!(!names.contains(&gone), "{gone} reached the brain: {names:?}");
        }
        assert!(names.contains(&"cookie"));
    }

    #[test]
    fn the_connections_own_headers_go() {
        let mut h = http::HeaderMap::new();
        h.insert("connection", "keep-alive, X-Secret-Hop".parse().expect("v"));
        h.insert("x-secret-hop", "1".parse().expect("v"));
        h.insert("keep-alive", "timeout=5".parse().expect("v"));
        h.insert("cookie", "a=b".parse().expect("v"));
        strip_hop(&mut h);
        assert!(h.get("x-secret-hop").is_none() && h.get("connection").is_none() && h.get("keep-alive").is_none());
        assert_eq!(h["cookie"], "a=b", "the brain's own sign-in reads its cookie");
    }

    #[test]
    fn only_what_a_browser_uses() {
        for p in [
            "/__cc/open",
            "/__cc/open/begin",
            "/__cc/session",
            "/__cc/brain",
            "/__cc/brain/lately",
            "/__cc/brain/api/pages",
            "/__cc/files-ui/brain.js",
            "/__cc/shell.js",
            "/admin",
            "/admin/auth/x",
            "/__cc/brain/api/pages/people%2Fana",
        ] {
            assert!(allowed(p), "{p}");
        }
        for p in [
            "/gbrain/connect",
            "/gbrain/mcp/vm_1",
            "/llm/apply",
            "/access/config",
            "/status",
            "/health",
            "/logs",
            "/brain/model",
            "/__cc/agent",
            "/__cc/agent/status",
            "/__cc/../gbrain/connect",
            "/__cc//x",
            "/__cc/%2e%2e/gbrain/connect",
            "/__cc/%2E%2E/status",
            "/__cc/brain/%2f%2fx",
            "/__cc/%252e%252e/x",
            "/administrator",
            "/",
        ] {
            assert!(!allowed(p), "{p}");
        }
    }
}
