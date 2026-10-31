//! Outgoing HTTPS from the firewall to an address a person typed: an MCP server, its sign-in
//! server (`public-host.ts`). The firewall sits on the organization's private network next to the
//! agents, so a URL that resolves to a private, loopback or link-local address would let a console
//! change reach the agents' own ports, or the cloud metadata service. Every resolution is checked,
//! and the address checked is the address dialled (the client's resolver drops the rest), so a
//! second DNS answer cannot move the connection somewhere private. Redirects are not followed.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use bytes::Bytes;
use http::HeaderMap;
use url::Url;

fn v4_in(a: Ipv4Addr, net: [u8; 4], bits: u32) -> bool {
    let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
    u32::from(a) & mask == u32::from(Ipv4Addr::from(net)) & mask
}

fn v6_in(a: Ipv6Addr, net: &str, bits: u32) -> bool {
    let Ok(n) = net.parse::<Ipv6Addr>() else { return false };
    let mask = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
    u128::from(a) & mask == u128::from(n) & mask
}

const V4_BLOCKED: &[([u8; 4], u32)] = &[
    ([0, 0, 0, 0], 8),
    ([10, 0, 0, 0], 8),
    ([100, 64, 0, 0], 10),
    ([127, 0, 0, 0], 8),
    ([169, 254, 0, 0], 16),
    ([172, 16, 0, 0], 12),
    ([192, 0, 0, 0], 24),
    ([192, 0, 2, 0], 24),
    ([192, 168, 0, 0], 16),
    ([198, 18, 0, 0], 15),
    ([198, 51, 100, 0], 24),
    ([203, 0, 113, 0], 24),
    ([224, 0, 0, 0], 4),
    ([240, 0, 0, 0], 4),
];

const V6_BLOCKED: &[(&str, u32)] = &[
    ("::", 128),
    // IPv4-compatible (deprecated) and site-local: both can lead back to private addresses.
    ("::", 96),
    ("fec0::", 10),
    ("::1", 128),
    ("64:ff9b::", 96),
    ("64:ff9b:1::", 48),
    // 6to4 carries an IPv4 address inside; a private one would reach the private network.
    ("2002::", 16),
    ("100::", 64),
    ("2001:db8::", 32),
    ("fc00::", 7),
    ("fe80::", 10),
    ("ff00::", 8),
];

/// True for an address on the internet; false for private, loopback, link-local and the like.
pub fn is_public_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => !V4_BLOCKED.iter().any(|(n, b)| v4_in(a, *n, *b)),
        // An IPv4 address written as IPv6 is the IPv4 address.
        IpAddr::V6(a) => match a.to_ipv4_mapped() {
            Some(v4) => is_public_address(IpAddr::V4(v4)),
            None => !V6_BLOCKED.iter().any(|(n, b)| v6_in(a, n, *b)),
        },
    }
}

/// A test may dial the plain-HTTP fakes on loopback; the daemon never can.
#[cfg(test)]
fn test_local(url: &Url) -> bool {
    url.scheme() == "http" && url.host_str() == Some("127.0.0.1")
}

#[cfg(not(test))]
fn test_local(_url: &Url) -> bool {
    false
}

/// Whether a URL is one the firewall may dial: https, a host name or public address, no user or
/// password.
pub fn public_https_url(value: &str) -> Option<Url> {
    let url = Url::parse(value).ok()?;
    if test_local(&url) {
        return Some(url);
    }
    if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
        return None;
    }
    match url.host()? {
        url::Host::Ipv4(a) if !is_public_address(IpAddr::V4(a)) => return None,
        url::Host::Ipv6(a) if !is_public_address(IpAddr::V6(a)) => return None,
        url::Host::Domain(d)
            if d == "localhost" || d.ends_with(".localhost") || d.ends_with(".internal") || d.ends_with(".local") =>
        {
            return None;
        }
        _ => {}
    }
    Some(url)
}

/// The resolver the client dials with: public answers only.
struct PublicResolver;

impl reqwest::dns::Resolve for PublicResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            let all: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0)).await?.collect();
            let public: Vec<SocketAddr> = all.into_iter().filter(|a| is_public_address(a.ip())).collect();
            if public.is_empty() {
                return Err(format!("{host} is not an address on the internet").into());
            }
            Ok(Box::new(public.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

static CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .dns_resolver(Arc::new(PublicResolver))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .unwrap_or_default()
});

#[derive(Debug, Clone)]
pub struct PublicAnswer {
    pub status: u16,
    pub headers: HeaderMap,
    pub body: Bytes,
}

impl PublicAnswer {
    pub fn header(&self, name: &str) -> Option<String> {
        let v: Vec<&str> = self
            .headers
            .get_all(name)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect();
        (!v.is_empty()).then(|| v.join(", "))
    }
}

/// The checks every request gets before it leaves: the URL, and an address in it that is not public.
fn checked(url: &Url) -> Result<(), String> {
    if test_local(url) {
        return Ok(());
    }
    if public_https_url(url.as_str()).is_none() {
        let host = url.host_str().unwrap_or_default();
        return Err(format!("{host} is not an address on the internet"));
    }
    Ok(())
}

pub struct Request<'a> {
    pub method: &'a str,
    pub headers: Vec<(String, String)>,
    pub body: Option<Bytes>,
    pub timeout: Duration,
}

impl Default for Request<'_> {
    fn default() -> Self {
        Self {
            method: "GET",
            headers: Vec::new(),
            body: None,
            timeout: Duration::from_secs(15),
        }
    }
}

/// An HTTPS request to a public address only; the answer is the caller's to read, through
/// [`idle_body`]. `timeout` is how long the connection may sit idle, as Node's `req.setTimeout`:
/// here, until the answer's head; [`idle_body`] keeps it for every read after.
pub async fn public_request(url: &Url, r: Request<'_>) -> Result<reqwest::Response, String> {
    checked(url)?;
    let method = reqwest::Method::from_bytes(r.method.as_bytes()).map_err(|e| e.to_string())?;
    let mut req = CLIENT.request(method, url.clone());
    for (k, v) in r.headers {
        req = req.header(k, v);
    }
    if let Some(b) = r.body {
        req = req.body(b);
    }
    let sent = tokio::time::timeout(r.timeout, req.send())
        .await
        .map_err(|_| "timeout".to_string())?;
    sent.map_err(|e| {
        if e.is_timeout() {
            return "timeout".to_string();
        }
        // The resolver's own words, when it refused every answer.
        let mut src: Option<&dyn std::error::Error> = Some(&e);
        while let Some(s) = src {
            let text = s.to_string();
            if text.ends_with("is not an address on the internet") {
                return text;
            }
            src = s.source();
        }
        // Never the URL: a request's address can carry a token.
        e.without_url().to_string()
    })
}

/// The answer's body, each read allowed `idle` with nothing arriving (`timeout` when it is not),
/// so a stream that keeps sending lives as long as it sends. Errors never carry the URL.
pub fn idle_body(
    res: reqwest::Response,
    idle: Duration,
) -> impl futures_util::Stream<Item = Result<Bytes, String>> + Send + 'static {
    futures_util::stream::unfold(Some(res), move |res| async move {
        let mut res = res?;
        match tokio::time::timeout(idle, res.chunk()).await {
            Err(_) => Some((Err("timeout".to_string()), None)),
            Ok(Ok(Some(c))) => Some((Ok(c), Some(res))),
            Ok(Ok(None)) => None,
            Ok(Err(e)) => Some((
                Err(if e.is_timeout() {
                    "timeout".to_string()
                } else {
                    e.without_url().to_string()
                }),
                None,
            )),
        }
    })
}

/// A whole request and answer, the answer cut at `max_bytes` (the request fails past it).
pub async fn public_fetch(url: &Url, r: Request<'_>, max_bytes: usize) -> Result<PublicAnswer, String> {
    use futures_util::StreamExt;
    let idle = r.timeout;
    let res = public_request(url, r).await?;
    let status = res.status().as_u16();
    let headers = res.headers().clone();
    let mut body = Vec::new();
    let mut chunks = std::pin::pin!(idle_body(res, idle));
    while let Some(chunk) = chunks.next().await {
        body.extend_from_slice(&chunk?);
        if body.len() > max_bytes {
            return Err("the answer is too large".into());
        }
    }
    Ok(PublicAnswer {
        status,
        headers,
        body: Bytes::from(body),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_https_to_the_internet_is_dialled() {
        for (ip, public) in [
            ("8.8.8.8", true),
            ("10.0.0.5", false),
            ("100.64.1.1", false),
            ("127.0.0.1", false),
            ("169.254.169.254", false),
            ("172.20.0.1", false),
            ("192.168.1.1", false),
            ("::1", false),
            ("::ffff:10.0.0.1", false),
            ("::ffff:8.8.8.8", true),
            ("fd00::1", false),
            ("fe80::1", false),
            ("2002:a00:1::", false),
            ("2606:4700:4700::1111", true),
        ] {
            assert_eq!(is_public_address(ip.parse().expect("ip")), public, "{ip}");
        }
        assert!(public_https_url("https://mcp.example.com/mcp").is_some());
        for bad in [
            "http://mcp.example.com/mcp",
            "https://user:pw@mcp.example.com/",
            "https://10.0.0.5/mcp",
            "https://[::1]/mcp",
            "https://localhost/mcp",
            "https://box.internal/",
            "https://printer.local/",
            "https://127.0.0.1/mcp",
            "not a url",
        ] {
            assert!(public_https_url(bad).is_none(), "{bad}");
        }
    }

    #[tokio::test]
    async fn a_private_answer_is_never_dialled() {
        let url = Url::parse("https://localhost.localdomain.invalid/x").expect("url");
        assert!(public_fetch(&url, Request::default(), 10).await.is_err());
        let ip = Url::parse("https://10.1.2.3/").expect("url");
        assert_eq!(
            public_fetch(&ip, Request::default(), 10).await.err().as_deref(),
            Some("10.1.2.3 is not an address on the internet")
        );
    }

    /// A raw HTTP server that sends a chunk every `gap`, `n` times, then stops (or stays silent).
    async fn trickle(gap: Duration, n: usize, end: bool) -> Url {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let url = Url::parse(&format!("http://{}/s", l.local_addr().expect("addr"))).expect("url");
        tokio::spawn(async move {
            let (mut c, _) = l.accept().await.expect("accept");
            let mut buf = [0u8; 2048];
            let _ = c.read(&mut buf).await;
            let _ = c
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\n\r\n")
                .await;
            for _ in 0..n {
                tokio::time::sleep(gap).await;
                let _ = c.write_all(b"5\r\nhello\r\n").await;
            }
            if end {
                let _ = c.write_all(b"0\r\n\r\n").await;
            } else {
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        });
        url
    }

    #[tokio::test]
    async fn the_timeout_is_idle_only_as_nodes_set_timeout() {
        use futures_util::StreamExt;
        // Sending every 100 ms for 600 ms in all, with 250 ms allowed idle: it lives to the end.
        let url = trickle(Duration::from_millis(100), 6, true).await;
        let r = Request {
            timeout: Duration::from_millis(250),
            ..Default::default()
        };
        let res = public_request(&url, r).await.expect("head");
        let got: Vec<Result<Bytes, String>> = idle_body(res, Duration::from_millis(250)).collect().await;
        assert_eq!(got.iter().filter(|c| c.is_ok()).count(), 6);
        assert!(got.iter().all(Result::is_ok));
        // Gone quiet for longer than that: the read ends with `timeout`.
        let url = trickle(Duration::from_millis(10), 1, false).await;
        let res = public_request(
            &url,
            Request {
                timeout: Duration::from_millis(250),
                ..Default::default()
            },
        )
        .await
        .expect("head");
        let got: Vec<Result<Bytes, String>> = idle_body(res, Duration::from_millis(250)).collect().await;
        assert_eq!(got.last(), Some(&Err("timeout".to_string())));
    }
}
