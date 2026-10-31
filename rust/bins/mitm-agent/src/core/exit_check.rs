//! Does the org's residential exit work, and what address does the world see (`exit-check.ts`)?
//! The same handshake the proxy does (HTTP CONNECT or SOCKS5, with the credential, through a TLS
//! hop when the exit's scheme is `https`), then a GET to an echo service through the tunnel.

use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use regex::Regex;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const CHECK_SESSION: &str = "__check";
const DEFAULT_URL: &str = "https://ipinfo.io/json";
const TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, Clone, PartialEq)]
pub struct CheckResult {
    pub ok: bool,
    pub exit_ip: Option<String>,
    pub exit_country: Option<String>,
    pub latency_ms: u64,
    pub error: Option<String>,
}

/// What the check needs of the stored upstream.
#[derive(Debug, Clone)]
pub struct Upstream {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: String,
}

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

fn fail(message: &str) -> CheckResult {
    CheckResult {
        ok: false,
        exit_ip: None,
        exit_country: None,
        latency_ms: 0,
        error: Some(message.chars().take(200).collect()),
    }
}

fn tls_config() -> Arc<rustls::ClientConfig> {
    static CONFIG: LazyLock<Arc<rustls::ClientConfig>> = LazyLock::new(|| {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        // Node also trusts NODE_EXTRA_CA_CERTS.
        if let Ok(path) = std::env::var("NODE_EXTRA_CA_CERTS")
            && let Ok(pem) = std::fs::read(path)
        {
            for cert in rustls_pemfile::certs(&mut pem.as_slice()).flatten() {
                let _ = roots.add(cert);
            }
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        Arc::new(
            rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .map(|b| b.with_root_certificates(roots).with_no_client_auth())
                .unwrap_or_else(|_| {
                    rustls::ClientConfig::builder()
                        .with_root_certificates(rustls::RootCertStore::empty())
                        .with_no_client_auth()
                }),
        )
    });
    CONFIG.clone()
}

async fn tls<S: Io + 'static>(stream: S, name: &str) -> Result<Box<dyn Io>, String> {
    let server = rustls::pki_types::ServerName::try_from(name.to_string()).map_err(|e| e.to_string())?;
    let conn = tokio_rustls::TlsConnector::from(tls_config());
    let s = tokio::time::timeout(TIMEOUT, conn.connect(server, stream))
        .await
        .map_err(|_| "timed out negotiating TLS with the exit".to_string())?
        .map_err(|e| e.to_string())?;
    Ok(Box::new(s))
}

/// Read until `done` says the buffer is complete; a close is fine only when `ends_ok`.
async fn read_until(s: &mut (dyn Io + '_), done: impl Fn(&[u8]) -> bool, ends_ok: bool) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    let read = async {
        let mut chunk = [0u8; 8192];
        loop {
            let n = s.read(&mut chunk).await.map_err(|e| e.to_string())?;
            if n == 0 {
                return if ends_ok {
                    Ok(())
                } else {
                    Err("the connection closed early".to_string())
                };
            }
            buf.extend_from_slice(&chunk[..n]);
            if done(&buf) {
                return Ok(());
            }
        }
    };
    tokio::time::timeout(TIMEOUT, read)
        .await
        .map_err(|_| "timed out".to_string())??;
    Ok(buf)
}

fn find(b: &[u8], needle: &[u8]) -> Option<usize> {
    b.windows(needle.len()).position(|w| w == needle)
}

async fn http_connect(s: &mut (dyn Io + '_), target: &str, user: &str, password: &str) -> Result<(), String> {
    use base64::Engine;
    let auth = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"));
    let req = format!(
        "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: Basic {auth}\r\nProxy-Connection: keep-alive\r\n\r\n"
    );
    s.write_all(req.as_bytes()).await.map_err(|e| e.to_string())?;
    let head = read_until(s, |b| find(b, b"\r\n\r\n").is_some(), false).await?;
    let line_end = find(&head, b"\r\n").unwrap_or(head.len());
    let status = String::from_utf8_lossy(&head[..line_end]).into_owned();
    static OK: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^HTTP/1\.[01] 2[0-9][0-9]").expect("re"));
    if !OK.is_match(&status) {
        return Err(format!("the exit refused the tunnel: {status}"));
    }
    Ok(())
}

fn socks5_reply_complete(b: &[u8]) -> bool {
    if b.len() < 5 {
        return false;
    }
    match b[3] {
        0x01 => b.len() >= 10,
        0x04 => b.len() >= 22,
        0x03 => b.len() >= 7 + b[4] as usize,
        _ => true,
    }
}

async fn socks5_connect(
    s: &mut (dyn Io + '_),
    host: &str,
    port: u16,
    user: &str,
    password: &str,
) -> Result<(), String> {
    let w = |e: std::io::Error| e.to_string();
    // Username and password only: a proxy that would take us without must not talk us out of it.
    s.write_all(&[0x05, 0x01, 0x02]).await.map_err(w)?;
    let greeting = read_until(s, |b| b.len() >= 2, false).await?;
    if greeting[0] != 0x05 || greeting[1] != 0x02 {
        return Err("the exit refused username/password auth".into());
    }
    let (u, p) = (user.as_bytes(), password.as_bytes());
    // SOCKS5 carries each in one length byte: a longer one would be cut and sent as another.
    if u.len() > 255 || p.len() > 255 {
        return Err("the exit's username or password is longer than SOCKS5 allows (255 bytes)".into());
    }
    let mut auth = vec![0x01, u.len() as u8];
    auth.extend_from_slice(u);
    auth.push(p.len() as u8);
    auth.extend_from_slice(p);
    s.write_all(&auth).await.map_err(w)?;
    let reply = read_until(s, |b| b.len() >= 2, false).await?;
    if reply[1] != 0x00 {
        return Err("the exit rejected the credential".into());
    }
    let name = host.as_bytes();
    if name.len() > 255 {
        return Err("the host name is longer than SOCKS5 allows (255 bytes)".into());
    }
    let mut req = vec![0x05, 0x01, 0x00, 0x03, name.len() as u8];
    req.extend_from_slice(name);
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await.map_err(w)?;
    let reply = read_until(s, socks5_reply_complete, false).await?;
    if reply[1] != 0x00 {
        return Err(format!("the exit refused the connection (reply {})", reply[1]));
    }
    Ok(())
}

/// Headers, plus a body as long as it claims; chunked or close-delimited waits for the close.
fn response_complete(b: &[u8]) -> bool {
    let Some(end) = find(b, b"\r\n\r\n") else { return false };
    let head = String::from_utf8_lossy(&b[..end]).to_lowercase();
    static LEN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"content-length:\s*([0-9]+)").expect("re"));
    let Some(c) = LEN.captures(&head) else { return false };
    b.len() >= end + 4 + c[1].parse::<usize>().unwrap_or(usize::MAX - end - 4)
}

/// `parseEcho`: the address and the country out of a JSON body or a bare address line.
pub fn parse_echo(body: &str) -> (Option<String>, Option<String>) {
    static IP: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#""ip"\s*:\s*"([0-9a-fA-F.:]{7,45})""#).expect("re"));
    static LINE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[0-9a-fA-F.:]{7,45}$").expect("re"));
    static COUNTRY: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#""country"\s*:\s*"([A-Za-z]{2})""#).expect("re"));
    let ip = IP.captures(body).map(|c| c[1].to_string()).or_else(|| {
        body.split('\n')
            .map(str::trim)
            .find(|l| LINE.is_match(l))
            .map(str::to_string)
    });
    let country = COUNTRY.captures(body).map(|c| c[1].to_uppercase());
    (ip, country)
}

/// `checkExit`, with the username and password already rendered from the templates.
pub async fn check_exit(up: &Upstream, url: Option<&str>) -> CheckResult {
    let started = Instant::now();
    let url = url
        .map(str::to_string)
        .or_else(|| std::env::var("MITM_EXIT_CHECK_URL").ok().filter(|u| !u.is_empty()))
        .unwrap_or_else(|| DEFAULT_URL.into());
    let Ok(parsed) = url::Url::parse(&url) else {
        return fail("Invalid URL");
    };
    let host = parsed.host_str().unwrap_or_default().to_string();
    let port = parsed.port().unwrap_or(443);
    let path = format!(
        "{}{}",
        parsed.path(),
        parsed.query().map(|q| format!("?{q}")).unwrap_or_default()
    );
    let run = async {
        let tcp = tokio::time::timeout(TIMEOUT, tokio::net::TcpStream::connect((up.host.as_str(), up.port)))
            .await
            .map_err(|_| "timed out connecting to the exit".to_string())?
            .map_err(|e| e.to_string())?;
        let mut s: Box<dyn Io> = if up.scheme == "https" {
            tls(tcp, &up.host).await?
        } else {
            Box::new(tcp)
        };
        if up.scheme == "socks5" {
            socks5_connect(s.as_mut(), &host, port, &up.user, &up.password).await?;
        } else {
            http_connect(s.as_mut(), &format!("{host}:{port}"), &up.user, &up.password).await?;
        }
        let mut t = tls(s, &host).await?;
        let req = format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: controlclaw-firewall\r\nConnection: close\r\n\r\n"
        );
        t.write_all(req.as_bytes()).await.map_err(|e| e.to_string())?;
        read_until(t.as_mut(), response_complete, true).await
    };
    let raw = match run.await {
        Ok(r) => r,
        Err(e) => {
            return fail(if e.is_empty() {
                "the exit could not be reached"
            } else {
                &e
            });
        }
    };
    let latency_ms = started.elapsed().as_millis() as u64;
    let end = find(&raw, b"\r\n\r\n").unwrap_or(raw.len());
    let head = String::from_utf8_lossy(&raw[..end]).into_owned();
    static STATUS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^HTTP/1\.[01]\s+([0-9]{3})").expect("re"));
    let status = STATUS.captures(&head).and_then(|c| c[1].parse::<u16>().ok());
    // What the echo service answered is about the echo service: the tunnel opened.
    if !status.is_some_and(|s| (200..300).contains(&s)) {
        let said = status
            .map(|s| s.to_string())
            .unwrap_or_else(|| "nothing readable".into());
        return CheckResult {
            ok: true,
            exit_ip: None,
            exit_country: None,
            latency_ms,
            error: Some(format!(
                "the tunnel opened, but {host} answered {said}, so the address could not be read"
            )),
        };
    }
    let body = String::from_utf8_lossy(raw.get(end + 4..).unwrap_or_default())
        .trim()
        .to_string();
    let (ip, country) = parse_echo(&body);
    CheckResult {
        ok: true,
        exit_ip: ip,
        exit_country: country,
        latency_ms,
        error: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn echoes_and_replies() {
        assert_eq!(
            parse_echo(r#"{"ip": "203.0.113.9", "country": "de"}"#),
            (Some("203.0.113.9".into()), Some("DE".into()))
        );
        assert_eq!(parse_echo("1f\r\n2001:db8::1\r\n0"), (Some("2001:db8::1".into()), None));
        assert!(socks5_reply_complete(&[5, 0, 0, 1, 1, 2, 3, 4, 0, 80]));
        assert!(!socks5_reply_complete(&[5, 0, 0, 3, 4, b'a', b'b']));
        assert!(response_complete(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"));
        assert!(!response_complete(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nhi"));
    }

    #[tokio::test]
    async fn an_http_exit_that_refuses_the_tunnel() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.expect("accept");
            let mut buf = [0u8; 1024];
            let _ = s.read(&mut buf).await;
            let _ = s.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n").await;
        });
        let up = Upstream {
            scheme: "http".into(),
            host: "127.0.0.1".into(),
            port,
            user: "u".into(),
            password: "p".into(),
        };
        let r = check_exit(&up, Some("https://ipinfo.io/json")).await;
        assert!(!r.ok);
        assert_eq!(
            r.error.as_deref(),
            Some("the exit refused the tunnel: HTTP/1.1 407 Proxy Authentication Required")
        );
    }
}
