//! The proxy as a running binary: CONNECT, a real TLS handshake through it, the drop record, and
//! the dev-flag refusal. Black-box, so the same cases can later run against mitmproxy too.
//!
//! The upstream listens on this machine's own non-loopback address: the proxy refuses loopback
//! targets (addon.py `check_target`), which is the point of the check, so a 127.0.0.1 echo server
//! could never be reached through it.

use std::io::BufRead;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

type Res = Result<(), Box<dyn std::error::Error + Send + Sync>>;

const CONTROL_PLANE: &str = "cp.controlclaw.test";
const BACKUP: &str = "backup.controlclaw.test";

/// Kills the proxy when the test ends, pass or fail.
struct Proxy {
    child: Child,
    addr: SocketAddr,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start_proxy(dir: &Path, extra_env: &[(&str, &str)]) -> Result<Proxy, Box<dyn std::error::Error + Send + Sync>> {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_cc-proxy"));
    cmd.args(["--listen", "127.0.0.1:0"])
        .env_clear()
        .env("MITM_CONTROL_PLANE_HOST", CONTROL_PLANE)
        .env("MITM_BACKUP_HOST", BACKUP)
        .env("MITM_TENANT", "org_test")
        .env("MITM_LOG_FILE", dir.join("traffic.jsonl"))
        .env("MITM_IDENTITIES_PATH", dir.join("identities.json"))
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn()?;
    let mut line = String::new();
    let stdout = child.stdout.take().ok_or("no stdout")?;
    std::io::BufReader::new(stdout).read_line(&mut line)?;
    let addr = line
        .trim()
        .strip_prefix("listening on ")
        .ok_or_else(|| format!("unexpected: {line}"))?
        .parse()?;
    Ok(Proxy { child, addr })
}

/// This machine's outward address, without sending anything (a UDP connect only picks a route).
fn own_ip() -> Option<IpAddr> {
    let s = UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("192.0.2.1:9").ok()?;
    Some(s.local_addr().ok()?.ip()).filter(|ip| !ip.is_loopback())
}

/// A TLS echo server for `names`, on `ip`. Returns its address and its certificate.
async fn echo_server(
    ip: IpAddr,
    names: &[&str],
) -> Result<(SocketAddr, CertificateDer<'static>), Box<dyn std::error::Error + Send + Sync>> {
    echo_server_tagged(ip, names, b"").await
}

/// The same, answering every read with `tag` in front of the echo, so a test can tell servers apart.
async fn echo_server_tagged(
    ip: IpAddr,
    names: &[&str],
    tag: &'static [u8],
) -> Result<(SocketAddr, CertificateDer<'static>), Box<dyn std::error::Error + Send + Sync>> {
    let cert = rcgen::generate_simple_self_signed(names.iter().map(|n| (*n).to_owned()).collect::<Vec<_>>())?;
    let der = CertificateDer::from(cert.cert.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![der.clone()], key)?;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind((ip, 0)).await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        while let Ok((s, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(s).await else { return };
                let mut buf = [0u8; 1024];
                while let Ok(n) = tls.read(&mut buf).await {
                    if n == 0 || tls.write_all(&[tag, &buf[..n]].concat()).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    Ok((addr, der))
}

/// CONNECT through the proxy and expect the 200.
async fn connect_via(
    proxy: SocketAddr,
    target: SocketAddr,
) -> Result<TcpStream, Box<dyn std::error::Error + Send + Sync>> {
    let mut s = TcpStream::connect(proxy).await?;
    s.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .await?;
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        let mut b = [0u8; 1];
        if s.read(&mut b).await? == 0 {
            return Err("closed during CONNECT".into());
        }
        head.push(b[0]);
    }
    assert!(head.starts_with(b"HTTP/1.1 200"), "{}", String::from_utf8_lossy(&head));
    Ok(s)
}

fn tls_client(
    cert: CertificateDer<'static>,
) -> Result<tokio_rustls::TlsConnector, Box<dyn std::error::Error + Send + Sync>> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert)?;
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(tokio_rustls::TlsConnector::from(Arc::new(config)))
}

fn records(dir: &Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(dir.join("traffic.jsonl"))
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

async fn wait_for_record(dir: &Path) -> Vec<serde_json::Value> {
    for _ in 0..50 {
        let r = records(dir);
        if !r.is_empty() {
            return r;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Vec::new()
}

// The control plane is intercepted, not passed through (owner, 2026-10-28): the client's own
// handshake never reaches the server. Its interception is covered in rust/conformance/proxy/w1.
#[tokio::test]
async fn the_control_plane_is_not_passed_through() -> Res {
    let Some(ip) = own_ip() else {
        eprintln!("skipped: this machine has no non-loopback address");
        return Ok(());
    };
    let dir = tempfile::tempdir()?;
    let (echo, cert) = echo_server(ip, &[CONTROL_PLANE]).await?;
    let map = format!("{CONTROL_PLANE}={echo}");
    let proxy = start_proxy(dir.path(), &[("MITM_DEV_RESOLVE", &map), ("MITM_ALLOW_DEV_FLAGS", "1")])?;
    let s = connect_via(proxy.addr, echo).await?;
    let r = tls_client(cert)?.connect(ServerName::try_from(CONTROL_PLANE)?, s).await;
    assert!(r.is_err(), "the server's own certificate must not reach the client");
    Ok(())
}

#[tokio::test]
async fn any_other_name_is_closed_with_a_drop_record() -> Res {
    let Some(ip) = own_ip() else {
        eprintln!("skipped: this machine has no non-loopback address");
        return Ok(());
    };
    let dir = tempfile::tempdir()?;
    let proxy = start_proxy(dir.path(), &[])?;
    let (echo, cert) = echo_server(ip, &["other.test"]).await?;

    let s = connect_via(proxy.addr, echo).await?;
    let r = tls_client(cert)?.connect(ServerName::try_from("other.test")?, s).await;
    assert!(r.is_err(), "the handshake must not reach the server");
    let recs = wait_for_record(dir.path()).await;
    assert_eq!(recs.len(), 1, "{recs:?}");
    let rec = &recs[0];
    assert_eq!(rec["effect"], "drop");
    assert_eq!(rec["host"], "other.test");
    assert_eq!(rec["port"], echo.port());
    assert_eq!(rec["tenant"], "org_test");
    assert!(
        rec["rule_id"].is_null() && rec.get("rule_id").is_some(),
        "rule_id is always on a record with an effect"
    );
    assert!(rec["vm_id"].is_null());
    assert!(rec["flow_id"].as_str().is_some_and(|id| id.len() == 36));
    Ok(())
}

#[test]
fn dev_flags_stop_the_proxy_from_starting() -> Res {
    let out = Command::new(env!("CARGO_BIN_EXE_cc-proxy"))
        .args(["--listen", "127.0.0.1:0"])
        .env_clear()
        .env("MITM_DEV_ALLOW_DIRECT_EGRESS", "1")
        .output()?;
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("refusing to start with dev flags"));
    Ok(())
}
