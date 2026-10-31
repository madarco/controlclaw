//! `mitm-ca.test.ts` and `https-ready.test.ts`: the CA trusted in process (only the current one),
//! a CA installed only when the pinned key signed it, and the own-certificate check.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use cc_proc::ok;
use ed25519_dalek::Signer;
use serde_json::json;

use super::*;
use crate::boxside::testing::test_box;

/// A throwaway CA and a leaf for localhost it signed, as the firewall's re-signing looks.
fn make_ca(dir: &Path, name: &str) -> Option<(PathBuf, String, String)> {
    let run = |args: &[&str]| {
        std::process::Command::new("openssl")
            .args(args)
            .current_dir(dir)
            .output()
            .ok()
            .filter(|o| o.status.success())
    };
    let ec = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes"];
    let (cak, cac) = (format!("{name}-ca.key"), format!("{name}-ca.crt"));
    let subj = format!("/CN={name} CA");
    let mut a: Vec<&str> = vec!["req", "-x509"];
    a.extend(ec);
    a.extend(["-keyout", &cak, "-out", &cac, "-days", "1", "-subj", &subj]);
    run(&a)?;
    let (k, csr, crt, ext) = (
        format!("{name}.key"),
        format!("{name}.csr"),
        format!("{name}.crt"),
        format!("{name}.ext"),
    );
    let mut a: Vec<&str> = vec!["req"];
    a.extend(ec);
    a.extend(["-keyout", &k, "-out", &csr, "-subj", "/CN=localhost"]);
    run(&a)?;
    std::fs::write(dir.join(&ext), "subjectAltName=DNS:localhost\n").ok()?;
    run(&[
        "x509",
        "-req",
        "-in",
        &csr,
        "-CA",
        &cac,
        "-CAkey",
        &cak,
        "-CAcreateserial",
        "-out",
        &crt,
        "-days",
        "1",
        "-extfile",
        &ext,
    ])?;
    Some((
        dir.join(&cac),
        std::fs::read_to_string(dir.join(&crt)).ok()?,
        std::fs::read_to_string(dir.join(&k)).ok()?,
    ))
}

async fn serve_tls(cert: &str, key: &str) -> u16 {
    let acceptor = cc_http::tls_acceptor(cert, key).expect("acceptor");
    let mut r = cc_http::Router::new(&["all"]);
    r.prefix("all", "/", |_, _| async {
        cc_http::full(http::StatusCode::OK, "text/plain", "ok")
    });
    let r = Arc::new(r);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    tokio::spawn(cc_http::serve_mux(listener, r.clone(), r, acceptor));
    port
}

/// A CONNECT proxy that answers 200 and joins every tunnel to 127.0.0.1:`target`.
async fn connect_proxy(target: u16) -> u16 {
    use tokio::io::AsyncReadExt;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    tokio::spawn(async move {
        while let Ok((mut c, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut b = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if c.read_exact(&mut b).await.is_err() {
                        return;
                    }
                    head.push(b[0]);
                }
                let Ok(mut up) = tokio::net::TcpStream::connect(("127.0.0.1", target)).await else {
                    return;
                };
                if tokio::io::AsyncWriteExt::write_all(&mut c, b"HTTP/1.1 200 Connection established\r\n\r\n")
                    .await
                    .is_ok()
                {
                    let _ = tokio::io::copy_bidirectional(&mut c, &mut up).await;
                }
            });
        }
    });
    port
}

#[tokio::test]
async fn the_process_trusts_the_firewall_ca_once_it_is_on_disk_and_only_the_current_one() {
    let dir = tempfile::tempdir().expect("dir");
    let (Some(first), Some(second)) = (make_ca(dir.path(), "first"), make_ca(dir.path(), "second")) else {
        return; // no openssl here
    };
    let (a, b) = (
        serve_tls(&first.1, &first.2).await,
        serve_tls(&second.1, &second.2).await,
    );
    let tb = test_box();
    let installed = dir.path().join("controlclaw-mitm.crt");
    let steps = BoxSteps::new(&tb.app, None).for_test(installed.clone(), Duration::from_millis(1));
    let get = |port: u16| tb.app.http.get().get(format!("https://localhost:{port}/")).send();
    assert!(get(a).await.is_err(), "not trusted before");
    assert!(!steps.trust_in_process(), "no CA installed yet is not an error");
    std::fs::copy(&first.0, &installed).expect("copy");
    assert!(steps.trust_in_process());
    assert_eq!(get(a).await.expect("a").text().await.expect("body"), "ok");
    // A firewall restore: the new CA is trusted and the old one is not kept beside it.
    std::fs::copy(&second.0, &installed).expect("copy");
    assert!(steps.trust_in_process());
    assert!(get(b).await.is_ok());
    assert!(get(a).await.is_err());
    // The own-certificate check sees the same chain.
    let tls = own_certificate_tls(&installed).expect("tls");
    assert!(own_certificate_serves("localhost", &tls, b).await);
    assert!(!own_certificate_serves("localhost", &tls, a).await);
    // An empty CA file is no CA: what was trusted stays.
    std::fs::write(&installed, "").expect("w");
    assert!(!steps.trust_in_process());
    assert!(get(b).await.is_ok());
    // The watchdog's probes trust what the process trusts: the firewall inspects the box's traffic,
    // so with the public roots alone the way out would show as down.
    let trusted = tb.app.http.extra_roots_pem();
    let probe = |port: u16, trusted: Vec<u8>| async move {
        crate::platform::watchdog::tls_reachable("localhost", "127.0.0.1", port, &trusted, Duration::from_secs(5)).await
    };
    assert!(probe(b, trusted.clone()).await);
    assert!(!probe(a, trusted).await);
    assert!(!probe(b, Vec::new()).await, "public roots alone");
    let proxy = connect_proxy(b).await;
    let tunnel = |trusted: Vec<u8>| async move {
        crate::platform::watchdog::proxy_tunnel_reachable(
            "127.0.0.1",
            proxy,
            "localhost",
            "127.0.0.1",
            &trusted,
            Duration::from_secs(5),
        )
        .await
    };
    assert!(tunnel(tb.app.http.extra_roots_pem()).await);
    assert!(!tunnel(Vec::new()).await);
}

#[tokio::test]
async fn a_ca_is_installed_only_when_the_pinned_key_signed_it() {
    let console = cc_testkit::FakeConsole::start().await.expect("console");
    let tb = test_box();
    let keys = &tb.app.config.keys_dir;
    std::fs::write(keys.join("mitm_box_private_ip"), "10.0.0.2").expect("w");
    std::fs::write(keys.join("config_api_url"), console.url("/api/vm-agent/config")).expect("w");
    let ca = "-----BEGIN CERTIFICATE-----\nMIIfake\n-----END CERTIFICATE-----";
    let sk = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
    let sig = base64::engine::general_purpose::STANDARD.encode(sk.sign(ca.as_bytes()).to_bytes());
    console.answer(
        "/api/vm-agent/config",
        vec![(200, json!({"mitm": {"caCert": ca, "caSig": sig}}))],
    );
    tb.runner.answer(&["sudo", "/usr/local/bin/cc-install-ca"], ok(""));
    let steps = BoxSteps::new(&tb.app, None).for_test(tb.dir.path().join("none.crt"), Duration::from_millis(1));
    let r = steps.ensure_ca(1).await;
    assert!(r.trusted && r.installed, "{r:?}");
    assert_eq!(std::fs::read_to_string(keys.join("mitm-ca.crt")).expect("ca"), ca);
    assert_eq!(
        std::fs::read_to_string(keys.join("mitm_ca_fingerprint")).expect("fpr"),
        sha256_hex(ca)
    );
    assert!(
        tb.runner
            .calls()
            .iter()
            .any(|c| c.args == ["/usr/local/bin/cc-install-ca"])
    );
    // The same CA again changes nothing.
    console.answer(
        "/api/vm-agent/config",
        vec![(200, json!({"mitm": {"caCert": ca, "caSig": sig}}))],
    );
    assert_eq!(steps.ensure_ca(1).await.message, "Already up to date.");
    // One the pinned key did not sign is refused.
    let other = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    let bad = base64::engine::general_purpose::STANDARD.encode(other.sign(b"forged").to_bytes());
    console.answer(
        "/api/vm-agent/config",
        vec![(200, json!({"mitm": {"caCert": "forged", "caSig": bad}}))],
    );
    let r = steps.ensure_ca(1).await;
    assert!(!r.trusted);
    assert_eq!(
        r.message,
        "The certificate on offer is not signed by this box's pinned firewall key, so it was refused."
    );
    assert_eq!(
        std::fs::read_to_string(keys.join("mitm-ca.crt")).expect("ca"),
        ca,
        "not replaced"
    );
}

#[tokio::test]
async fn a_box_with_no_firewall_has_nothing_to_install_or_enable() {
    let tb = test_box();
    let steps = BoxSteps::new(&tb.app, None);
    let r = steps.ensure_ca(1).await;
    assert!(r.trusted && !r.installed);
    assert!(steps.enable_egress().await);
    assert!(tb.runner.calls().is_empty());
}

#[tokio::test]
async fn waiting_for_the_certificate_stops_when_it_is_served_or_the_time_is_up() {
    let n = std::sync::atomic::AtomicUsize::new(0);
    let probe = || {
        let i = n.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        async move { i >= 1 }
    };
    assert!(wait_for_own_certificate(probe, Duration::from_secs(30)).await);
    assert!(!wait_for_own_certificate(|| async { false }, Duration::from_secs(3)).await);
}

#[test]
fn detached_signatures() {
    let sk = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]);
    let pem = cc_testkit::Pair::from_seed(5).public_pem;
    let sig = base64::engine::general_purpose::STANDARD.encode(sk.sign(b"hello").to_bytes());
    assert!(verify_detached("hello", &sig, &pem));
    assert!(!verify_detached("hellO", &sig, &pem));
    assert!(!verify_detached("hello", "not base64!", &pem));
    assert!(!verify_detached("hello", &sig, "garbage"));
}

#[tokio::test]
async fn a_first_sight_pin_that_cannot_be_saved_installs_nothing() {
    let console = cc_testkit::FakeConsole::start().await.expect("console");
    let tb = test_box();
    let keys = &tb.app.config.keys_dir;
    std::fs::write(keys.join("mitm_box_private_ip"), "10.0.0.2").expect("w");
    std::fs::write(keys.join("config_api_url"), console.url("/api/vm-agent/config")).expect("w");
    // No pin, and a folder where it would be written, so the write fails.
    std::fs::remove_file(keys.join("mitm_pinned_pubkey.pem")).expect("rm");
    std::fs::create_dir(keys.join("mitm_pinned_pubkey.pem")).expect("dir");
    let ca = "-----BEGIN CERTIFICATE-----\nMIIfake\n-----END CERTIFICATE-----";
    let sk = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
    let sig = base64::engine::general_purpose::STANDARD.encode(sk.sign(ca.as_bytes()).to_bytes());
    let pk = cc_testkit::Pair::from_seed(3).public_pem;
    console.answer(
        "/api/vm-agent/config",
        vec![(200, json!({"mitm": {"caCert": ca, "caSig": sig, "pubKey": pk}}))],
    );
    let steps = BoxSteps::new(&tb.app, None).for_test(tb.dir.path().join("none.crt"), Duration::from_millis(1));
    let r = steps.ensure_ca(1).await;
    assert!(!r.trusted && !r.installed, "{r:?}");
    assert!(tb.runner.calls().is_empty(), "cc-install-ca never ran");
    assert!(!keys.join("mitm-ca.crt").exists());
}

/// `firewallCa` (main #564): `GET /ca` on the firewall's gate, with the installed CA's sha256 when
/// the box announces itself; the pair, or None for anything but a 200 with both strings.
#[tokio::test]
async fn the_firewall_is_asked_for_its_ca() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = l.local_addr().expect("addr").port();
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let s = seen.clone();
    tokio::spawn(async move {
        for answer in [
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 26\r\n\r\n{\"caCert\":\"C\",\"caSig\":\"S\"}",
            "HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n",
        ] {
            let Ok((mut c, _)) = l.accept().await else { return };
            let mut buf = vec![0u8; 2048];
            let n = c.read(&mut buf).await.unwrap_or(0);
            s.lock().expect("lock").push(
                String::from_utf8_lossy(&buf[..n])
                    .lines()
                    .next()
                    .unwrap_or("")
                    .to_owned(),
            );
            let _ = c.write_all(answer.as_bytes()).await;
        }
    });
    let fpr = "ab".repeat(32);
    assert_eq!(
        super::firewall_ca_at("127.0.0.1", port, Some(&fpr)).await,
        Some(("C".into(), "S".into()))
    );
    assert_eq!(super::firewall_ca_at("127.0.0.1", port, None).await, None);
    let seen = seen.lock().expect("lock").clone();
    assert_eq!(seen[0], format!("GET /ca?installed={fpr} HTTP/1.1"));
    assert_eq!(seen[1], "GET /ca HTTP/1.1");
}
