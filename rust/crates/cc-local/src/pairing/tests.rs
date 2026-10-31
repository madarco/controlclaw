//! Pairing: the code's form, the proof and the mac, single use, expiry, the waiting cap, the
//! throttle, addresses (the request's source, or the admin's on the code), replacing an agent,
//! refusals after a match, and the endpoint over HTTP.

use ed25519_dalek::SigningKey;
use ed25519_dalek::pkcs8::EncodePublicKey;
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;

use sha2::Digest;

use super::*;
use crate::plane::{Call, ControlPlane, LocalControlPlane};

fn agent_key() -> String {
    SigningKey::generate(&mut rand::rngs::OsRng)
        .verifying_key()
        .to_public_key_pem(LineEnding::LF)
        .expect("pem")
}

fn info() -> InfoHook {
    Arc::new(|| {
        Ok(FirewallInfo {
            public_key: "FW-KEY".into(),
            ca_pem: "CA".into(),
            proxy: Some("10.0.0.2:8080".into()),
            dns: None,
            wg: None,
        })
    })
}

fn service() -> (Arc<Db>, Arc<PairService>) {
    let db = Arc::new(Db::memory().expect("db"));
    LocalControlPlane::new(db.clone()).register_self("fw").expect("self");
    let s = PairService::new(db.clone(), info());
    (db, s)
}

fn code(db: &Db) -> NewCode {
    create_code(db, &CodeFor::default()).expect("code")
}

fn request(code: &str, req: &PairRequest) -> (Value, String) {
    let text = serde_json::to_string(req).expect("json");
    let key = normalize(code).expect("code");
    (
        json!({"request": text, "proof": hmac_hex(&key, REQUEST_TAG, &text)}),
        key,
    )
}

/// A request from the machine at [`IP`], which says so.
fn req(nonce: &str) -> PairRequest {
    PairRequest {
        v: 1,
        nonce: nonce.repeat(64 / nonce.len()),
        agent_public_key: agent_key(),
        name: None,
        source: Some("203.0.113.7".into()),
        unpair_sha256: None,
        wg_public_key: None,
        agent_listen: None,
    }
}

/// The status a pairing answered with.
fn status(r: Result<Value, Refusal>) -> u16 {
    match r {
        Ok(_) => 200,
        Err(Refusal(s, _)) => s,
    }
}

fn pairing_of(v: &Value) -> Pairing {
    serde_json::from_str(v["pairing"].as_str().expect("pairing")).expect("pairing json")
}

fn pending(db: &Db) -> usize {
    list_pending(db).expect("list").len()
}

const IP: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));

#[test]
fn codes_read_as_crockford_base32() {
    let c = new_code();
    assert_eq!(c.len(), 14);
    assert_eq!(c.matches('-').count(), 2);
    assert!(normalize(&c).is_some());
    // Lower case, O for 0 and I or L for 1, spaces: all the same code.
    assert_eq!(normalize("4f7k 92qd-xm3p"), Some("4F7K92QDXM3P".into()));
    assert_eq!(normalize("O1IL-0000-0000"), Some("011100000000".into()));
    assert_eq!(normalize("4F7K-92QD"), None);
    assert_eq!(normalize("4F7K-92QD-XM3U"), None, "U is not in the alphabet");
    // The same vector as the CLI's pair.test.ts: both sides make the same HMAC.
    assert_eq!(
        hmac_hex("4F7K92QDXM3P", REQUEST_TAG, r#"{"v":1}"#),
        "cf7e753a7cd09e5ab89e472d13b8b09f9c99223d603ea1a54dca87f2b4d900a2"
    );
}

#[test]
fn pairs_once_and_records_the_agent() {
    let (db, s) = service();
    let c = create_code(
        &db,
        &CodeFor {
            name: Some("laptop"),
            ..Default::default()
        },
    )
    .expect("code");
    let mut r = req("ab");
    r.name = Some("hostname-of-the-machine".into());
    let (body, key) = request(&c.code, &r);
    let out = s.pair(&body, IP).expect("paired");
    let text = out["pairing"].as_str().expect("pairing");
    assert_eq!(
        out["mac"],
        hmac_hex(&key, RESPONSE_TAG, text),
        "the mac covers the exact text"
    );
    let p = pairing_of(&out);
    assert_eq!(p.nonce, r.nonce);
    assert_eq!(p.name, "laptop", "the admin's name for the code wins");
    assert_eq!(p.address, "203.0.113.7", "the source address");
    assert_eq!(p.firewall_public_key, "FW-KEY");
    assert_eq!(p.proxy.as_deref(), Some("10.0.0.2:8080"));
    assert!(p.agent_id.starts_with("agent_"));

    let row: (String, String, String, Option<i64>) = db
        .lock()
        .query_row(
            "SELECT role, private_ip, public_key, paired_at FROM agents WHERE vm_id = ?1",
            [&p.agent_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .expect("row");
    assert_eq!(row.0, "openclaw");
    assert_eq!(row.1, "203.0.113.7");
    assert_eq!(row.2, r.agent_public_key.trim());
    assert!(row.3.is_some());

    // Spent: the same request again is refused.
    assert_eq!(status(s.pair(&body, IP)), 401);
    assert_eq!(pending(&db), 0);
}

#[tokio::test]
async fn the_address_the_admin_set_on_the_code_is_the_agents() {
    let (db, s) = service();
    let c = create_code(
        &db,
        &CodeFor {
            address: Some("172.31.251.10"),
            ..Default::default()
        },
    )
    .expect("code");
    // From a published port on the firewall's machine: loopback, whatever the machine says.
    let lo: IpAddr = "127.0.0.1".parse().expect("ip");
    let r = req("cd");
    let p = pairing_of(&s.pair(&request(&c.code, &r).0, lo).expect("paired"));
    assert_eq!(p.address, "172.31.251.10");
    let plane = LocalControlPlane::new(db.clone());
    let a = plane
        .call(
            "fw",
            Call {
                method: "GET".into(),
                path: "/api/vm-agent/identities".into(),
                query: String::new(),
                body: None,
            },
        )
        .await;
    let ids = a.body["identities"].as_array().expect("list");
    assert_eq!(ids.len(), 1);
    assert_eq!(ids[0]["vm_id"], p.agent_id.as_str());
    assert_eq!(ids[0]["private_ip"], "172.31.251.10");
    assert_eq!(
        ids[0]["agent_addr"],
        Value::Null,
        "not said: no call goes to it in clear"
    );
}

/// Where the vm-agent listens: this machine's own address (the request's source), or a private
/// address when the code names the agent's (`up --local`: OpenClaw in a container, its vm-agent on
/// the host). Never over the tunnel, never link-local; a bad one refused before any code is tried.
#[tokio::test]
async fn the_agent_says_where_its_vm_agent_listens() {
    let (db, s) = service();
    let c = code(&db);
    for bad in [
        "203.0.113.7",
        "0.0.0.0:3100",
        "203.0.113.7:0",
        "[::1]:3100",
        "host:3100",
        "127.0.0.1:8800",
        "169.254.169.254:80",
    ] {
        let mut r = req("cf");
        r.agent_listen = Some(bad.into());
        assert_eq!(status(s.pair(&request(&c.code, &r).0, IP)), 400, "{bad}");
    }
    assert_eq!(pending(&db), 1, "nothing spent");
    // Not its own address: refused (and the code is spent, as any refusal after a match).
    let mut r = req("cf");
    r.agent_listen = Some("10.0.0.9:3100".into());
    assert_eq!(status(s.pair(&request(&c.code, &r).0, IP)), 409);
    let c = code(&db);
    let mut r = req("cf");
    r.agent_listen = Some("203.0.113.7:3100".into());
    pairing_of(&s.pair(&request(&c.code, &r).0, IP).expect("paired"));
    // The code names the agent's address: a private one on its machine.
    let named = |db: &Db| {
        create_code(
            db,
            &CodeFor {
                address: Some("172.31.251.10"),
                replace: true,
                ..Default::default()
            },
        )
        .expect("code")
    };
    let lo: IpAddr = "127.0.0.1".parse().expect("ip");
    let mut r = req("ce");
    r.agent_listen = Some("100.64.0.5:3100".into());
    let got = s.pair(&request(&named(&db).code, &r).0, lo);
    assert!(
        matches!(got, Err(Refusal(409, _))),
        "public: {:?}",
        got.err().map(|Refusal(s, m)| (s, m))
    );
    r.agent_listen = Some("172.31.252.1:3100".into());
    pairing_of(&s.pair(&request(&named(&db).code, &r).0, lo).expect("paired"));
    let a = LocalControlPlane::new(db.clone())
        .call(
            "fw",
            Call {
                method: "GET".into(),
                path: "/api/vm-agent/identities".into(),
                query: String::new(),
                body: None,
            },
        )
        .await;
    let mut addrs: Vec<String> = a.body["identities"]
        .as_array()
        .expect("list")
        .iter()
        .map(|i| i["agent_addr"].to_string())
        .collect();
    addrs.sort();
    assert_eq!(addrs, [r#""172.31.252.1:3100""#, r#""203.0.113.7:3100""#]);
}

#[test]
fn the_agent_cannot_choose_its_address() {
    let (db, s) = service();
    let c = code(&db);
    // An old-style `address` in the request is not read: the source is what counts.
    let mut r = serde_json::to_value(req("ce")).expect("v");
    r["address"] = json!("10.9.9.9");
    let text = r.to_string();
    let key = normalize(&c.code).expect("key");
    let body = json!({"request": text, "proof": hmac_hex(&key, REQUEST_TAG, &text)});
    assert_eq!(pairing_of(&s.pair(&body, IP).expect("paired")).address, "203.0.113.7");
}

#[test]
fn a_request_replayed_from_another_address_is_refused_and_spends_the_code() {
    let (db, s) = service();
    let c = code(&db);
    // The machine says 203.0.113.7; the request arrives from somewhere else (on-path replay, or a
    // NAT the admin did not name).
    let elsewhere: IpAddr = "198.51.100.66".parse().expect("ip");
    let r = s.pair(&request(&c.code, &req("cf")).0, elsewhere).expect_err("refused");
    assert_eq!(r.0, 409);
    assert!(r.1.contains("pair-code --address"), "{}", r.1);
    assert_eq!(pending(&db), 0, "a refusal after a match spends the code");
    // With no source at all (an older CLI): refused before any code is tried, so it is kept.
    let c = code(&db);
    let mut r = req("d0");
    r.source = None;
    let e = s.pair(&request(&c.code, &r).0, IP).expect_err("refused");
    assert_eq!(e.0, 400);
    assert!(e.1.contains("update controlclaw"), "{}", e.1);
    assert_eq!(pending(&db), 1);
}

#[test]
fn an_agent_already_there_is_replaced_only_when_the_code_says_so() {
    let (db, s) = service();
    let first = pairing_of(&s.pair(&request(&code(&db).code, &req("10")).0, IP).expect("paired"));
    // A second machine (or OpenClaw itself, with a stolen code) at the same address: refused.
    let r = s
        .pair(&request(&code(&db).code, &req("20")).0, IP)
        .expect_err("refused");
    assert_eq!(r.0, 409);
    assert!(r.1.contains(&first.agent_id) && r.1.contains("--replace"), "{}", r.1);
    assert_eq!(pending(&db), 0, "spent");
    // The admin allows it.
    let c = create_code(
        &db,
        &CodeFor {
            replace: true,
            ..Default::default()
        },
    )
    .expect("code");
    let second = pairing_of(&s.pair(&request(&c.code, &req("30")).0, IP).expect("paired"));
    assert_eq!(second.replaced, vec![first.agent_id.clone()]);
    let n: i64 = db
        .lock()
        .query_row(
            "SELECT COUNT(*) FROM agents WHERE private_ip = '203.0.113.7'",
            [],
            |r| r.get(0),
        )
        .expect("count");
    assert_eq!(n, 1);
}

#[test]
fn a_wrong_proof_or_a_changed_request_is_refused() {
    let (db, s) = service();
    let c = code(&db);
    // Another code's proof.
    let (body, _) = request("AAAA-BBBB-CCCC", &req("01"));
    assert_eq!(status(s.pair(&body, IP)), 401);
    // The right proof, then the request changed on the way (another key).
    let (mut body, _) = request(&c.code, &req("02"));
    let mut changed: PairRequest = serde_json::from_str(body["request"].as_str().expect("s")).expect("r");
    changed.agent_public_key = agent_key();
    body["request"] = json!(serde_json::to_string(&changed).expect("json"));
    assert_eq!(status(s.pair(&body, IP)), 401);
    // The code is still there for the real agent.
    assert_eq!(pending(&db), 1);
}

#[test]
fn an_expired_code_does_not_pair() {
    let (db, s) = service();
    let c = create_code(
        &db,
        &CodeFor {
            ttl_min: Some(1),
            ..Default::default()
        },
    )
    .expect("code");
    db.lock()
        .execute("UPDATE pairing_codes SET expires_at = ?1", [now_s() - 1])
        .expect("expire");
    assert_eq!(status(s.pair(&request(&c.code, &req("03")).0, IP)), 401);
}

#[test]
fn bad_requests_say_why_and_spend_nothing() {
    let (db, s) = service();
    let c = code(&db);
    let mut r = req("04");
    r.agent_public_key = "not a key".into();
    assert_eq!(status(s.pair(&request(&c.code, &r).0, IP)), 400);
    let mut r = req("05");
    r.source = Some("::1".into());
    assert_eq!(status(s.pair(&request(&c.code, &r).0, IP)), 400);
    let mut r = req("06");
    r.nonce = "short".into();
    assert_eq!(status(s.pair(&request(&c.code, &r).0, IP)), 400);
    assert_eq!(status(s.pair(&json!({}), IP)), 400);
    assert_eq!(pending(&db), 1);
}

#[test]
fn ten_failures_from_one_address_then_429() {
    let (db, s) = service();
    let c = code(&db);
    for i in 0..10 {
        let (body, _) = request("AAAA-BBBB-CCCC", &req(&format!("{i:02}")));
        assert_eq!(status(s.pair(&body, IP)), 401);
    }
    // Even the right code waits now, from that address.
    assert_eq!(status(s.pair(&request(&c.code, &req("aa")).0, IP)), 429);
    // Another address is not held up by it.
    let other: IpAddr = "198.51.100.1".parse().expect("ip");
    let mut r = req("bb");
    r.source = Some("198.51.100.1".into());
    assert!(s.pair(&request(&c.code, &r).0, other).is_ok());
}

#[test]
fn no_cap_over_all_addresses_and_bad_requests_do_not_count() {
    let (db, s) = service();
    for i in 0..40u8 {
        let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, i));
        assert_eq!(status(s.pair(&request("AAAA-BBBB-CCCC", &req("0f")).0, ip)), 401);
    }
    for _ in 0..12 {
        assert_eq!(status(s.pair(&json!({}), IP)), 400);
    }
    assert!(s.pair(&request(&code(&db).code, &req("aa")).0, IP).is_ok());
}

#[test]
fn a_refusal_after_a_match_counts_like_a_wrong_code() {
    let (db, s) = service();
    // The firewall's own address: refused for any code, and a match is spent and counted, so it
    // confirms nothing for free.
    db.lock()
        .execute("UPDATE agents SET private_ip = '203.0.113.7' WHERE role = 'mitm'", [])
        .expect("own ip");
    for i in 0..10 {
        let r = s.pair(&request(&code(&db).code, &req(&format!("{i:02}"))).0, IP);
        assert_eq!(status(r), 409);
    }
    assert_eq!(status(s.pair(&request(&code(&db).code, &req("aa")).0, IP)), 429);
}

#[test]
fn addresses_the_proxy_never_sees_an_agent_at_are_refused() {
    let (db, s) = service();
    for a in ["127.0.0.1", "0.0.0.0", "224.0.0.1", "255.255.255.255", "not-an-ip"] {
        let f = CodeFor {
            address: Some(a),
            ..Default::default()
        };
        assert!(create_code(&db, &f).is_err(), "{a}");
    }
    db.lock()
        .execute("UPDATE agents SET private_ip = '10.0.0.2' WHERE role = 'mitm'", [])
        .expect("own ip");
    let own = CodeFor {
        address: Some("10.0.0.2"),
        ..Default::default()
    };
    assert!(create_code(&db, &own).is_err(), "the firewall's own address");
    // From loopback with a code that names no address: refused.
    let lo: IpAddr = "127.0.0.1".parse().expect("ip");
    let mut r = req("0d");
    r.source = Some("127.0.0.1".into());
    assert_eq!(status(s.pair(&request(&code(&db).code, &r).0, lo)), 409);
    let v6: IpAddr = "2001:db8::1".parse().expect("ip");
    assert_eq!(status(s.pair(&request(&code(&db).code, &req("0e")).0, v6)), 409);
}

#[test]
fn codes_are_capped_and_bounded() {
    let (db, _) = service();
    let f = |ttl, name| CodeFor {
        ttl_min: ttl,
        name,
        ..Default::default()
    };
    assert!(create_code(&db, &f(Some(0), None)).is_err());
    assert!(create_code(&db, &f(Some(TTL_MAX_MIN + 1), None)).is_err());
    assert!(create_code(&db, &f(None, Some("a\u{7}b"))).is_err());
    for _ in 0..PENDING_MAX {
        code(&db);
    }
    assert!(
        create_code(&db, &CodeFor::default()).is_err(),
        "at most {PENDING_MAX} wait"
    );
    // An expired one makes room.
    db.lock()
        .execute("UPDATE pairing_codes SET expires_at = ?1 WHERE id = 1", [now_s() - 1])
        .expect("expire");
    assert!(create_code(&db, &CodeFor::default()).is_ok());
}

#[test]
fn codes_are_listed_without_the_code_and_revoked() {
    let (db, _) = service();
    let made = create_code(
        &db,
        &CodeFor {
            name: Some("pi"),
            ttl_min: Some(5),
            address: Some("10.0.0.9"),
            replace: true,
        },
    )
    .expect("code");
    let list = list_pending(&db).expect("list");
    assert_eq!(list.len(), 1);
    let shown = serde_json::to_value(&list[0]).expect("json");
    assert!(shown.get("code").is_none(), "the list never shows a code");
    assert_eq!(shown["address"], "10.0.0.9");
    assert_eq!(shown["replace"], true);
    assert!(revoke(&db, made.id).expect("revoke"));
    assert!(!revoke(&db, made.id).expect("revoke again"));
}

#[tokio::test]
async fn the_endpoint_over_http() {
    let (db, s) = service();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("addr"));
    tokio::spawn(cc_http::serve(listener, Arc::new(s.router())));
    let http = reqwest::Client::new();
    // From loopback, so the code names the address the proxy will see.
    let c = create_code(
        &db,
        &CodeFor {
            address: Some("10.0.0.7"),
            ..Default::default()
        },
    )
    .expect("code");
    let (body, key) = request(&c.code, &req("ef"));
    let r = http
        .post(format!("{base}/pair"))
        .json(&body)
        .send()
        .await
        .expect("send");
    assert_eq!(r.status(), 200);
    let out: Value = r.json().await.expect("json");
    assert_eq!(
        out["mac"],
        hmac_hex(&key, RESPONSE_TAG, out["pairing"].as_str().expect("s"))
    );
    let r = http
        .post(format!("{base}/pair"))
        .json(&body)
        .send()
        .await
        .expect("send");
    assert_eq!(r.status(), 401);
    let r = http.get(format!("{base}/pair")).send().await.expect("send");
    assert_eq!(r.status(), 404);
    let r = http
        .post(format!("{base}/api/setup"))
        .json(&json!({}))
        .send()
        .await
        .expect("send");
    assert_eq!(r.status(), 404, "only /pair is served here");
}

#[test]
fn a_database_from_before_pairing_migrates() {
    let d = tempfile::tempdir().expect("dir");
    let p = d.path().join("local.db");
    {
        let c = rusqlite::Connection::open(&p).expect("open");
        c.execute_batch(&format!("{} PRAGMA user_version = 1;", crate::db::MIGRATIONS[0]))
            .expect("v1");
        c.execute(
            "INSERT INTO agents (vm_id, role, name, private_ip, created_at) VALUES ('vm_1', 'openclaw', 'old', '10.0.0.5', 1)",
            [],
        )
        .expect("old agent");
    }
    let db = Db::open(&p).expect("migrate");
    let paired: Option<i64> = db
        .lock()
        .query_row("SELECT paired_at FROM agents WHERE vm_id = 'vm_1'", [], |r| r.get(0))
        .expect("row");
    assert_eq!(paired, None, "the old agent stays, not paired");
    assert!(create_code(&db, &CodeFor::default()).is_ok());
}

#[test]
fn a_code_address_that_became_the_firewalls_own_is_refused() {
    let (db, s) = service();
    let c = create_code(
        &db,
        &CodeFor {
            address: Some("10.0.0.2"),
            ..Default::default()
        },
    )
    .expect("code");
    db.lock()
        .execute("UPDATE agents SET private_ip = '10.0.0.2' WHERE role = 'mitm'", [])
        .expect("own ip");
    assert_eq!(status(s.pair(&request(&c.code, &req("d1")).0, IP)), 409);
    assert_eq!(pending(&db), 0);
}

#[test]
fn unpair_with_the_secret_lets_the_machine_pair_again() {
    let (db, s) = service();
    let secret = "s3cret-of-the-agent";
    let mut r = req("e1");
    r.unpair_sha256 = Some(hex::encode(Sha256::digest(secret.as_bytes())));
    let p = pairing_of(&s.pair(&request(&code(&db).code, &r).0, IP).expect("paired"));
    // A wrong secret, or another agent's id: the same 404.
    let e = s
        .unpair(&json!({"agent_id": p.agent_id, "secret": "wrong"}), IP)
        .expect_err("refused");
    assert_eq!(e.0, 404);
    assert_eq!(
        status(s.unpair(&json!({"agent_id": "agent_x", "secret": secret}), IP)),
        404
    );
    assert_eq!(status(s.unpair(&json!({"agent_id": p.agent_id}), IP)), 404);
    s.unpair(&json!({"agent_id": p.agent_id, "secret": secret}), IP)
        .expect("unpaired");
    // The machine pairs again, without --replace.
    assert!(s.pair(&request(&code(&db).code, &req("e2")).0, IP).is_ok());
    // An agent paired with no secret cannot be unpaired this way.
    let other: IpAddr = "198.51.100.9".parse().expect("ip");
    let mut r = req("e3");
    r.source = Some("198.51.100.9".into());
    let p2 = pairing_of(&s.pair(&request(&code(&db).code, &r).0, other).expect("paired"));
    assert_eq!(
        status(s.unpair(&json!({"agent_id": p2.agent_id, "secret": ""}), other)),
        404
    );
}

const WG_KEY: &str = "uEjM2N4pNCQnVBJm/eEtYhXeJ8JyBQlpS9Oa8HVnHlA=";

fn service_wg() -> (Arc<Db>, Arc<PairService>) {
    let db = Arc::new(Db::memory().expect("db"));
    LocalControlPlane::new(db.clone()).register_self("fw").expect("self");
    let s = PairService::new(
        db.clone(),
        Arc::new(|| {
            Ok(FirewallInfo {
                public_key: "FW-KEY".into(),
                ca_pem: "CA".into(),
                proxy: Some("10.0.0.2:8080".into()),
                dns: Some("10.0.0.2".into()),
                wg: Some(crate::wireguard::WgInfo {
                    public_key: "FWWG".into(),
                    endpoint: "203.0.113.1:51820".into(),
                    address: "10.77.0.1".parse().expect("ip"),
                    prefix: 24,
                    proxy_port: 8080,
                }),
            })
        }),
    );
    (db, s)
}

#[test]
fn over_wireguard_the_agent_gets_a_tunnel_address_and_the_firewalls_tunnel_side() {
    let (db, s) = service_wg();
    let mut r = req("f1");
    r.wg_public_key = Some(WG_KEY.into());
    r.agent_listen = Some("10.0.0.9:3100".into());
    assert_eq!(
        status(s.pair(&request(&code(&db).code, &r).0, IP)),
        400,
        "over the tunnel, nowhere else"
    );
    r.agent_listen = None;
    // Behind a NAT: the machine says a private address, the request comes from a public one. Over
    // WireGuard that is fine: the identity is the tunnel address.
    r.source = Some("192.168.1.20".into());
    let p = pairing_of(&s.pair(&request(&code(&db).code, &r).0, IP).expect("paired"));
    assert_eq!(p.address, "10.77.0.2");
    assert_eq!(p.proxy.as_deref(), Some("10.77.0.1:8080"));
    assert_eq!(p.dns.as_deref(), Some("10.77.0.1"));
    let wg = p.wg.expect("wg");
    assert_eq!(wg.address, "10.77.0.2");
    assert_eq!(wg.firewall_address, "10.77.0.1");
    assert_eq!(wg.endpoint, "203.0.113.1:51820");
    assert_eq!(wg.firewall_public_key, "FWWG");
    // The next one gets the next address, and both are in the peers file.
    let mut r2 = req("f2");
    r2.wg_public_key = Some("aEjM2N4pNCQnVBJm/eEtYhXeJ8JyBQlpS9Oa8HVnHlA=".into());
    let p2 = pairing_of(&s.pair(&request(&code(&db).code, &r2).0, IP).expect("paired"));
    assert_eq!(p2.address, "10.77.0.3");
    let conf = crate::wireguard::peers_conf(&db.lock()).expect("conf");
    assert!(conf.contains(&format!("PublicKey = {WG_KEY}\nAllowedIPs = 10.77.0.2/32")));
    assert!(conf.contains("AllowedIPs = 10.77.0.3/32"));
}

#[test]
fn a_bad_wireguard_key_or_a_firewall_without_wireguard_is_refused() {
    let (db, s) = service_wg();
    let mut r = req("f3");
    r.wg_public_key = Some("x\n[Peer]\nAllowedIPs = 0.0.0.0/0".into());
    assert_eq!(status(s.pair(&request(&code(&db).code, &r).0, IP)), 400);
    assert_eq!(pending(&db), 1, "refused before any code is tried");
    let (db, s) = service();
    let mut r = req("f4");
    r.wg_public_key = Some(WG_KEY.into());
    let e = s.pair(&request(&code(&db).code, &r).0, IP).expect_err("refused");
    assert_eq!(e.0, 409);
    assert!(e.1.contains("runs no WireGuard"), "{}", e.1);
}

#[test]
fn a_code_for_an_address_is_not_for_a_remote_agent() {
    let (db, s) = service_wg();
    let c = create_code(
        &db,
        &CodeFor {
            address: Some("10.0.0.5"),
            ..Default::default()
        },
    )
    .expect("code");
    let mut r = req("f5");
    r.wg_public_key = Some(WG_KEY.into());
    let e = s.pair(&request(&c.code, &r).0, IP).expect_err("refused");
    assert_eq!(e.0, 409);
    assert!(e.1.contains("not for one over WireGuard"), "{}", e.1);
    assert_eq!(pending(&db), 0, "spent");
}

#[test]
fn a_wireguard_key_pairs_once() {
    let (db, s) = service_wg();
    let mut r = req("f6");
    r.wg_public_key = Some(WG_KEY.into());
    s.pair(&request(&code(&db).code, &r).0, IP).expect("paired");
    let mut again = req("f7");
    again.wg_public_key = Some(WG_KEY.into());
    let e = s.pair(&request(&code(&db).code, &again).0, IP).expect_err("refused");
    assert_eq!(e.0, 409);
    assert!(e.1.contains("belongs to an agent already"), "{}", e.1);
    // And the database itself holds no second one.
    let dup = db.lock().execute(
        "INSERT INTO agents (vm_id, role, name, private_ip, wg_public_key, created_at) VALUES ('x', 'openclaw', 'x', '10.77.0.9', ?1, 1)",
        [WG_KEY],
    );
    assert!(dup.is_err());
}

/// With a code that names the agent's address, the vm-agent listens there, or for an `up --local`
/// container on its host's side of `outside`; nowhere else, not any private address.
#[test]
fn a_named_code_ties_the_listen_address_to_it() {
    let ip = |s: &str| s.parse::<Ipv4Addr>().expect("ip");
    let source = ip("203.0.113.7");
    assert!(listen_allowed(ip("203.0.113.7"), None, source).is_ok());
    assert!(listen_allowed(ip("10.0.0.9"), None, source).is_err());
    assert!(listen_allowed(ip("10.0.0.5"), Some(ip("10.0.0.5")), source).is_ok());
    assert!(
        listen_allowed(ip("10.0.0.6"), Some(ip("10.0.0.5")), source).is_err(),
        "another private address"
    );
    assert!(
        listen_allowed(ip("172.31.252.1"), Some(ip("172.31.251.10")), source).is_ok(),
        "up --local"
    );
    assert!(listen_allowed(ip("172.31.252.1"), Some(ip("10.0.0.5")), source).is_err());
    assert!(
        listen_allowed(ip("172.31.252.2"), Some(ip("172.31.251.10")), source).is_err(),
        "the firewall's side"
    );
}

#[test]
fn the_firewalls_own_addresses_are_read_from_the_kernel() {
    if std::path::Path::new("/proc/net/fib_trie").exists() {
        assert!(firewall_addresses().contains(&Ipv4Addr::LOCALHOST));
    }
}

/// The firewall says where its calls come from: its own address toward the vm-agent.
#[test]
fn the_firewall_calls_from_its_own_address_toward_the_agent() {
    assert_eq!(
        source_toward("127.0.0.1:9".parse().expect("addr")),
        Some(Ipv4Addr::LOCALHOST)
    );
}
