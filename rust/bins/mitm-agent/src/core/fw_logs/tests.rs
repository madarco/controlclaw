//! `fw-logs.test.ts` and `fw-logs-page.test.ts`.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};

use super::*;

fn entry(fields: Value) -> String {
    let mut m = json!({"__REALTIME_TIMESTAMP": "1760000000000000", "PRIORITY": "6"})
        .as_object()
        .cloned()
        .expect("o");
    if let Value::Object(f) = fields {
        m.extend(f);
    }
    Value::Object(m).to_string()
}

fn none(s: &str) -> String {
    s.to_string()
}

#[test]
fn journal_lines_newest_first_outside_units_dropped() {
    let out = [
        entry(json!({"__REALTIME_TIMESTAMP": "1760000001000000", "_SYSTEMD_UNIT": "dnsmasq.service", "PRIORITY": "3", "MESSAGE": "failed to bind DHCP server socket"})),
        entry(json!({"__REALTIME_TIMESTAMP": "1760000003000000", "_SYSTEMD_UNIT": "init.scope", "_PID": "1", "SYSLOG_IDENTIFIER": "systemd", "UNIT": "dnsmasq.service", "MESSAGE": "dnsmasq.service: Failed with result 'exit-code'."})),
        entry(json!({"__REALTIME_TIMESTAMP": "1760000002000000", "_SYSTEMD_UNIT": "tangd@3-127.0.0.1:3921-127.0.0.1:5000.service", "PRIORITY": "4", "MESSAGE": "warn"})),
        entry(json!({"_SYSTEMD_UNIT": "caddy.service", "MESSAGE": "{\"level\":\"error\",\"msg\":\"tls handshake\"}"})),
        entry(json!({"_SYSTEMD_UNIT": "sshd.service", "MESSAGE": "Accepted publickey"})),
        "not json".to_string(),
        entry(json!({"_SYSTEMD_UNIT": "clickclack.service", "MESSAGE": [104, 105, 10]})),
    ]
    .join("\n");
    let lines = parse_journal(&out, &none);
    let got: Vec<(Value, Value)> = lines
        .iter()
        .map(|l| (l["service"].clone(), l["level"].clone()))
        .collect();
    assert_eq!(
        got,
        vec![
            (json!("dnsmasq"), json!("unit")),
            (json!("tang"), json!("warn")),
            (json!("dnsmasq"), json!("error")),
            (json!("caddy"), json!("error")),
            (json!("team-chat"), json!("info"))
        ]
    );
    assert_eq!(lines.last().expect("l")["message"], "hi");
    assert_eq!(lines[0]["time"], "2025-10-09T08:53:23.000Z");
}

#[test]
fn own_reads_and_clean_tang_units_are_left_out() {
    let out = [
        entry(json!({"_SYSTEMD_UNIT": "controlclaw-mitm-agent.service", "SYSLOG_IDENTIFIER": "sudo", "MESSAGE": "controlclaw : PWD=/ ; USER=root ; COMMAND=/usr/local/bin/cc-fw-logs journal 3600 3000 all"})),
        entry(json!({"_SYSTEMD_UNIT": "controlclaw-mitm-agent.service", "SYSLOG_IDENTIFIER": "sudo", "MESSAGE": "pam_unix(sudo:session): session opened for user root(uid=0) by (uid=999)"})),
        entry(json!({"_SYSTEMD_UNIT": "controlclaw-mitm-agent.service", "SYSLOG_IDENTIFIER": "sudo", "MESSAGE": "controlclaw : PWD=/ ; USER=root ; COMMAND=/usr/bin/systemctl restart controlclaw-mitmproxy"})),
        entry(json!({"_SYSTEMD_UNIT": "init.scope", "_PID": "1", "SYSLOG_IDENTIFIER": "systemd", "UNIT": "tangd@75-127.0.0.1:3921-127.0.0.1:52510.service", "MESSAGE": "Started tangd@75-127.0.0.1:3921-127.0.0.1:52510.service - Tang Server (127.0.0.1:52510)."})),
        entry(json!({"_SYSTEMD_UNIT": "init.scope", "_PID": "1", "SYSLOG_IDENTIFIER": "systemd", "UNIT": "tangd@75-127.0.0.1:3921-127.0.0.1:52510.service", "MESSAGE": "tangd@75-127.0.0.1:3921-127.0.0.1:52510.service: Deactivated successfully."})),
        entry(json!({"_SYSTEMD_UNIT": "init.scope", "_PID": "1", "SYSLOG_IDENTIFIER": "systemd", "UNIT": "tangd@76-127.0.0.1:3921-127.0.0.1:52511.service", "MESSAGE": "tangd@76-127.0.0.1:3921-127.0.0.1:52511.service: Failed with result 'exit-code'."})),
    ]
    .join("\n");
    let got: Vec<Value> = parse_journal(&out, &none)
        .iter()
        .map(|l| l["message"].clone())
        .collect();
    assert_eq!(
        got,
        vec![
            json!("controlclaw : PWD=/ ; USER=root ; COMMAND=/usr/bin/systemctl restart controlclaw-mitmproxy"),
            json!("tangd@76-127.0.0.1:3921-127.0.0.1:52511.service: Failed with result 'exit-code'.")
        ]
    );
    let line = json!({"__REALTIME_TIMESTAMP": "1760000000000000", "_SYSTEMD_UNIT": "dnsmasq.service", "MESSAGE": "q"})
        .to_string();
    assert_eq!(parse_journal(&line, &none)[0]["level"], "info");
}

#[test]
fn systemctl_show_states() {
    let show = [
        "Id=controlclaw-mitm-agent.service\nLoadState=loaded\nActiveState=active\nSubState=running\nResult=success\nNRestarts=0\nExecMainStatus=0\nActiveEnterTimestamp=@1760000000\nInactiveEnterTimestamp=",
        "Id=dnsmasq.service\nLoadState=loaded\nActiveState=failed\nSubState=failed\nResult=exit-code\nNRestarts=3\nExecMainStatus=2\nActiveEnterTimestamp=@1759990000\nInactiveEnterTimestamp=@1760000100",
        "Id=tailscaled.service\nLoadState=not-found\nActiveState=inactive",
        "Id=clickclack.service\nLoadState=loaded\nActiveState=inactive\nSubState=dead\nResult=success\nNRestarts=0\nExecMainStatus=0\nActiveEnterTimestamp=\nInactiveEnterTimestamp=",
    ]
    .join("\n\n");
    let states = service_states(&parse_show(&show));
    let ids: Vec<&Value> = states.iter().map(|s| &s["id"]).collect();
    assert_eq!(ids, [&json!("mitm-agent"), &json!("dnsmasq"), &json!("team-chat")]);
    assert_eq!(states[1]["active"], "failed");
    assert_eq!(states[1]["exitStatus"], 2);
    assert_eq!(states[1]["restarts"], 3);
    assert_eq!(
        states[1]["since"],
        cc_crypto::store_health::iso_from_millis(1_760_000_100_000)
    );
    assert_eq!(states[2]["optional"], true);
}

fn reader(run: Run, helper: bool, update: Value) -> FwLogsReader {
    FwLogsReader {
        secrets: Arc::new(|| {
            vec![
                "tg-bot-token-1234567890".into(),
                "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIG9zZWNyZXQ\n-----END PRIVATE KEY-----".into(),
            ]
        }),
        hostname: Arc::new(|| Some("fw.example.com".into())),
        run,
        helper_present: Arc::new(move || helper),
        update: Arc::new(move || update.clone()),
    }
}

#[tokio::test]
async fn the_reader_masks_and_asks_the_helper() {
    let calls: Arc<Mutex<Vec<Vec<String>>>> = Arc::default();
    let c = calls.clone();
    let run: Run = Arc::new(move |cmd: &str, args: Vec<String>| {
        let mut all = vec![cmd.to_string()];
        all.extend(args.clone());
        c.lock().expect("lock").push(all);
        let cmd = cmd.to_string();
        Box::pin(async move {
            if cmd == "systemctl" {
                return Ok(
                    "Id=controlclaw-mitmproxy.service\nLoadState=loaded\nActiveState=active\nSubState=running".into(),
                );
            }
            if args.get(2).map(String::as_str) == Some("run") {
                return Ok("TASK [x]\nok: MC4CAQAwBQYDK2VwBCIEIG9zZWNyZXQ\nchanged: token=abcdef123\n".into());
            }
            Ok(entry(
                json!({"_SYSTEMD_UNIT": "controlclaw-mitmproxy.service", "MESSAGE": "upstream https://api.telegram.org/bottg-bot-token-1234567890/getMe Authorization: Bearer sk-live-abcdefgh"}),
            ))
        })
    });
    let r = reader(
        run,
        true,
        json!({"phase": "done", "detail": "updated to abc", "ref": "abc", "at": "2026-10-08T10:00:00Z"}),
    );
    let res = r.read("15m", "proxy").await;
    assert_eq!(
        calls.lock().expect("lock")[1],
        [
            "sudo",
            "-n",
            "/usr/local/bin/cc-fw-logs",
            "journal",
            "900",
            "3000",
            "proxy"
        ]
    );
    assert_eq!(
        res["lines"][0]["message"],
        "upstream https://api.telegram.org/bot[redacted]/getMe Authorization: Bearer [redacted]"
    );
    assert_eq!(res["firewall"], "fw.example.com");
    assert_eq!(res["services"][0]["id"], "proxy");
    let keys: Vec<&String> = res.as_object().expect("o").keys().collect();
    assert_eq!(
        keys,
        [
            "firewall",
            "range",
            "service",
            "update",
            "lines",
            "truncated",
            "services"
        ]
    );
    let run = r.read("1h", "run").await;
    assert_eq!(
        run["run"],
        json!(["TASK [x]", "ok: [redacted]", "changed: token=[redacted]"])
    );
    assert_eq!(run["lines"], json!([]));
    assert_eq!(run["update"]["phase"], "done");
    let r = reader(
        Arc::new(|_: &str, _| Box::pin(async { Ok(String::new()) })),
        false,
        Value::Null,
    );
    let res = r.read("1h", "all").await;
    assert!(res["warning"].as_str().expect("w").contains("Press Update"));
}

#[test]
fn a_secret_across_the_cap_is_masked_whole() {
    let secret = "s3cr3t-value-ABCDEFGHIJKLMNOP";
    let message = format!("{}{secret} tail", "x".repeat(3990));
    let r = cc_redact::Redactor::new([secret]);
    let lines = parse_journal(
        &entry(json!({"_SYSTEMD_UNIT": "controlclaw-mitmproxy.service", "MESSAGE": message})),
        &|s| r.redact(s),
    );
    assert!(!lines[0]["message"].as_str().expect("m").contains("s3cr3t"));
}

/// `fw-logs-page.test.ts`.
#[tokio::test]
async fn the_page_behind_its_door() {
    use crate::core::access::{AccessFirewall, AccessOptions};
    use crate::core::access_store::{AccessStore, AccessStoreFile, StoredDevice};
    use std::sync::atomic::AtomicBool;
    let d = tempfile::tempdir().expect("dir");
    let key = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
    let pair = cc_testkit::Pair::from_seed(5);
    let token = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ".to_string();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("t")
        .as_millis() as u64;
    let file = AccessStoreFile::new(&d.path().join("access.enc"), key, "org", "fw");
    let mut store = AccessStore::default();
    store.devices.insert(
        "device".into(),
        StoredDevice {
            hash: hex::encode(Sha256::digest(token.as_bytes())),
            user_id: "owner".into(),
            email: None,
            label: "Test".into(),
            via: "code".into(),
            created_at: crate::core::consent::iso(now),
            last_used_at: crate::core::consent::iso(now),
            listed_at: None,
            extra: Map::new(),
        },
    );
    file.save(&store).expect("save");
    let stopped = Arc::new(AtomicBool::new(false));
    let s = stopped.clone();
    let keys = d.path().join("keys");
    cc_testkit::BoxKeys::write(&keys, "fw", "fw.example").expect("keys");
    let agents = Arc::new(crate::core::identities::Agents::default());
    let client = crate::core::agent_client::AgentClient::for_tests(
        cc_auth::keys::KeysDir::new(&keys),
        agents.clone(),
        Arc::new(|_| None),
    );
    let consent = crate::core::consent::Consent::for_tests(client.clone(), Arc::new(|| None), Arc::new(|| 0), "111111");
    let (pubpem, privpem) = (pair.public_pem.clone(), pair.private_pem.clone());
    let access = AccessFirewall::new(AccessOptions {
        store: file,
        org_id: "org".into(),
        box_id: "fw".into(),
        agent: client,
        consent: crate::contracts::CodeService::module(
            &crate::core::consent::ConsentView(consent),
            crate::core::access::MODULE,
        ),
        code_routes: Arc::new(Vec::new),
        channels_ready: Arc::new(|| true),
        identities: Arc::new(|| {
            vec![
                json!({"vm_id": "agent-one", "hostname": "a1.example.com"})
                    .as_object()
                    .cloned()
                    .expect("o"),
            ]
        }),
        stopped: Arc::new(move |_: &str| s.load(Ordering::SeqCst)),
        hostname: Arc::new(|| Some("firewall.example.com".into())),
        saas_public_key: Arc::new(move || Some(pubpem.clone())),
        signing_key: Arc::new(move || Some(privpem.clone())),
        now: Arc::new(move || now),
    });
    let asked = Arc::new(AtomicUsize::new(0));
    let a = asked.clone();
    let reader = Arc::new(FwLogsReader {
        secrets: Arc::new(Vec::new),
        hostname: Arc::new(|| None),
        run: Arc::new(move |cmd: &str, _| {
            if cmd == "sudo" {
                a.fetch_add(1, Ordering::SeqCst);
            }
            Box::pin(async {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                Ok(entry(
                    json!({"_SYSTEMD_UNIT": "controlclaw-mitmproxy.service", "MESSAGE": "proxy marker"}),
                ))
            })
        }),
        helper_present: Arc::new(|| true),
        update: Arc::new(|| Value::Null),
    });
    let page = FwLogsPage::new(
        access.clone(),
        reader,
        Arc::new(|| Some("https://console.example.com/dashboard/firewall".into())),
        "document.title='x';".into(),
        Arc::new(move || now),
    );
    let sign = |claims: Value| {
        let mut c = json!({"purpose": "open-intent", "orgId": "org", "vmId": "fw", "userId": "owner", "canWrite": false, "next": "firewall-logs"})
            .as_object()
            .cloned()
            .expect("o");
        if let Value::Object(e) = claims {
            c.extend(e);
        }
        c.insert("jti".into(), json!(format!("{}", rand::random::<u64>())));
        let k = cc_auth::jwt::SignKey::ed25519_pkcs8_pem(&pair.private_pem).expect("k");
        cc_auth::jwt::sign(c, &k, Some(60), Some((now / 1000) as i64)).expect("sign")
    };
    let origin = "https://firewall.example.com";
    let device = format!("__Host-cc_dev={token}");
    let req = |method: &str, path: &str, query: &str, cookie: &str, origin: Option<&str>, body: &str| PageRequest {
        method: method.into(),
        path: path.into(),
        query: query.into(),
        origin: origin.map(str::to_string),
        cookie: Some(cookie.to_string()).filter(|c| !c.is_empty()),
        content_type: "application/x-www-form-urlencoded".into(),
        body: Some(body.as_bytes().to_vec()),
    };
    let post = |jwt: &str, cookie: &str, o: &str| {
        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("intent", jwt)
            .finish();
        req("POST", "/__cc/doctor/logs/open", "", cookie, Some(o), &body)
    };
    assert_eq!(page.handle(&post(&sign(json!({})), "", origin)).await.status, 403);
    assert_eq!(
        page.handle(&post(&sign(json!({})), &device, "https://evil.example"))
            .await
            .status,
        403
    );
    for claims in [
        json!({"orgId": "other"}),
        json!({"vmId": "agent-one"}),
        json!({"userId": "other"}),
        json!({"next": "ai-review"}),
        json!({"next": "team-chat"}),
        json!({"purpose": "box-ticket"}),
    ] {
        assert_eq!(
            page.handle(&post(&sign(claims.clone()), &device, origin)).await.status,
            403,
            "{claims}"
        );
    }
    stopped.store(true, Ordering::SeqCst);
    assert_eq!(page.handle(&post(&sign(json!({})), &device, origin)).await.status, 403);
    stopped.store(false, Ordering::SeqCst);
    let jwt = sign(json!({}));
    let opened = page.handle(&post(&jwt, &device, origin)).await;
    assert_eq!(opened.status, 303);
    let h = |r: &PageReply, k: &str| {
        r.headers
            .iter()
            .find(|(n, _)| n == k)
            .map(|x| x.1.clone())
            .unwrap_or_default()
    };
    assert_eq!(h(&opened, "location"), "/__cc/doctor/logs/");
    let set = h(&opened, "set-cookie");
    assert!(
        set.starts_with("__Secure-cc_fw_logs=")
            && set.contains("; Path=/__cc/doctor/logs; Secure; HttpOnly; SameSite=Strict")
    );
    assert_eq!(
        page.handle(&post(&jwt, &device, origin)).await.status,
        403,
        "an intent opens once"
    );
    let cookie = format!("{device}; {}", set.split(';').next().expect("c"));
    let html = page
        .handle(&req("GET", "/__cc/doctor/logs/", "", &cookie, None, ""))
        .await;
    assert_eq!(html.status, 200);
    assert!(h(&html, "content-security-policy").contains("script-src 'self'"));
    assert!(html.body.contains(r#"<div id="root"></div>"#));
    assert!(html.body.contains("https://console.example.com/dashboard/firewall"));
    let grant_only = set.split(';').next().expect("c").to_string();
    assert_eq!(
        page.handle(&req("GET", "/__cc/doctor/logs/", "", &grant_only, None, ""))
            .await
            .status,
        403
    );
    let data = page
        .handle(&req(
            "GET",
            "/__cc/doctor/logs/data",
            "range=15m&service=dnsmasq",
            &cookie,
            None,
            "",
        ))
        .await;
    assert!(data.body.contains("\"range\":\"15m\""));
    assert_eq!(
        page.handle(&req("GET", "/__cc/doctor/logs/data", "range=7d", &cookie, None, ""))
            .await
            .status,
        400
    );
    assert_eq!(
        page.handle(&req("GET", "/__cc/doctor/logs/data", "service=sshd", &cookie, None, ""))
            .await
            .status,
        400
    );
    assert_eq!(
        page.handle(&req("POST", "/__cc/doctor/logs/data", "", &cookie, Some(origin), ""))
            .await
            .status,
        405
    );
    // Two tabs asking the same while a read is out share it.
    let before = asked.load(Ordering::SeqCst);
    let (r1, r2) = (
        req(
            "GET",
            "/__cc/doctor/logs/data",
            "range=1h&service=proxy",
            &cookie,
            None,
            "",
        ),
        req(
            "GET",
            "/__cc/doctor/logs/data",
            "range=1h&service=proxy",
            &cookie,
            None,
            "",
        ),
    );
    let (a, b) = tokio::join!(page.handle(&r1), page.handle(&r2));
    assert_eq!((a.status, b.status), (200, 200));
    assert!(a.body.contains("proxy marker"));
    assert_eq!(asked.load(Ordering::SeqCst) - before, 1, "one read for two requests");
    access
        .revoke(json!({"deviceIds": ["device"]}).as_object().cloned().expect("o"))
        .await;
    assert_eq!(
        page.handle(&req("GET", "/__cc/doctor/logs/data", "", &cookie, None, ""))
            .await
            .status,
        403
    );
}
