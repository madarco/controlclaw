//! `phone-setup.test.ts`, against the fake gateway from `cc-openclaw`.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use cc_openclaw::ConfigWriter;
use cc_openclaw::config_queue::fake_config::{FakeConfigGateway, FakeOpenClawConfig};
use cc_proc::{Output, RecordingRunner, ok};
use serde_json::{Value, json};

use super::*;

fn input(generation: char) -> Value {
    super::super::apply::parse_phone_apply(Some(&json!({
        "generation": generation.to_string().repeat(32),
        "placeholder": format!("CC-TWILIO-{}", "b".repeat(32)),
        "accountSid": format!("AC{}", "c".repeat(32)),
        "fromNumber": "+14155550123",
        "publicUrl": format!("https://firewall.example/hook/hk_{}", "d".repeat(32)),
        "allowFrom": [],
        "allowAll": false,
    })))
    .expect("valid")
}

struct Rig {
    oc: FakeOpenClawConfig,
    service: Arc<PhoneService>,
    installs: Arc<AtomicUsize>,
}

fn rig(install: HookFn, installs: Arc<AtomicUsize>) -> Rig {
    let oc = FakeOpenClawConfig::new(json!({"agents": {"defaults": {"model": "test/model"}}}), None, false);
    let writer = Arc::new(ConfigWriter::new(Arc::new(FakeConfigGateway::new(oc.clone(), true))));
    let mut deps = Deps::new(
        Arc::new(move || Some(writer.clone())),
        Arc::new(RecordingRunner::new()),
        Arc::new(|| Box::pin(async {})),
    );
    deps.install = Some(install);
    deps.probe = Some(Arc::new(|_| Box::pin(async { true })));
    deps.poll = Duration::from_millis(10);
    Rig {
        oc,
        service: PhoneService::new(deps),
        installs,
    }
}

async fn settle(s: &PhoneService) {
    for _ in 0..500 {
        if s.status().and_then(|m| m.get("status").cloned()) != Some(json!("pending")) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// "plugin operations allow the native ten-minute lease wait and only return fixed failure codes".
#[tokio::test]
async fn plugin_operations_wait_for_the_lease_and_fail_with_fixed_codes() {
    assert!(PHONE_PLUGIN_INSTALL > Duration::from_secs(600));
    let args = ["plugins", "install", "@openclaw/voice-call@2026.9.7"];
    let r = RecordingRunner::new();
    r.answer(&["/usr/bin/openclaw"], ok("installed"));
    assert_eq!(run_plugin_mutation(&r, &args).await, Ok("installed".to_string()));
    let call = &r.calls()[0];
    assert_eq!(call.args, args);
    assert_eq!(call.timeout, Some(PHONE_PLUGIN_INSTALL));
    for (stderr, code) in [
        (
            "Waiting for plugin lifecycle lease core:plugin-lifecycle/global held by private-owner; current lease expires",
            "plugin_busy",
        ),
        ("plugin lifecycle lease is held by private-owner", "plugin_busy"),
        (
            &*format!("registry rejected secret-token AC{}", "a".repeat(32)),
            "plugin_install_failed",
        ),
    ] {
        let r = RecordingRunner::new();
        r.answer(
            &["/usr/bin/openclaw"],
            Output {
                code: Some(1),
                stderr: stderr.as_bytes().to_vec(),
                ..Default::default()
            },
        );
        let e = run_plugin_mutation(&r, &args).await.expect_err("fails");
        assert_eq!(e, SetupError::Code(code));
        assert!(!format!("{e:?}").contains("private-owner") && !format!("{e:?}").contains("secret-token"));
    }
}

/// "Retry re-runs a failed identical apply, clears its error, and deduplicates only pending work".
#[tokio::test]
async fn retry_reruns_a_failed_identical_apply() {
    let installs = Arc::new(AtomicUsize::new(0));
    let gate = Arc::new(tokio::sync::Notify::new());
    let (n, g) = (installs.clone(), gate.clone());
    let r = rig(
        Arc::new(move || {
            let (n, g) = (n.clone(), g.clone());
            Box::pin(async move {
                let k = n.fetch_add(1, Ordering::SeqCst) + 1;
                if k == 1 {
                    g.notified().await;
                    return Err(SetupError::Code("plugin_busy"));
                }
                Ok(())
            })
        }),
        installs,
    );
    let first = r.service.start(input('a'));
    assert_eq!(
        first,
        json!({"generation": "a".repeat(32), "status": "pending"})
            .as_object()
            .cloned()
            .expect("o")
    );
    // The same pending settings again: the same record, no second run.
    assert_eq!(r.service.start(input('a')), first);
    tokio::time::sleep(Duration::from_millis(20)).await;
    gate.notify_one();
    settle(&r.service).await;
    let status = r.service.status().expect("status");
    assert_eq!(status["status"], "failed");
    assert_eq!(status["error"], "plugin_busy");
    assert_eq!(r.installs.load(Ordering::SeqCst), 1);
    let retry = r.service.start(input('a'));
    assert_eq!(retry.get("error"), None);
    assert_eq!(retry["status"], "pending");
    settle(&r.service).await;
    assert_eq!(r.installs.load(Ordering::SeqCst), 2);
    let status = r.service.status().expect("status");
    assert_eq!(status["status"], "active");
    assert_eq!(status.get("error"), None);
    assert_eq!(r.service.stream_binding().map(|b| b.generation), Some("a".repeat(32)));
}

/// "a changed apply for the same assignment runs again and names the arrays it may shrink".
#[tokio::test]
async fn a_changed_apply_runs_again_and_names_the_arrays() {
    let installs = Arc::new(AtomicUsize::new(0));
    let r = rig(Arc::new(|| Box::pin(async { Ok(()) })), installs);
    let mut first = input('f');
    first["allowFrom"] = json!(["+14155550999", "+14155550998"]);
    first["maxDurationSeconds"] = json!(600);
    r.service.start(first.clone());
    settle(&r.service).await;
    assert_eq!(r.service.status().expect("s")["status"], "active");
    let mut changed = first.clone();
    changed["allowFrom"] = json!(["+14155550999"]);
    changed["maxDurationSeconds"] = json!(120);
    assert_eq!(r.service.start(changed)["status"], "pending");
    settle(&r.service).await;
    assert_eq!(r.service.status().expect("s")["status"], "active");
    let patches = r.oc.state().patches;
    assert_eq!(patches.len(), 2);
    for path in [
        "plugins.entries.voice-call.config.allowFrom",
        "plugins.entries.voice-call.config.realtime.providers.cc-phone-voice.wake.words",
    ] {
        assert!(
            patches[1].1.iter().any(|p| p == path),
            "{path} not named: {:?}",
            patches[1].1
        );
    }
    assert_eq!(
        r.oc.config()["plugins"]["entries"]["voice-call"]["config"]["allowFrom"],
        json!(["+14155550999"])
    );
    assert_eq!(
        r.service.stream_binding().and_then(|b| b.max_duration_seconds),
        Some(120)
    );
}

/// While W6's gateway slot is empty, setup fails closed with the TS code; nothing is written.
#[tokio::test]
async fn no_gateway_is_gateway_unavailable() {
    let mut deps = Deps::new(
        Arc::new(|| None),
        Arc::new(RecordingRunner::new()),
        Arc::new(|| Box::pin(async {})),
    );
    deps.install = Some(Arc::new(|| Box::pin(async { Ok(()) })));
    let s = PhoneService::new(deps);
    s.start(input('e'));
    settle(&s).await;
    let status = s.status().expect("s");
    assert_eq!(status["status"], "failed");
    assert_eq!(status["error"], "gateway_unavailable");
    assert!(s.stream_binding().is_none());
}

/// Settings without a placeholder turn the plugin off, and the relay has nothing to check against.
#[tokio::test]
async fn a_removal_turns_the_plugin_off() {
    let r = rig(Arc::new(|| Box::pin(async { Ok(()) })), Arc::new(AtomicUsize::new(0)));
    let off = super::super::apply::parse_phone_apply(Some(&json!({"generation": "1".repeat(32), "placeholder": null})))
        .expect("v");
    r.service.start(off);
    settle(&r.service).await;
    assert_eq!(r.service.status().expect("s")["status"], "active");
    // The patch sends `config: null`, which a merge patch reads as "remove".
    let patches = r.oc.state().patches;
    assert_eq!(
        patches[0].0.pointer("/plugins/entries/voice-call"),
        Some(&json!({"enabled": false, "config": null}))
    );
    assert_eq!(
        r.oc.config()["plugins"]["entries"]["voice-call"],
        json!({"enabled": false})
    );
    assert!(r.service.stream_binding().is_none());
}

/// A model nobody set is `model_missing`.
#[tokio::test]
async fn no_model_is_model_missing() {
    let oc = FakeOpenClawConfig::new(json!({}), None, false);
    let writer = Arc::new(ConfigWriter::new(Arc::new(FakeConfigGateway::new(oc, true))));
    let mut deps = Deps::new(
        Arc::new(move || Some(writer.clone())),
        Arc::new(RecordingRunner::new()),
        Arc::new(|| Box::pin(async {})),
    );
    deps.install = Some(Arc::new(|| Box::pin(async { Ok(()) })));
    let s = PhoneService::new(deps);
    s.start(input('2'));
    settle(&s).await;
    assert_eq!(s.status().expect("s")["error"], "model_missing");
}

/// `probePhone`: a "completed" status callback from the number to itself, signed as Twilio signs
/// (HMAC-SHA1 of the public URL, the query and the sorted parameters, with the placeholder).
#[tokio::test]
async fn the_probe_is_signed_as_twilio_signs() {
    use http_body_util::BodyExt;
    let seen: Arc<std::sync::Mutex<Option<(String, String, String)>>> = Arc::default();
    let s = seen.clone();
    let mut router = cc_http::Router::new(&["all"]);
    router.route(
        "all",
        |_, _| true,
        move |req: cc_http::Req, _| {
            let s = s.clone();
            async move {
                let target = req.uri().to_string();
                let sig = req
                    .headers()
                    .get("x-twilio-signature")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default()
                    .to_string();
                let body = String::from_utf8(req.into_body().collect().await.expect("body").to_bytes().to_vec())
                    .expect("utf8");
                *s.lock().expect("seen") = Some((target, sig, body));
                cc_http::full(http::StatusCode::OK, "text/xml", "<Response/>")
            }
        },
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("addr"));
    tokio::spawn(cc_http::serve(listener, Arc::new(router)));
    let i = input('a');
    assert!(probe_at(&i, &base).await);
    let (target, sig, body) = seen.lock().expect("seen").clone().expect("called");
    let query = target.trim_start_matches("/voice/webhook");
    assert!(query.starts_with("?type=status&callId="));
    let params: Vec<(String, String)> = url::form_urlencoded::parse(body.as_bytes()).into_owned().collect();
    let mut sorted = params.clone();
    sorted.sort();
    let signed = format!(
        "{}{query}{}",
        i["publicUrl"].as_str().expect("url"),
        sorted.iter().map(|(k, v)| format!("{k}{v}")).collect::<String>()
    );
    let mut mac =
        <Hmac<sha1::Sha1> as Mac>::new_from_slice(i["placeholder"].as_str().expect("p").as_bytes()).expect("key");
    mac.update(signed.as_bytes());
    assert_eq!(
        sig,
        base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes())
    );
    assert!(body.contains("From=%2B14155550123"));
    assert!(params.iter().any(|(k, v)| k == "CallStatus" && v == "completed"));
    // Nothing listening: not ready.
    assert!(!probe_at(&i, "http://127.0.0.1:9").await);
}

/// A trusted install whose files are not the pinned ones is not a dead end: setup goes on to a
/// fresh install, as the TS's `catch` around the receipt does (here `npm pack` is not answered,
/// so the setup ends in `plugin_install_failed`, not `plugin_integrity`).
#[tokio::test]
async fn a_trusted_install_that_does_not_patch_is_reinstalled() {
    let dir = tempfile::tempdir().expect("dir");
    let setup = dir.path().join("dist").join(".setup");
    std::fs::create_dir_all(&setup).expect("dir");
    for name in [
        "runtime-entry-BNOQRXii.mjs",
        "response-generator-BzKrJMEb.mjs",
        "twilio-Bp3gfmUB.mjs",
        "realtime-handler-BgDPcPZt.mjs",
    ] {
        std::fs::write(setup.join(name), "changed").expect("file");
    }
    let receipt = json!({"install": {
        "source": "npm", "spec": super::super::apply::PHONE_PACKAGE, "resolvedName": "@openclaw/voice-call",
        "resolvedVersion": "2026.9.7", "integrity": super::super::apply::PHONE_INTEGRITY,
        "installPath": dir.path().display().to_string(),
    }});
    let runner = RecordingRunner::new();
    runner.answer(&["/usr/bin/openclaw", "--version"], ok("OpenClaw 2026.9.7\n"));
    runner.answer(
        &["/usr/bin/openclaw", "plugins", "info"],
        ok(&format!("log line\n{receipt}")),
    );
    let oc = FakeOpenClawConfig::new(json!({"agents": {"defaults": {"model": "test/model"}}}), None, false);
    let writer = Arc::new(ConfigWriter::new(Arc::new(FakeConfigGateway::new(oc, true))));
    let deps = Deps::new(
        Arc::new(move || Some(writer.clone())),
        Arc::new(runner.clone()),
        Arc::new(|| Box::pin(async {})),
    );
    let s = PhoneService::new(deps);
    s.start(input('3'));
    settle(&s).await;
    assert_eq!(s.status().expect("s")["error"], "plugin_install_failed");
    assert!(
        runner.calls().iter().any(|c| c.program == "npm"),
        "a fresh install was tried"
    );
}

/// "a setup that fails while the agent is being updated stays pending and is retried once the
/// update settles". The update finishes while the service waits: no real minutes pass.
#[tokio::test]
async fn a_setup_that_fails_during_an_update_stays_pending_and_is_retried_once_it_settles() {
    let installs = Arc::new(AtomicUsize::new(0));
    let i = installs.clone();
    let install: HookFn = Arc::new(move || {
        let n = i.fetch_add(1, Ordering::SeqCst) + 1;
        Box::pin(async move {
            // OpenClaw is replaced under the first attempt (the D16 failure); the retry finds it back.
            if n == 1 {
                Err(SetupError::Code("plugin_install_failed"))
            } else {
                Ok(())
            }
        })
    });
    let oc = FakeOpenClawConfig::new(json!({"agents": {"defaults": {"model": "test/model"}}}), None, false);
    let writer = Arc::new(ConfigWriter::new(Arc::new(FakeConfigGateway::new(oc, true))));
    let mut deps = Deps::new(
        Arc::new(move || Some(writer.clone())),
        Arc::new(RecordingRunner::new()),
        Arc::new(|| Box::pin(async {})),
    );
    deps.install = Some(install);
    deps.probe = Some(Arc::new(|_| Box::pin(async { true })));
    deps.poll = Duration::from_millis(10);
    let done = Arc::new(AtomicBool::new(false));
    let (d1, d2) = (done.clone(), done.clone());
    // What the firewall would read while the setup waits for the update.
    let slot: Arc<std::sync::OnceLock<std::sync::Weak<PhoneService>>> = Arc::default();
    let waits: Arc<std::sync::Mutex<Vec<Value>>> = Arc::default();
    let (s2, w2) = (slot.clone(), waits.clone());
    deps.settle = Some(Settle {
        update: Arc::new(move || {
            let phase = if d1.load(Ordering::SeqCst) { "done" } else { "running" };
            json!({"phase": phase, "detail": null, "ref": null, "at": crate::platform::time::now_iso()})
        }),
        gateway_ready: Arc::new(|_| Box::pin(async { true })),
        sleep: Some(Arc::new(move |_| {
            if let Some(svc) = s2.get().and_then(std::sync::Weak::upgrade) {
                w2.lock()
                    .expect("w")
                    .push(svc.status().and_then(|m| m.get("status").cloned()).unwrap_or_default());
            }
            d2.store(true, Ordering::SeqCst);
            Box::pin(async {})
        })),
    });
    let service = PhoneService::new(deps);
    let _ = slot.set(Arc::downgrade(&service));
    service.start(input('e'));
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..2000 {
        let status = service
            .status()
            .and_then(|m| m.get("status").cloned())
            .unwrap_or_default();
        if status != json!("pending") {
            break;
        }
        seen.insert(status.to_string());
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(seen.into_iter().collect::<Vec<_>>(), ["\"pending\""]);
    assert_eq!(
        service.status().and_then(|m| m.get("status").cloned()),
        Some(json!("active"))
    );
    assert_eq!(installs.load(Ordering::SeqCst), 2);
    // While it waited after the failed attempt, the record still read pending.
    let waits = waits.lock().expect("w").clone();
    assert!(!waits.is_empty() && waits.iter().all(|w| w == "pending"), "{waits:?}");
}

/// Rust only: a setup sitting out the 60 s pause between tries after an Update stops as soon as
/// newer settings arrive, and those are set up straight away.
#[tokio::test]
async fn newer_settings_end_the_retry_pause_of_the_setup_they_replace() {
    let installs = Arc::new(AtomicUsize::new(0));
    let i = installs.clone();
    let install: HookFn = Arc::new(move || {
        let n = i.fetch_add(1, Ordering::SeqCst) + 1;
        Box::pin(async move {
            if n == 1 {
                Err(SetupError::Code("plugin_install_failed"))
            } else {
                Ok(())
            }
        })
    });
    let oc = FakeOpenClawConfig::new(json!({"agents": {"defaults": {"model": "test/model"}}}), None, false);
    let writer = Arc::new(ConfigWriter::new(Arc::new(FakeConfigGateway::new(oc, true))));
    let mut deps = Deps::new(
        Arc::new(move || Some(writer.clone())),
        Arc::new(RecordingRunner::new()),
        Arc::new(|| Box::pin(async {})),
    );
    deps.install = Some(install);
    deps.probe = Some(Arc::new(|_| Box::pin(async { true })));
    deps.poll = Duration::from_millis(10);
    // The Update finished a moment ago: inside the window where a failed setup is retried.
    let at = crate::platform::time::now_iso();
    deps.settle = Some(Settle {
        update: Arc::new(move || json!({"phase": "done", "detail": null, "ref": null, "at": at})),
        gateway_ready: Arc::new(|_| Box::pin(async { true })),
        sleep: None,
    });
    let service = PhoneService::new(deps);
    service.start(input('e'));
    let started = std::time::Instant::now();
    while installs.load(Ordering::SeqCst) == 0 {
        assert!(started.elapsed() < Duration::from_secs(10), "the first setup never ran");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    service.start(input('f'));
    let started = std::time::Instant::now();
    loop {
        let status = service.status().and_then(|m| m.get("status").cloned());
        if status == Some(json!("active")) {
            break;
        }
        assert!(started.elapsed() < Duration::from_secs(10), "still {status:?}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        service.status().and_then(|m| m.get("generation").cloned()),
        Some(json!("f".repeat(32)))
    );
    assert_eq!(installs.load(Ordering::SeqCst), 2);
}
