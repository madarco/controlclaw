//! `gbrain-gate.test.ts`: "the agent box's brain entry".

use cc_openclaw::ConfigWriter;
use cc_openclaw::config_queue::fake_config::{FakeConfigGateway, FakeOpenClawConfig};
use cc_proc::RecordingRunner;

use super::*;

fn deps(writer: Option<Arc<ConfigWriter>>) -> Deps {
    Deps {
        writer: Arc::new(move || writer.clone()),
        runner: Arc::new(RecordingRunner::new()),
        home: std::path::PathBuf::from("/tmp"),
        restart: Arc::new(|| Box::pin(async { Ok(()) })),
        log: Arc::new(|_| {}),
        bin: crate::platform::common::OPENCLAW_BIN.to_string(),
        unit_down: None,
    }
}

fn obj(v: Value) -> Map<String, Value> {
    v.as_object().cloned().expect("object")
}

#[tokio::test]
async fn the_brain_entry_is_one_url_written_by_the_firewall() {
    assert_eq!(
        parse_brain_apply(Some(&obj(json!({"url": "http://10.0.0.9:3131/mcp"})))),
        Ok(BrainApply::Url("http://10.0.0.9:3131/mcp".into()))
    );
    assert_eq!(
        parse_brain_apply(Some(&obj(json!({"remove": true})))),
        Ok(BrainApply::Remove)
    );
    for url in [
        "https://evil.example/mcp",
        "http://10.0.0.9:3130/mcp",
        "http://10.0.0.9:3131/admin",
        "http://10.0.0.9:3131/mcp?t=x",
        // Digits other than ASCII, which JavaScript's `\d` does not take.
        "http://10.\u{966}.\u{966}.\u{96f}:3131/mcp",
        "http://10.\u{ff10}.\u{ff10}.\u{ff19}:3131/mcp",
        // Rust only: an octet over 255, or with a leading zero (octal to a URL parser).
        "http://10.0.0.256:3131/mcp",
        "http://10.010.0.9:3131/mcp",
        "http://10.0.00.9:3131/mcp",
    ] {
        assert!(parse_brain_apply(Some(&obj(json!({"url": url})))).is_err(), "{url}");
    }
    for url in ["http://10.255.249.0:3131/mcp", "http://10.1.10.100:3131/mcp"] {
        assert!(parse_brain_apply(Some(&obj(json!({"url": url})))).is_ok(), "{url}");
    }
    assert_eq!(parse_brain_apply(None), Err("a JSON body is required"));

    let oc = FakeOpenClawConfig::new(json!({}), None, false);
    let gw = Arc::new(FakeConfigGateway::new(oc.clone(), true));
    let d = deps(Some(Arc::new(ConfigWriter::new(gw.clone()))));
    let url = BrainApply::Url("http://10.0.0.9:3131/mcp".into());
    assert_eq!(apply(&d, &url).await.expect("apply")["changed"], true);
    assert_eq!(
        oc.get()["config"]["mcp"]["servers"]["gbrain"],
        json!({"url": "http://10.0.0.9:3131/mcp", "transport": "streamable-http"})
    );
    assert_eq!(apply(&d, &url).await.expect("again")["changed"], false);
    let removed = apply(&d, &BrainApply::Remove).await.expect("remove");
    assert_eq!(removed, json!({"ok": true, "configured": false, "changed": true}));
    assert_eq!(oc.get()["config"]["mcp"]["servers"].get("gbrain"), None);
    // A removal is written even when the gateway's view has no entry.
    assert_eq!(apply(&d, &BrainApply::Remove).await.expect("remove")["changed"], true);

    let err = apply(&deps(None), &BrainApply::Remove).await.expect_err("down");
    assert!(err.contains("not running"), "{err}");
}
