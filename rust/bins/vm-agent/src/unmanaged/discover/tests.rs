use std::path::Path;

use cc_proc::{RecordingRunner, exit, ok};
use serde_json::json;

use super::*;

/// `openclaw gateway status --json` on Ubuntu 24.04 after the official installer and
/// `onboard --install-daemon` (OpenClaw 2026.10.9).
const SYSTEMD_USER: &str = include_str!("../testdata/gateway-status-systemd-user.json");

#[test]
fn versions() {
    assert_eq!(
        parse_version("OpenClaw 2026.10.9 (8b18b55)\n").as_deref(),
        Some("2026.10.9")
    );
    assert_eq!(parse_version("2026.9.7").as_deref(), Some("2026.9.7"));
    assert_eq!(parse_version("  \n"), None);
}

#[test]
fn json_after_a_banner() {
    assert_eq!(json_out("warn: x\n{\"path\":\"/a\"}"), Some(json!({"path": "/a"})));
    assert_eq!(json_out("nothing"), None);
    assert_eq!(
        json_out("[plugins] loaded 3\n{\"ok\":true}\n"),
        Some(json!({"ok": true}))
    );
    assert_eq!(json_out("[1,2]"), Some(json!([1, 2])));
}

#[test]
fn the_official_install_is_a_systemd_user_unit() {
    let v = json_out(SYSTEMD_USER).expect("json");
    let (runs, port) = parse_gateway_status(&v);
    assert_eq!(
        runs,
        Some(Runs::SystemdUser {
            unit: "openclaw-gateway.service".into()
        })
    );
    assert_eq!(port, Some(18789));
}

#[test]
fn a_system_unit_a_hand_started_gateway_and_none() {
    let system = json!({"service": {"loaded": true, "systemdInstallation": {"kind": "system",
        "system": {"unitName": "openclaw.service"}}}, "gateway": {"port": 18800}});
    assert_eq!(
        parse_gateway_status(&system),
        (
            Some(Runs::SystemdSystem {
                unit: "openclaw.service".into()
            }),
            Some(18800)
        )
    );
    let by_hand = json!({"service": {"loaded": false}, "port": {"port": 18789, "status": "busy",
        "listeners": [{"pid": 42}]}});
    assert_eq!(
        parse_gateway_status(&by_hand),
        (Some(Runs::Process { pid: Some(42) }), Some(18789))
    );
    // A unit that runs but is not enabled.
    let disabled = json!({"service": {"loaded": false, "runtime": {"status": "running"},
        "systemdInstallation": {"kind": "user", "user": {"unitName": "openclaw-gateway.service"}}},
        "port": {"port": 18789, "status": "busy", "listeners": [{"pid": 9}]}});
    assert_eq!(
        parse_gateway_status(&disabled).0,
        Some(Runs::SystemdUser {
            unit: "openclaw-gateway.service".into()
        })
    );
    let none = json!({"service": {"loaded": false}, "port": {"port": 18789, "status": "free"}});
    assert_eq!(parse_gateway_status(&none), (None, Some(18789)));
}

#[test]
fn pm2_and_docker_listings() {
    let pm2 = json!([{"name": "web", "pm2_env": {"pm_exec_path": "/srv/web.js"}},
        {"name": "claw", "pm2_env": {"pm_exec_path": "/home/u/.npm-global/bin/openclaw", "args": ["gateway"]}}]);
    assert_eq!(parse_pm2(&pm2).as_deref(), Some("claw"));
    assert_eq!(parse_pm2(&json!([])), None);

    let ps = concat!(
        r#"{"Image":"postgres:16","Names":"db","Ports":""}"#,
        "\n",
        r#"{"Image":"ghcr.io/openclaw/openclaw:latest","Names":"openclaw-openclaw-gateway-1","Ports":"0.0.0.0:28789->18789/tcp, [::]:28789->18789/tcp"}"#,
    );
    assert_eq!(
        parse_docker_ps(ps),
        Some(("openclaw-openclaw-gateway-1".into(), Some(28789)))
    );
    assert_eq!(parse_docker_ps(r#"{"Image":"nginx","Names":"n","Ports":""}"#), None);
    // Comma-joined names from old links: the plain one.
    assert_eq!(
        parse_docker_ps(r#"{"Image":"openclaw:local","Names":"web/oc,oc-gw","Ports":""}"#),
        Some(("oc-gw".into(), None))
    );
    assert_eq!(
        parse_docker_ps(r#"{"Image":"openclaw:local","Names":"a b","Ports":""}"#),
        None
    );
}

fn hints() -> OpenClawHints {
    OpenClawHints {
        cli: Some("/opt/oc/openclaw".into()),
        ..OpenClawHints::default()
    }
}

#[tokio::test]
async fn discovers_the_official_install() {
    let r = RecordingRunner::new();
    r.answer(&["docker", "ps"], exit(1, ""));
    r.answer(&["/opt/oc/openclaw", "--version"], ok("OpenClaw 2026.10.9 (8b18b55)\n"));
    r.answer(
        &["/opt/oc/openclaw", "config", "file", "--json"],
        ok(r#"{"path":"/home/claw/.openclaw/openclaw.json"}"#),
    );
    r.answer(&["/opt/oc/openclaw", "gateway", "status", "--json"], ok(SYSTEMD_USER));
    let d = tempfile::tempdir().expect("dir");
    let found = discover(&r, &hints(), Path::new("/home/claw"), d.path()).await;
    assert_eq!(
        found,
        Install {
            cli: Some("/opt/oc/openclaw".into()),
            version: Some("2026.10.9".into()),
            config_file: Some("/home/claw/.openclaw/openclaw.json".into()),
            state_dir: Some("/home/claw/.openclaw".into()),
            container_state_dir: None,
            runs: Runs::SystemdUser {
                unit: "openclaw-gateway.service".into()
            },
            gateway_port: 18789,
        }
    );
    // No pm2 asked: OpenClaw named its service.
    assert!(r.calls().iter().all(|c| c.program != "pm2"));
}

#[tokio::test]
async fn a_container_gets_a_wrapper_and_its_published_port() {
    let r = RecordingRunner::new();
    r.answer(
        &["docker", "ps"],
        ok(r#"{"Image":"ghcr.io/openclaw/openclaw:latest","Names":"oc-gw","Ports":"127.0.0.1:18790->18789/tcp"}"#),
    );
    let d = tempfile::tempdir().expect("dir");
    let wrapper = d.path().join(CLI_WRAPPER).to_string_lossy().into_owned();
    r.answer(&[wrapper.as_str(), "--version"], ok("OpenClaw 2026.10.9\n"));
    r.answer(
        &[wrapper.as_str(), "config", "file"],
        ok(r#"{"path":"/home/node/.openclaw/openclaw.json"}"#),
    );
    r.answer(
        &["docker", "inspect"],
        ok(r#"[{"Source":"/home/u/oc-docker","Destination":"/home/node/.openclaw"},{"Source":"/home/u/oc-docker/workspace","Destination":"/home/node/.openclaw/workspace"}]"#),
    );
    let found = discover(&r, &OpenClawHints::default(), Path::new("/home/u"), d.path()).await;
    assert_eq!(
        found.runs,
        Runs::Docker {
            container: "oc-gw".into()
        }
    );
    assert_eq!(found.cli.as_deref(), Some(wrapper.as_str()));
    assert_eq!(found.gateway_port, 18790);
    assert_eq!(found.version.as_deref(), Some("2026.10.9"));
    let script = std::fs::read_to_string(&wrapper).expect("wrapper");
    assert_eq!(
        script,
        "#!/bin/sh\nexec docker exec -i 'oc-gw' node dist/index.js \"$@\"\n"
    );
    // The container's paths, as the host sees them.
    assert_eq!(found.state_dir.as_deref(), Some("/home/u/oc-docker"));
    assert_eq!(found.config_file.as_deref(), Some("/home/u/oc-docker/openclaw.json"));
}

/// A container whose state folder no mount holds: the folder is not known here. Never the path the
/// container's CLI names, read on this machine (another file there, written as root).
#[tokio::test]
async fn a_container_path_no_mount_holds_is_not_taken_here() {
    let r = RecordingRunner::new();
    r.answer(
        &["docker", "ps"],
        ok(r#"{"Image":"ghcr.io/openclaw/openclaw:latest","Names":"oc-gw","Ports":"127.0.0.1:18790->18789/tcp"}"#),
    );
    let d = tempfile::tempdir().expect("dir");
    let wrapper = d.path().join(CLI_WRAPPER).to_string_lossy().into_owned();
    r.answer(&[wrapper.as_str(), "--version"], ok("OpenClaw 2026.10.9\n"));
    r.answer(
        &[wrapper.as_str(), "config", "file"],
        ok(r#"{"path":"/etc/openclaw.json"}"#),
    );
    r.answer(
        &["docker", "inspect"],
        ok(r#"[{"Source":"/home/u/data","Destination":"/data"}]"#),
    );
    let found = discover(&r, &OpenClawHints::default(), Path::new("/home/u"), d.path()).await;
    assert_eq!(found.state_dir, None);
    assert_eq!(found.config_file, None);
}

#[test]
fn wrappers_and_names() {
    assert_eq!(
        wrapper_script(Some(&WrapperTarget::Host("/opt/it's/openclaw".into()))),
        "#!/bin/sh\nexec '/opt/it'\\''s/openclaw' \"$@\"\n"
    );
    assert!(wrapper_script(None).contains("exit 1"));
    assert!(valid_container("openclaw-src-openclaw-gateway-1"));
    for bad in ["", "-x", "a b", "a;rm", "$(x)"] {
        assert!(!valid_container(bad), "{bad}");
    }
}

#[tokio::test]
async fn a_container_hint_that_is_not_a_name_is_ignored() {
    let r = RecordingRunner::new();
    let d = tempfile::tempdir().expect("dir");
    let h = OpenClawHints {
        container: Some("x; rm -rf ~".into()),
        runs: Some("docker".into()),
        ..OpenClawHints::default()
    };
    let found = discover(&r, &h, d.path(), d.path()).await;
    assert!(!matches!(found.runs, Runs::Docker { .. }));
}

#[test]
fn host_paths_take_the_longest_mount() {
    let m = json!([{"Source": "/a", "Destination": "/c"}, {"Source": "/b", "Destination": "/c/w"}]);
    assert_eq!(host_path(&m, "/c/w/x").as_deref(), Some("/b/x"));
    assert_eq!(host_path(&m, "/c").as_deref(), Some("/a"));
    assert_eq!(host_path(&m, "/elsewhere"), None);
    // A path the container names to climb out of its mount: not taken.
    assert_eq!(host_path(&m, "/c/../../etc/c.json"), None);
    assert_eq!(host_path(&m, "c/x"), None);
}

#[tokio::test]
async fn pm2_when_openclaw_sees_only_a_process_and_hints_win() {
    let r = RecordingRunner::new();
    r.answer(&["docker", "ps"], exit(1, ""));
    r.answer(
        &["/opt/oc/openclaw", "gateway", "status", "--json"],
        ok(r#"{"service":{"loaded":false},"port":{"status":"busy","listeners":[{"pid":7}]}}"#),
    );
    r.answer(
        &["pm2", "jlist"],
        ok(r#"[{"name":"oc","pm2_env":{"pm_exec_path":"/x/openclaw"}}]"#),
    );
    let d = tempfile::tempdir().expect("dir");
    let found = discover(&r, &hints(), Path::new("/home/u"), d.path()).await;
    assert_eq!(found.runs, Runs::Pm2 { name: "oc".into() });

    let mut h = hints();
    h.runs = Some("systemd-system".into());
    h.unit = Some("claw.service".into());
    h.gateway_port = Some(19000);
    let found = discover(&r, &h, Path::new("/home/u"), d.path()).await;
    assert_eq!(
        found.runs,
        Runs::SystemdSystem {
            unit: "claw.service".into()
        }
    );
    assert_eq!(found.gateway_port, 19000);
}

#[tokio::test]
async fn nothing_installed() {
    let r = RecordingRunner::new();
    let d = tempfile::tempdir().expect("dir");
    let h = OpenClawHints {
        runs: Some("systemd-user".into()),
        ..OpenClawHints::default()
    };
    // No docker asked when the hint says how it runs, and no CLI anywhere in a fake home.
    let found = discover(&r, &h, d.path(), d.path()).await;
    if found.cli.is_none() {
        assert_eq!(found, Install::not_found(DEFAULT_GATEWAY_PORT));
    }
    assert!(r.calls().iter().all(|c| c.program != "docker"));
}

#[tokio::test]
async fn the_wrapper_is_kept_on_a_miss_and_not_written_by_a_dry_run() {
    let r = RecordingRunner::new();
    let d = tempfile::tempdir().expect("dir");
    let home = d.path().join("home");
    let state = d.path().join("state");
    let h = OpenClawHints {
        cli: Some("/opt/oc/openclaw".into()),
        runs: Some("systemd-user".into()),
        ..OpenClawHints::default()
    };
    let wrapper = wrapper_path(&state);
    // A dry run writes nothing.
    dry_run(&r, &h, &home, &state).await;
    assert!(!wrapper.exists());
    discover(&r, &h, &home, &state).await;
    let first = std::fs::read_to_string(&wrapper).expect("written");
    assert!(first.contains("/opt/oc/openclaw"));
    // One look that finds no CLI keeps the working wrapper.
    let none = OpenClawHints {
        runs: Some("systemd-user".into()),
        ..OpenClawHints::default()
    };
    if find_cli(None, &home).is_none() {
        discover(&r, &none, &home, &state).await;
        assert_eq!(std::fs::read_to_string(&wrapper).expect("kept"), first);
    }
    // No wrapper yet and no CLI: the "not installed" one.
    let other = d.path().join("other");
    if find_cli(None, &home).is_none() {
        discover(&r, &none, &home, &other).await;
        assert_eq!(
            std::fs::read_to_string(wrapper_path(&other)).expect("written"),
            wrapper_script(None)
        );
    }
}

#[tokio::test]
async fn a_dry_run_asks_the_container_directly() {
    // It writes no wrapper, so it cannot ask through one (found with `controlclaw doctor`).
    let r = RecordingRunner::new();
    r.answer(
        &["docker", "ps"],
        ok(r#"{"Image":"ghcr.io/openclaw/openclaw:2026.10.9","Names":"oc-gw","Ports":"0.0.0.0:18789->18789/tcp"}"#),
    );
    r.answer(
        &["docker", "exec", "-i", "oc-gw", "node", "dist/index.js", "--version"],
        ok("OpenClaw 2026.10.9 (8b18b55)\n"),
    );
    r.answer(
        &[
            "docker",
            "exec",
            "-i",
            "oc-gw",
            "node",
            "dist/index.js",
            "config",
            "file",
        ],
        ok(r#"{"path":"/home/node/.openclaw/openclaw.json"}"#),
    );
    r.answer(
        &["docker", "inspect"],
        ok(r#"[{"Source":"/srv/oc/config","Destination":"/home/node/.openclaw"}]"#),
    );
    let d = tempfile::tempdir().expect("dir");
    let found = dry_run(&r, &OpenClawHints::default(), Path::new("/home/u"), d.path()).await;
    assert_eq!(found.version.as_deref(), Some("2026.10.9"));
    assert_eq!(found.config_file.as_deref(), Some("/srv/oc/config/openclaw.json"));
    assert!(!wrapper_path(d.path()).exists());
}
