//! `gbrain-backup.test.ts`: fixed verbs, fixed paths, and what a failure says.

use cc_proc::{Output, RecordingRunner, ok};

use super::*;

fn staged(runner: RecordingRunner, dir: &std::path::Path) -> BrainStaged {
    let runner: Arc<dyn cc_proc::Runner> = Arc::new(runner);
    let deps = Deps {
        writer: Arc::new(|| None),
        runner: runner.clone(),
        home: std::path::PathBuf::from("/tmp"),
        restart: Arc::new(|| Box::pin(async { Ok(()) })),
        log: Arc::new(|_| {}),
        bin: crate::platform::common::OPENCLAW_BIN.to_string(),
        unit_down: None,
    };
    BrainStaged::new(deps, Arc::new(BrainGate::new(&dir.join("gate.json"), runner)))
}

#[tokio::test]
async fn the_helper_runs_with_fixed_verbs_and_a_failure_says_what_could_not_be_done() {
    let dir = tempfile::tempdir().expect("dir");
    let runner = RecordingRunner::new();
    runner.answer(&["sudo", HELPER], ok(""));
    let s = staged(runner.clone(), dir.path());
    assert_eq!(s.kind(), "gbrain");
    assert_eq!(BRAIN_KINDS, [s.kind()], "the route takes the staged kind, and only it");
    assert_eq!(s.root(), PathBuf::from("/opt/controlclaw/state/gbrain-backup/stage"));
    assert_eq!(
        s.restore_dir(),
        PathBuf::from("/opt/controlclaw/state/gbrain-backup/restoring")
    );
    s.prepare().await.expect("stage");
    s.release().await.expect("clean");
    s.apply(s.restore_dir()).await.expect("restore");
    let verbs: Vec<Vec<String>> = runner.calls().iter().map(|c| c.args.clone()).collect();
    assert_eq!(
        verbs,
        [[HELPER, "stage"], [HELPER, "clean"], [HELPER, "restore"]].map(|v| v.map(String::from).to_vec())
    );

    let failing = RecordingRunner::new();
    failing.answer(
        &["sudo", HELPER],
        Output {
            code: Some(1),
            stderr: b"pg_dump: error: connection refused\n".to_vec(),
            ..Default::default()
        },
    );
    let err = staged(failing, dir.path()).prepare().await.expect_err("fails");
    assert!(err.starts_with("could not copy the brain for its backup: "), "{err}");
    assert!(err.contains("connection refused"), "{err}");
}

/// After the helper has loaded the backup, the connected agents get new tokens: the restored
/// database has the backup's token table.
#[tokio::test]
async fn a_restore_reissues_the_connected_agents_tokens_after_the_load() {
    let dir = tempfile::tempdir().expect("dir");
    let runner = RecordingRunner::new();
    runner.answer(&["sudo", HELPER], ok(""));
    runner.answer(
        &["sudo", "/usr/local/bin/cc-gbrain-token", "create"],
        ok(&format!("gbrain_{}\n", "a".repeat(40))),
    );
    let s = staged(runner.clone(), dir.path());
    s.gate
        .connect(&super::super::gate::ConnectInput {
            vm_id: "vm_1".into(),
            ip: "10.0.0.5".into(),
            scope: "read".into(),
        })
        .await
        .expect("connect");
    let before = runner.calls().len();
    s.apply(s.restore_dir()).await.expect("restore");
    let after: Vec<Vec<String>> = runner.calls()[before..].iter().map(|c| c.args.clone()).collect();
    assert_eq!(after[0], [HELPER, "restore"], "the load first");
    assert!(
        after[1..]
            .iter()
            .any(|a| a.get(1).map(String::as_str) == Some("create")),
        "then a new token: {after:?}"
    );
}
