//! `backup.test.ts`, against a fake object store (presigned URLs are paths on a loopback server),
//! and the archives the TS build sealed (`fixtures/ts-sealed`).

use std::collections::{BTreeMap, HashMap};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::sync::{Arc, Mutex};

use cc_proc::{RecordingRunner, exit, ok};
use serde_json::json;

use super::*;
use crate::boxside::testing::serve;

const KEY: &str = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=";

#[derive(Clone, Default)]
struct Store {
    objects: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    refuse_put: Arc<Mutex<bool>>,
}

async fn store() -> (Store, String) {
    let s = Store::default();
    let st = s.clone();
    let mut r = cc_http::Router::new(&["all"]);
    r.prefix("all", "/", move |req, _| {
        let st = st.clone();
        async move {
            let path = req.uri().path().to_string();
            if req.method() == http::Method::PUT {
                if *st.refuse_put.lock().expect("lock") {
                    return cc_http::empty(403);
                }
                use http_body_util::BodyExt;
                let body = req
                    .into_body()
                    .collect()
                    .await
                    .map(|b| b.to_bytes().to_vec())
                    .unwrap_or_default();
                st.objects.lock().expect("lock").insert(path, body);
                return cc_http::empty(200);
            }
            match st.objects.lock().expect("lock").get(&path) {
                Some(b) => cc_http::full(http::StatusCode::OK, "application/octet-stream", b.clone()),
                None => cc_http::empty(404),
            }
        }
    });
    (s, serve(r).await)
}

#[derive(Default)]
struct Hooks {
    calls: Mutex<Vec<String>>,
    fail_before: Mutex<bool>,
    fail_sanitize: Mutex<bool>,
}

impl crate::contracts::BackupHooks for Hooks {
    fn before_restore(&self) -> BoxFuture<Result<(), String>> {
        self.calls.lock().expect("lock").push("before".into());
        let fail = *self.fail_before.lock().expect("lock");
        Box::pin(async move {
            if fail {
                Err("Retry meeting cleanup before restoring".into())
            } else {
                Ok(())
            }
        })
    }
    fn sanitize_restore(&self, kind: &str, staging: &Path) -> Result<(), String> {
        self.calls.lock().expect("lock").push(format!("sanitize {kind}"));
        if *self.fail_sanitize.lock().expect("lock") {
            return Err("Could not read meeting deletions".into());
        }
        // A tombstoned meeting is scrubbed from the staged tree before it goes live.
        let _ = std::fs::remove_file(staging.join("meetings/deleted.json"));
        Ok(())
    }
    fn restore_finished(&self) {
        self.calls.lock().expect("lock").push("finished".into());
    }
}

struct Box_ {
    _dir: tempfile::TempDir,
    home: PathBuf,
    svc: BackupService,
    runner: RecordingRunner,
    hooks: Arc<Hooks>,
}

fn make(with_hooks: bool) -> Box_ {
    let dir = tempfile::tempdir().expect("dir");
    let home = dir.path().join(".openclaw");
    std::fs::create_dir_all(&home).expect("home");
    let runner = RecordingRunner::new();
    runner.answer(&["sudo", "systemctl"], ok(""));
    let hooks = Arc::new(Hooks::default());
    let h: Arc<dyn crate::contracts::BackupHooks> = hooks.clone();
    let mut svc = BackupService::new(
        home.clone(),
        dir.path().join("spool"),
        Arc::new(runner.clone()),
        cc_client::HttpClient::new(true).expect("http"),
        "openclaw".into(),
    );
    if with_hooks {
        svc = svc.with_hooks(Arc::new(move || Some(h.clone())));
    }
    Box_ {
        _dir: dir,
        home,
        svc,
        runner,
        hooks,
    }
}

fn seed(home: &Path) {
    let ws = home.join("workspace");
    std::fs::create_dir_all(ws.join("notes")).expect("d");
    std::fs::create_dir_all(ws.join("node_modules/x")).expect("d");
    std::fs::create_dir_all(ws.join("meetings")).expect("d");
    std::fs::write(ws.join("notes/a.md"), "# notes\n").expect("w");
    std::fs::write(ws.join("node_modules/x/i.js"), "skip").expect("w");
    std::fs::write(ws.join("meetings/deleted.json"), "{}").expect("w");
    std::fs::write(ws.join("run.sh"), "echo\n").expect("w");
    std::fs::set_permissions(ws.join("run.sh"), std::fs::Permissions::from_mode(0o755)).expect("chmod");
    // A link whose target does not fit tar's 100-byte field.
    symlink(format!("{}/target", "t".repeat(120)), ws.join("long-link")).expect("link");
    std::fs::write(home.join("openclaw.json"), "{}").expect("w");
    std::fs::write(home.join("openclaw_gateway_token"), "secret-token").expect("w");
    std::fs::create_dir_all(home.join("logs")).expect("d");
    std::fs::write(home.join("logs/x.log"), "l").expect("w");
    std::fs::create_dir_all(home.join("extensions/google-meet")).expect("d");
    std::fs::write(home.join("extensions/google-meet/pinned.js"), "pinned").expect("w");
}

/// Path → `dir:mode`, `file:mode:size` or `link:target`, as the fixture script lists a tree.
fn tree(root: &Path) -> BTreeMap<String, String> {
    fn walk(root: &Path, rel: &str, out: &mut BTreeMap<String, String>) {
        let dir = if rel.is_empty() {
            root.to_path_buf()
        } else {
            root.join(rel)
        };
        let mut names: Vec<String> = std::fs::read_dir(&dir)
            .map(|rd| {
                rd.flatten()
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        for n in names {
            let r = if rel.is_empty() { n } else { format!("{rel}/{n}") };
            let m = std::fs::symlink_metadata(root.join(&r)).expect("meta");
            if m.file_type().is_symlink() {
                let t = std::fs::read_link(root.join(&r)).expect("link");
                out.insert(r, format!("link:{}", t.display()));
            } else if m.is_dir() {
                out.insert(r.clone(), format!("dir:{:o}", m.permissions().mode() & 0o777));
                walk(root, &r, out);
            } else {
                out.insert(r, format!("file:{:o}:{}", m.permissions().mode() & 0o777, m.len()));
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, "", &mut out);
    out
}

fn run_input(kind: &str, url: &str) -> RunInput {
    RunInput {
        org_id: "org_1".into(),
        vm_id: "vm_1".into(),
        backup_id: "bk_1".into(),
        kind: kind.into(),
        data_key: KEY.into(),
        upload_url: url.into(),
    }
}

fn restore_input(r: &Value, kind: &str, url: &str) -> RestoreInput {
    RestoreInput {
        org_id: "org_1".into(),
        vm_id: "vm_1".into(),
        backup_id: "bk_1".into(),
        kind: kind.into(),
        data_key: KEY.into(),
        header: r["header"].as_str().expect("header").into(),
        manifest_hash: r["manifestHash"].as_str().expect("hash").into(),
        download_url: url.into(),
        source_vm_id: None,
    }
}

#[tokio::test]
async fn the_plans_leave_out_what_is_not_content() {
    let b = make(true);
    seed(&b.home);
    let ws = b.svc.plan("workspace").await.expect("plan");
    let paths: Vec<&str> = ws.manifest.entries.iter().map(|e| e.path.as_str()).collect();
    assert!(paths.contains(&"notes/a.md") && !paths.iter().any(|p| p.starts_with("node_modules")));
    assert_eq!(ws.manifest.excluded, vec![("node_modules".to_string(), 4)]);
    let state = b.svc.plan("state").await.expect("plan");
    let paths: Vec<&str> = state.manifest.entries.iter().map(|e| e.path.as_str()).collect();
    assert!(paths.contains(&"openclaw.json"));
    for gone in ["workspace", "logs", "openclaw_gateway_token"] {
        assert!(!paths.iter().any(|p| p.starts_with(gone)), "{gone}");
    }
    assert!(b.svc.plan("firewall").await.is_err());
    assert!(b.svc.plan("gbrain").await.is_err());
}

#[tokio::test]
async fn a_backup_is_sealed_uploaded_and_restored_over_a_changed_tree() {
    let (st, url) = store().await;
    let b = make(true);
    seed(&b.home);
    let r = b
        .svc
        .run(&run_input("workspace", &format!("{url}/obj")))
        .await
        .expect("run");
    assert_eq!(r["kind"], "workspace");
    let blob = st.objects.lock().expect("lock").get("/obj").cloned().expect("uploaded");
    assert_eq!(r["cipherBytes"], blob.len());
    assert!(!blob.windows(7).any(|w| w == b"# notes"), "no plaintext in the store");
    // The spool is gone.
    assert_eq!(
        std::fs::read_dir(b._dir.path().join("spool")).expect("spool").count(),
        0
    );

    let before = tree(&b.home.join("workspace"));
    std::fs::write(b.home.join("workspace/notes/a.md"), "changed").expect("w");
    std::fs::write(b.home.join("workspace/new.txt"), "new").expect("w");
    let out = b
        .svc
        .restore(&restore_input(&r, "workspace", &format!("{url}/obj")))
        .await
        .expect("restore");
    assert_eq!(out["restarted"], true);
    let mut want = before;
    want.remove("node_modules");
    want.remove("node_modules/x");
    want.remove("node_modules/x/i.js");
    want.remove("meetings/deleted.json");
    assert_eq!(tree(&b.home.join("workspace")), want);
    assert_eq!(
        std::fs::read_to_string(b.home.join("workspace/notes/a.md")).expect("r"),
        "# notes\n"
    );
    assert_eq!(
        *b.hooks.calls.lock().expect("lock"),
        ["before", "sanitize workspace", "finished"]
    );
    let calls: Vec<String> = b.runner.calls().iter().map(|c| c.args.join(" ")).collect();
    assert_eq!(calls, ["systemctl stop openclaw", "systemctl start openclaw"]);
    // Nothing left beside the target.
    let leftovers: Vec<_> = std::fs::read_dir(&b.home)
        .expect("rd")
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().contains(".cc-"))
        .collect();
    assert!(leftovers.is_empty());
}

#[tokio::test]
async fn restoring_state_keeps_the_workspace_and_the_identity() {
    let (_st, url) = store().await;
    let b = make(true);
    seed(&b.home);
    let r = b.svc.run(&run_input("state", &format!("{url}/s"))).await.expect("run");
    std::fs::write(b.home.join("workspace/notes/after.md"), "made after").expect("w");
    std::fs::write(b.home.join("openclaw.json"), "{\"changed\":1}").expect("w");
    b.svc
        .restore(&restore_input(&r, "state", &format!("{url}/s")))
        .await
        .expect("restore");
    assert_eq!(std::fs::read_to_string(b.home.join("openclaw.json")).expect("r"), "{}");
    assert!(
        b.home.join("workspace/notes/after.md").exists(),
        "the workspace is not state's"
    );
    assert_eq!(
        std::fs::read_to_string(b.home.join("openclaw_gateway_token")).expect("r"),
        "secret-token"
    );
    assert!(b.home.join("extensions/google-meet/pinned.js").exists());
}

#[tokio::test]
async fn a_restore_that_cannot_be_verified_or_is_cut_short_changes_nothing() {
    let (st, url) = store().await;
    let b = make(true);
    seed(&b.home);
    let r = b
        .svc
        .run(&run_input("workspace", &format!("{url}/o")))
        .await
        .expect("run");
    std::fs::write(b.home.join("workspace/notes/a.md"), "mine").expect("w");
    let mut wrong = restore_input(&r, "workspace", &format!("{url}/o"));
    wrong.manifest_hash = "0".repeat(64);
    assert_eq!(
        b.svc.restore(&wrong).await.expect_err("mismatch"),
        "This backup does not match what was recorded for it. Nothing was restored."
    );
    let blob = st.objects.lock().expect("lock").get("/o").cloned().expect("blob");
    st.objects
        .lock()
        .expect("lock")
        .insert("/cut".into(), blob[..blob.len() - 30].to_vec());
    assert_eq!(
        b.svc
            .restore(&restore_input(&r, "workspace", &format!("{url}/cut")))
            .await
            .expect_err("cut"),
        cc_crypto::envelope::TRUNCATED
    );
    let mut other = restore_input(&r, "workspace", &format!("{url}/o"));
    other.backup_id = "bk_2".into();
    assert_eq!(
        b.svc.restore(&other).await.expect_err("other backup"),
        cc_crypto::envelope::WRONG_KEY
    );
    assert_eq!(
        b.svc
            .restore(&restore_input(&r, "workspace", &format!("{url}/missing")))
            .await
            .expect_err("404"),
        "The backup store would not serve this archive (HTTP 404)."
    );
    assert_eq!(
        std::fs::read_to_string(b.home.join("workspace/notes/a.md")).expect("r"),
        "mine"
    );
    assert!(b.runner.calls().is_empty(), "OpenClaw was never stopped");
}

#[tokio::test]
async fn no_restore_without_the_meetings_scrub_or_when_openclaw_will_not_stop() {
    let (_st, url) = store().await;
    let b = make(false);
    seed(&b.home);
    let r = b
        .svc
        .run(&run_input("workspace", &format!("{url}/o")))
        .await
        .expect("run");
    let e = b
        .svc
        .restore(&restore_input(&r, "workspace", &format!("{url}/o")))
        .await
        .expect_err("no hooks");
    assert!(e.contains("meetings service is not ready"), "{e}");
    assert!(b.runner.calls().is_empty(), "OpenClaw was never stopped");

    // With the scrub in place, an OpenClaw that will not stop is no restore either.
    let runner = RecordingRunner::new();
    runner.answer(&["sudo", "systemctl", "stop"], exit(1, ""));
    runner.answer(&["sudo", "systemctl"], ok(""));
    let h: Arc<dyn crate::contracts::BackupHooks> = Arc::new(Hooks::default());
    let svc = BackupService::new(
        b.home.clone(),
        b._dir.path().join("spool"),
        Arc::new(runner),
        cc_client::HttpClient::new(true).expect("http"),
        "openclaw".into(),
    )
    .with_hooks(Arc::new(move || Some(h.clone())));
    std::fs::write(b.home.join("workspace/notes/a.md"), "mine").expect("w");
    assert_eq!(
        svc.restore(&restore_input(&r, "workspace", &format!("{url}/o")))
            .await
            .expect_err("no stop"),
        "Could not stop the archive writer before restore"
    );
    assert_eq!(
        std::fs::read_to_string(b.home.join("workspace/notes/a.md")).expect("r"),
        "mine"
    );

    // A meetings scrub that fails stops the restore with its own words. Before the stop: nothing
    // was stopped. In the scrub: OpenClaw is started again and nothing was swapped.
    for before in [true, false] {
        let runner = RecordingRunner::new();
        runner.answer(&["sudo", "systemctl"], ok(""));
        let hooks = Arc::new(Hooks::default());
        *hooks.fail_before.lock().expect("l") = before;
        *hooks.fail_sanitize.lock().expect("l") = !before;
        let h: Arc<dyn crate::contracts::BackupHooks> = hooks.clone();
        let svc = BackupService::new(
            b.home.clone(),
            b._dir.path().join("spool"),
            Arc::new(runner.clone()),
            cc_client::HttpClient::new(true).expect("http"),
            "openclaw".into(),
        )
        .with_hooks(Arc::new(move || Some(h.clone())));
        let e = svc
            .restore(&restore_input(&r, "workspace", &format!("{url}/o")))
            .await
            .expect_err("scrub failed");
        let verbs: Vec<String> = runner.calls().iter().filter_map(|c| c.args.get(1).cloned()).collect();
        if before {
            assert_eq!(e, "Retry meeting cleanup before restoring");
            assert!(verbs.is_empty(), "nothing stopped: {verbs:?}");
        } else {
            assert_eq!(e, "Could not read meeting deletions");
            assert_eq!(verbs, ["stop", "start"]);
        }
        assert_eq!(
            std::fs::read_to_string(b.home.join("workspace/notes/a.md")).expect("r"),
            "mine"
        );
    }
}

/// An archive whose second entry goes through a link the first one made is refused, and nothing
/// lands outside staging (`a` → elsewhere, then `a\\x`, read as `a/x`).
#[test]
fn a_restore_never_writes_through_a_link_it_made() {
    let dir = tempfile::tempdir().expect("dir");
    let (staging, outside) = (dir.path().join("staging"), dir.path().join("outside"));
    std::fs::create_dir_all(&staging).expect("d");
    std::fs::create_dir_all(&outside).expect("d");
    let mut u = Untar {
        reader: TarReader::default(),
        into: &staging,
        manifest: None,
        entries: 0,
        plain: 0,
        dirs: Vec::new(),
        error: None,
    };
    let entry = |path: &str, kind: TarType, target: Option<&str>, body: &[u8]| super::super::archive::ReadEntry {
        entry: TarEntry {
            path: path.into(),
            kind,
            size: body.len() as u64,
            mode: 0o644,
            mtime: 0,
            target: target.map(str::to_string),
        },
        body: body.to_vec(),
    };
    u.place(entry("a", TarType::Link, Some(outside.to_str().expect("utf8")), b""))
        .expect("link");
    let e = u
        .place(entry("a\\x", TarType::File, None, b"planted"))
        .expect_err("refused");
    assert!(e.contains("through a link"), "{e}");
    assert!(u.place(entry("a/y/z", TarType::File, None, b"planted")).is_err());
    assert!(u.place(entry("a", TarType::File, None, b"planted")).is_err());
    assert_eq!(
        std::fs::read_dir(&outside).expect("rd").count(),
        0,
        "nothing written outside"
    );
}

/// A file swapped for a link between the walk and the tar is not archived from where it points.
#[test]
fn a_file_swapped_for_a_link_after_the_walk_is_not_read() {
    let dir = tempfile::tempdir().expect("dir");
    let root = dir.path().join("ws");
    std::fs::create_dir_all(root.join("x")).expect("d");
    std::fs::write(root.join("x/key"), "harmless").expect("w");
    let plan = plan_blocking(&root, "workspace").expect("plan");
    let secret = dir.path().join("keys");
    std::fs::create_dir_all(&secret).expect("d");
    std::fs::write(secret.join("key"), "SECRETKEY").expect("w");
    std::fs::remove_dir_all(root.join("x")).expect("rm");
    symlink(&secret, root.join("x")).expect("link");
    let mut tar = Vec::new();
    write_tar(&root, &plan.manifest, &plan.inodes, &mut tar).expect("tar");
    assert!(
        !tar.windows(9).any(|w| w == b"SECRETKEY"),
        "the key must not be in the archive"
    );
}

#[tokio::test]
async fn a_refused_upload_fails_the_backup_and_leaves_nothing_behind() {
    let (st, url) = store().await;
    *st.refuse_put.lock().expect("lock") = true;
    let b = make(true);
    seed(&b.home);
    assert_eq!(
        b.svc
            .run(&run_input("workspace", &format!("{url}/o")))
            .await
            .expect_err("refused"),
        "The backup store refused the upload (HTTP 403)."
    );
    assert_eq!(
        std::fs::read_dir(b._dir.path().join("spool")).expect("spool").count(),
        0
    );
    // A store that is not there says so without its URL.
    let e = b
        .svc
        .run(&run_input(
            "workspace",
            "http://127.0.0.1:9/presigned?X-Amz-Signature=secret",
        ))
        .await
        .expect_err("down");
    assert_eq!(e, "fetch failed");
}

#[tokio::test]
async fn two_backups_at_once_are_refused() {
    let b = make(true);
    let _busy = b.svc.take_busy("workspace of vm_1".into()).expect("first");
    let e = b
        .svc
        .run(&run_input("workspace", "https://store.example/x"))
        .await
        .expect_err("busy");
    assert_eq!(
        e,
        "This agent is already backing up or restoring (workspace of vm_1). Wait for that to finish."
    );
}

#[test]
fn the_limit_names_the_biggest_directories() {
    let plan = Plan {
        kind: "workspace".into(),
        root: "/x".into(),
        manifest: Manifest {
            kind: "workspace".into(),
            taken_at: String::new(),
            root: String::new(),
            entries: Vec::new(),
            total_bytes: 0,
            excluded: Vec::new(),
            extra: Map::new(),
        },
        plain_bytes: 6 * 1024 * 1024 * 1024,
        largest: vec![
            ("browser".into(), 3 * 1024 * 1024 * 1024 + 512 * 1024 * 1024),
            ("empty".into(), 0),
        ],
        inodes: Default::default(),
    };
    assert_eq!(
        BackupService::over_limit(&plan),
        "This agent's workspace is 6 GB, over the 5 GB limit for one backup. The biggest directories are browser (3.5 GB). Move or delete what you do not need, or ask us to enable large backups."
    );
    assert_eq!(bytes_line(0), "0 B");
    assert_eq!(bytes_line(1536), "1.5 KB");
}

#[test]
fn the_route_validates_what_it_is_given() {
    let base = json!({"orgId": "org_1", "vmId": "vm_1", "backupId": "bk_1", "kind": "workspace", "dataKey": KEY,
        "uploadUrl": "https://s.example/p", "downloadUrl": "https://s.example/g", "header": "A".repeat(32), "manifestHash": "a".repeat(64)});
    let with = |k: &str, v: Value| {
        let mut m = base.as_object().expect("obj").clone();
        m.insert(k.into(), v);
        m
    };
    let run_err = |m: Map<String, Value>| parse_run(&m, AGENT_KINDS).err();
    let restore_err = |m: Map<String, Value>| parse_restore(&m, AGENT_KINDS).err();
    assert!(parse_run(base.as_object().expect("obj"), AGENT_KINDS).is_ok());
    assert!(parse_restore(base.as_object().expect("obj"), AGENT_KINDS).is_ok());
    assert_eq!(
        run_err(with("kind", json!("firewall"))).as_deref(),
        Some("kind must be workspace or state")
    );
    assert_eq!(
        run_err(with("vmId", json!("../x"))).as_deref(),
        Some("vmId is required")
    );
    assert_eq!(
        run_err(with("dataKey", json!("short"))).as_deref(),
        Some("dataKey is required")
    );
    assert_eq!(
        run_err(with("uploadUrl", json!("http://s.example/p"))).as_deref(),
        Some("uploadUrl must be an https URL")
    );
    assert_eq!(
        run_err(with("orgId", json!("o".repeat(65)))).as_deref(),
        Some("orgId is required")
    );
    assert_eq!(
        restore_err(with("header", json!("x"))).as_deref(),
        Some("header is required")
    );
    assert_eq!(
        restore_err(with("manifestHash", json!("A".repeat(64)))).as_deref(),
        Some("manifestHash is required")
    );
    assert_eq!(
        restore_err(with("sourceVmId", json!("bad id"))).as_deref(),
        Some("sourceVmId must be a vm id")
    );
    assert_eq!(
        parse_restore(&with("sourceVmId", json!("vm_2")), AGENT_KINDS)
            .expect("ok")
            .source_vm_id
            .as_deref(),
        Some("vm_2")
    );
    assert_eq!(
        parse_run(&with("kind", json!("gbrain")), &["gbrain"])
            .map(|r| r.kind)
            .ok()
            .as_deref(),
        Some("gbrain")
    );
}

fn fixture_dir(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src/boxside/fixtures")
        .join(name)
}

/// What the TS build sealed (`fixtures/backup.mts seal`), restored by this build.
#[tokio::test]
async fn an_archive_the_ts_build_sealed_restores_here() {
    let dir = fixture_dir("ts-sealed");
    let meta: Value = serde_json::from_slice(&std::fs::read(dir.join("meta.json")).expect("meta")).expect("json");
    let want: BTreeMap<String, String> =
        serde_json::from_slice(&std::fs::read(dir.join("tree.json")).expect("tree")).expect("json");
    let (st, url) = store().await;
    st.objects
        .lock()
        .expect("lock")
        .insert("/ts".into(), std::fs::read(dir.join("blob.bin")).expect("blob"));
    let b = make(true);
    let input = RestoreInput {
        org_id: meta["orgId"].as_str().expect("s").into(),
        vm_id: meta["vmId"].as_str().expect("s").into(),
        backup_id: meta["backupId"].as_str().expect("s").into(),
        kind: "workspace".into(),
        data_key: meta["dataKey"].as_str().expect("s").into(),
        header: meta["header"].as_str().expect("s").into(),
        manifest_hash: meta["manifestHash"].as_str().expect("s").into(),
        download_url: format!("{url}/ts"),
        source_vm_id: None,
    };
    b.svc.restore(&input).await.expect("restore");
    assert_eq!(tree(&b.home.join("workspace")), want);
}

/// Writes `fixtures/rust-sealed` for `backup.mts restore` (the other direction). Run by hand:
/// `cargo test -p vm-agent write_rust_sealed_fixture -- --ignored`.
#[tokio::test]
#[ignore]
async fn write_rust_sealed_fixture() {
    let (st, url) = store().await;
    let b = make(true);
    let ws = b.home.join("workspace");
    std::fs::create_dir_all(ws.join("notes/deep")).expect("d");
    std::fs::create_dir_all(ws.join("empty")).expect("d");
    std::fs::write(ws.join("notes/a.md"), "# hello\n").expect("w");
    std::fs::write(ws.join("notes/deep/b.txt"), "b".repeat(70_000)).expect("w");
    std::fs::write(ws.join("run.sh"), "echo hi\n").expect("w");
    std::fs::set_permissions(ws.join("run.sh"), std::fs::Permissions::from_mode(0o755)).expect("chmod");
    symlink("notes/a.md", ws.join("link.md")).expect("link");
    let r = b
        .svc
        .run(&run_input("workspace", &format!("{url}/rs")))
        .await
        .expect("run");
    let dir = fixture_dir("rust-sealed");
    std::fs::create_dir_all(&dir).expect("dir");
    let blob = st.objects.lock().expect("lock").get("/rs").cloned().expect("blob");
    std::fs::write(dir.join("blob.bin"), blob).expect("w");
    let meta = json!({"orgId": "org_1", "vmId": "vm_1", "backupId": "bk_1", "kind": "workspace", "dataKey": KEY,
        "header": r["header"], "manifestHash": r["manifestHash"], "entries": r["entries"]});
    std::fs::write(
        dir.join("meta.json"),
        format!("{}\n", serde_json::to_string_pretty(&meta).expect("json")),
    )
    .expect("w");
    std::fs::write(
        dir.join("tree.json"),
        format!("{}\n", serde_json::to_string_pretty(&tree(&ws)).expect("json")),
    )
    .expect("w");
}

#[tokio::test]
async fn the_upload_carries_its_length_and_is_never_chunked() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    // A raw listener, so the request head is what went on the wire.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let server = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.expect("accept");
        let mut got = Vec::new();
        let mut buf = [0u8; 65536];
        loop {
            let n = s.read(&mut buf).await.expect("read");
            got.extend_from_slice(&buf[..n]);
            if let Some(end) = got.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&got[..end]).to_lowercase();
                if n == 0 || got.len() - end - 4 >= 300_000 {
                    let _ = s.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n").await;
                    return (head, got.len() - end - 4);
                }
            }
        }
    });
    let dir = tempfile::tempdir().expect("dir");
    let file = dir.path().join("archive");
    std::fs::write(&file, vec![7u8; 300_000]).expect("w");
    let svc = BackupService::new(
        dir.path().to_path_buf(),
        dir.path().join("spool"),
        Arc::new(RecordingRunner::new()),
        cc_client::HttpClient::new(true).expect("http"),
        "openclaw".into(),
    );
    svc.put(&format!("http://127.0.0.1:{port}/o?X-Amz-Signature=s"), &file, 300_000)
        .await
        .expect("put");
    let (head, body) = server.await.expect("server");
    assert!(head.contains("content-length: 300000"), "{head}");
    assert!(!head.contains("transfer-encoding"), "{head}");
    assert_eq!(body, 300_000);
}
