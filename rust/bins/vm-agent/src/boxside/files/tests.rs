//! `files.test.ts`: the parts a conformance case cannot set up (symlinks, a deny list inside the
//! root, small caps, the activity lines), through a real server.

use std::os::unix::fs::{PermissionsExt, symlink};
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};

use super::*;
use crate::boxside::testing::{TestBox, client, serve, session_cookie, test_box};

struct Files {
    b: TestBox,
    root: PathBuf,
    url: String,
    writes: Arc<Mutex<Vec<FilesWrite>>>,
}

async fn files_box(limits: FilesLimits) -> Files {
    let b = test_box();
    let root = b.dir.path().join("home");
    std::fs::create_dir_all(&root).expect("root");
    let writes = Arc::new(Mutex::new(Vec::new()));
    let w = writes.clone();
    // The deny list names a folder INSIDE the root, so the tests are about the list, not
    // containment.
    let service = Arc::new(
        FilesService::new(root.clone(), Some("vm_1".into()))
            .with_denied(vec![root.join("keys")])
            .with_limits(limits)
            .on_write(Arc::new(move |x| w.lock().expect("lock").push(x))),
    );
    let access = crate::boxside::access(&b.app, None);
    let mut router = cc_http::Router::new(&["prefixed"]);
    router.prefix("prefixed", "/files/", move |req, _| {
        let (s, a) = (service.clone(), access.clone());
        async move { handle(&s, &a, req).await }
    });
    let url = serve(router).await;
    Files { b, root, url, writes }
}

impl Files {
    fn req(&self, method: reqwest::Method, path: &str, write: bool) -> reqwest::RequestBuilder {
        client()
            .request(method, format!("{}{path}", self.url))
            .header("origin", "https://box.example")
            .header("cookie", session_cookie(write))
    }

    async fn get(&self, path: &str) -> (u16, Value) {
        let r = self.req(reqwest::Method::GET, path, true).send().await.expect("get");
        let status = r.status().as_u16();
        (status, r.json().await.unwrap_or(Value::Null))
    }

    async fn post(&self, path: &str, body: impl Into<reqwest::Body>) -> (u16, Value) {
        let r = self
            .req(reqwest::Method::POST, path, true)
            .body(body)
            .send()
            .await
            .expect("post");
        let status = r.status().as_u16();
        (status, r.json().await.unwrap_or(Value::Null))
    }

    async fn op(&self, path: &str, body: Value) -> (u16, Value) {
        self.post(path, body.to_string()).await
    }
}

#[test]
fn pure_helpers_path_normalisation_and_content_types() {
    assert_eq!(normalize_relative(Some("../../etc/passwd")), "etc/passwd");
    assert_eq!(normalize_relative(Some("/etc/passwd")), "etc/passwd");
    assert_eq!(normalize_relative(Some("a/./b/../c")), "a/c");
    assert_eq!(normalize_relative(Some("a\\..\\..\\b")), "b");
    assert_eq!(normalize_relative(None), "");
    assert_eq!(normalize_relative(Some("notes/\0secret")), "notes/secret");
    assert_eq!(mime_for("notes.MD"), "text/markdown");
    assert_eq!(mime_for(".bashrc"), "text/plain");
    assert_eq!(mime_for("blob.bin"), "application/octet-stream");
    assert_eq!(mime_for(".env"), "text/plain");
    assert_eq!(mime_for(".env.local"), "text/plain");
    assert_eq!(mime_for("shot.png"), "image/png");
    assert_eq!(mime_for("Dockerfile"), "text/plain");
    assert!(is_textual("image/svg+xml"));
    assert!(!is_textual("image/png"));
    assert_eq!(human_bytes(999), "999 B");
    assert_eq!(human_bytes(4200), "4.2 kB");
    assert_eq!(human_bytes(1_048_576), "1.0 MB");
    assert_eq!(human_bytes(104_857_600), "105 MB");
    assert_eq!(thousands(10_000), "10,000");
    assert_eq!(
        content_disposition("ré\"po\u{1F600}.txt"),
        "attachment; filename=\"r__po__.txt\"; filename*=UTF-8''r%C3%A9%22po%F0%9F%98%80.txt"
    );
}

#[test]
fn names_sort_as_people_read_them() {
    let mut v = vec!["b10", "b2", "B1", "_x", ".env", "a", "é", "z"];
    v.sort_by(|a, b| locale_compare(a, b));
    assert_eq!(v, vec!["_x", ".env", "a", "B1", "b2", "b10", "é", "z"]);
}

#[tokio::test]
async fn a_denied_dir_that_does_not_exist_yet_is_still_denied_once_it_does_under_a_symlinked_parent() {
    let tmp = tempfile::tempdir().expect("tmp");
    std::fs::create_dir(tmp.path().join("real-home")).expect("mkdir");
    symlink(tmp.path().join("real-home"), tmp.path().join("home")).expect("link");
    let via_link = realpath_lenient(&tmp.path().join("home/keys/deep")).await;
    let via_real = realpath_lenient(&tmp.path().join("real-home/keys/deep")).await;
    assert_eq!(via_link, via_real);

    let f = files_box(FilesLimits::default()).await;
    assert_eq!(f.get("/files/list?path=").await.0, 200);
    std::fs::create_dir(f.root.join("keys")).expect("keys");
    assert_eq!(f.get("/files/list?path=keys").await.0, 403);
    assert_eq!(
        f.post("/files/write?path=keys%2Fauthorized", "ssh-ed25519 AAAA")
            .await
            .0,
        403
    );
    assert!(!f.root.join("keys/authorized").exists());
}

#[tokio::test]
async fn the_path_guard_dot_dots_absolute_paths_a_symlink_out_of_the_root_and_the_keys_dir() {
    let f = files_box(FilesLimits::default()).await;
    let outside = f.b.dir.path().join("outside.txt");
    std::fs::write(&outside, "the box's own business").expect("w");
    std::fs::create_dir(f.root.join("keys")).expect("keys");
    std::fs::write(f.root.join("keys/gateway_token"), "s3cret").expect("w");
    symlink(&outside, f.root.join("escape.txt")).expect("link");
    symlink(f.b.dir.path(), f.root.join("escape-dir")).expect("link");
    std::fs::write(f.root.join("notes.md"), "# hi").expect("w");

    for p in ["..%2F..%2Fetc%2Fpasswd", "%2Fetc%2Fpasswd", "..%252f..%252fetc"] {
        assert_eq!(f.get(&format!("/files/read?path={p}")).await.0, 404, "{p}");
    }
    assert_eq!(f.get("/files/list?path=..%2F..%2F..").await.1["path"], "");
    let (s, b) = f.get("/files/read?path=escape.txt").await;
    assert_eq!((s, b["code"].as_str()), (403, Some("outside_root")));
    assert_eq!(f.get("/files/list?path=escape-dir").await.0, 403);
    assert_eq!(f.get("/files/download?path=escape.txt").await.0, 403);
    let (s, b) = f.get("/files/list?path=keys").await;
    assert_eq!((s, b["code"].as_str()), (403, Some("denied")));
    assert_eq!(f.get("/files/read?path=keys/gateway_token").await.0, 403);
    assert_eq!(f.op("/files/mkdir", json!({"path": "keys/new"})).await.0, 403);
    let (s, b) = f.get("/files/read?path=").await;
    assert_eq!((s, b["code"].as_str()), (400, Some("is_a_directory")));
}

#[tokio::test]
async fn list_folders_first_hidden_files_included_a_blocked_symlink_flagged() {
    let f = files_box(FilesLimits::default()).await;
    std::fs::write(f.root.join("zebra.txt"), "z").expect("w");
    std::fs::write(f.root.join("alpha.txt"), "a").expect("w");
    std::fs::create_dir(f.root.join("workspace")).expect("d");
    std::fs::create_dir(f.root.join(".openclaw")).expect("d");
    std::fs::write(f.root.join(".openclaw/openclaw.json"), "{}").expect("w");
    symlink("/etc", f.root.join("etc-link")).expect("link");
    std::fs::write(f.root.join("target.txt"), "t").expect("w");
    symlink(f.root.join("target.txt"), f.root.join("inner-link")).expect("link");

    let (_, body) = f.get("/files/list").await;
    let names: Vec<&str> = body["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .filter_map(|e| e["name"].as_str())
        .collect();
    assert_eq!(
        names,
        [
            ".openclaw",
            "workspace",
            "alpha.txt",
            "etc-link",
            "inner-link",
            "target.txt",
            "zebra.txt"
        ]
    );
    let e = |n: &str| {
        body["entries"]
            .as_array()
            .and_then(|a| a.iter().find(|e| e["name"] == n).cloned())
            .expect("entry")
    };
    assert_eq!(e("etc-link")["symlink"], true);
    assert_eq!(e("etc-link")["blocked"], true);
    assert_eq!(e("etc-link")["kind"], "other");
    assert_eq!(e("inner-link")["kind"], "file");
    assert_eq!(e("inner-link")["size"], 1);
    assert!(e("inner-link").get("blocked").is_none());
    assert_eq!(e("alpha.txt")["size"], 1);
    assert!(
        regex::Regex::new("^0[0-7]{3}$")
            .expect("re")
            .is_match(e("alpha.txt")["mode"].as_str().unwrap_or_default())
    );
}

#[tokio::test]
async fn list_says_so_when_a_folder_has_more_entries_than_it_will_return() {
    let f = files_box(FilesLimits {
        list_max_entries: 3,
        ..FilesLimits::default()
    })
    .await;
    for i in 0..5 {
        std::fs::write(f.root.join(format!("f{i}.txt")), "x").expect("w");
    }
    let (_, body) = f.get("/files/list").await;
    assert_eq!(body["entries"].as_array().map(Vec::len), Some(3));
    assert_eq!(body["truncated"], true);
    // The first three by name, as Node's readdir hands them.
    assert_eq!(body["entries"][2]["name"], "f2.txt");
}

#[tokio::test]
async fn read_text_its_cap_an_image_streamed_and_anything_else_as_metadata() {
    let f = files_box(FilesLimits {
        text_preview_bytes: 32,
        image_preview_bytes: 64,
        ..FilesLimits::default()
    })
    .await;
    std::fs::write(f.root.join("long.txt"), "x".repeat(100)).expect("w");
    std::fs::write(f.root.join("big.png"), vec![0u8; 100]).expect("w");
    std::fs::write(f.root.join("cut.txt"), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\u{e9}").expect("w");
    let (_, b) = f.get("/files/read?path=long.txt").await;
    assert_eq!(b["truncated"], true);
    assert_eq!(b["content"].as_str().map(str::len), Some(32));
    let (_, b) = f.get("/files/read?path=big.png").await;
    assert_eq!(
        (b["kind"].as_str(), b["reason"].as_str()),
        (Some("binary"), Some("too_large"))
    );
    // A character cut at the cap becomes U+FFFD.
    let (_, b) = f.get("/files/read?path=cut.txt").await;
    assert_eq!(b["content"].as_str().map(|c| c.ends_with('\u{fffd}')), Some(true));
}

#[tokio::test]
async fn upload_is_atomic_refuses_to_overwrite_unless_asked_and_is_capped() {
    let f = files_box(FilesLimits {
        upload_max_bytes: 10,
        ..FilesLimits::default()
    })
    .await;
    let (s, b) = f.post("/files/upload?path=big.bin", vec![1u8; 11]).await;
    assert_eq!((s, b["error"].as_str()), (413, Some("Files are limited to 10 B.")));
    assert!(!f.root.join("big.bin").exists());
    // No spool file is left behind.
    let leftovers: Vec<_> = std::fs::read_dir(&f.root)
        .expect("rd")
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with(".cc-"))
        .collect();
    assert!(leftovers.is_empty());
    assert_eq!(f.post("/files/upload?path=a.bin", vec![1u8; 10]).await.0, 200);
    assert_eq!(std::fs::read(f.root.join("a.bin")).expect("read").len(), 10);
}

#[tokio::test]
async fn write_keeps_the_mode_and_is_capped_at_the_preview_size() {
    let f = files_box(FilesLimits {
        text_preview_bytes: 8,
        ..FilesLimits::default()
    })
    .await;
    let script = f.root.join("run.sh");
    std::fs::write(&script, "echo").expect("w");
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    let (s, b) = f.post("/files/write?path=run.sh", "echo 2").await;
    assert_eq!(s, 200, "{b}");
    assert_eq!(
        std::fs::metadata(&script).expect("m").permissions().mode() & 0o777,
        0o755
    );
    let (s, b) = f.post("/files/write?path=new.txt&create=1", "").await;
    assert_eq!(s, 200, "{b}");
    assert_eq!(
        std::fs::metadata(f.root.join("new.txt"))
            .expect("m")
            .permissions()
            .mode()
            & 0o777,
        0o644
    );
    // The mtime the answer gives is the one the next save must send.
    let mtime = b["mtime"].as_str().expect("mtime").to_string();
    assert_eq!(
        f.post(&format!("/files/write?path=new.txt&mtime={mtime}"), "x").await.0,
        200
    );
    let (s, b) = f.post("/files/write?path=run.sh", "123456789").await;
    assert_eq!(
        (s, b["error"].as_str()),
        (
            413,
            Some("The editor saves files up to 8 B. Download this one, change it, and upload it back.")
        )
    );
    // Saving onto a symlink is refused, not turned into a file.
    symlink(f.root.join("new.txt"), f.root.join("link.txt")).expect("link");
    assert_eq!(f.post("/files/write?path=link.txt", "x").await.1["code"], "not_a_file");
}

#[tokio::test]
async fn delete_unlinks_a_symlink_and_caps_a_recursive_delete() {
    let f = files_box(FilesLimits {
        recursive_delete_max_entries: 2,
        ..FilesLimits::default()
    })
    .await;
    let outside = f.b.dir.path().join("keep");
    std::fs::create_dir(&outside).expect("d");
    std::fs::write(outside.join("x"), "x").expect("w");
    symlink(&outside, f.root.join("link")).expect("link");
    assert_eq!(f.op("/files/delete", json!({"path": "link"})).await.0, 200);
    assert!(outside.join("x").exists(), "the target stays");
    std::fs::create_dir_all(f.root.join("big/a/b/c")).expect("d");
    let (s, b) = f.op("/files/delete", json!({"path": "big", "recursive": true})).await;
    assert_eq!(
        (s, b["error"].as_str()),
        (
            413,
            Some("That folder holds more than 2 items. Delete it from the agent's terminal instead.")
        )
    );
    assert!(f.root.join("big").exists());
}

#[tokio::test]
async fn every_write_and_only_a_write_produces_one_activity_line() {
    let f = files_box(FilesLimits::default()).await;
    std::fs::write(f.root.join("a.txt"), "aa").expect("w");
    f.get("/files/list").await;
    f.get("/files/read?path=a.txt").await;
    f.post("/files/upload?path=b.txt", "bbb").await;
    f.op("/files/mkdir", json!({"path": "d"})).await;
    f.op("/files/rename", json!({"from": "b.txt", "to": "d/b.txt"})).await;
    f.op("/files/delete", json!({"path": "a.txt"})).await;
    f.op("/files/delete", json!({"path": "d", "recursive": true})).await;
    // A member's refused write is not one.
    let r = f
        .req(reqwest::Method::POST, "/files/mkdir", false)
        .body(json!({"path": "x"}).to_string())
        .send()
        .await
        .expect("post");
    assert_eq!(r.status(), 403);
    let writes = f.writes.lock().expect("lock").clone();
    let w = |op, path: &str, size| FilesWrite {
        op,
        path: path.into(),
        size,
    };
    assert_eq!(
        writes,
        vec![
            w("upload", "b.txt", Some(3)),
            w("mkdir", "d", None),
            w("rename", "b.txt → d/b.txt", None),
            w("delete", "a.txt", Some(2)),
            w("delete", "d", None),
        ]
    );
}
