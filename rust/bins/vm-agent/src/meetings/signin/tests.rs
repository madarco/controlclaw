//! `meeting-signin.test.ts`.

use std::sync::Mutex;

use super::*;

const ACCOUNT: &str = "agent@example.com";

fn listed(rows: &[(&str, i64)]) -> String {
    let rows: Vec<Value> = rows
        .iter()
        .map(|(email, out)| {
            json!([
                "gaia.l.a", 1, "Name", email, "photo", 1, 1, 0, null, 1, "1234", null, null, null, out, 1
            ])
        })
        .collect();
    json!(["gaia.l.a.r", rows]).to_string()
}

#[derive(Default)]
struct World {
    account: Option<String>,
    signed_in: Vec<String>,
    busy: bool,
    log: Vec<String>,
    connected: bool,
    fail: Option<&'static str>,
    accounts_fail: bool,
}

struct Fx {
    _dir: tempfile::TempDir,
    state_path: PathBuf,
    profile_dir: PathBuf,
    w: Arc<Mutex<World>>,
    signin: Arc<MeetingSignin>,
}

fn deps(w: &Arc<Mutex<World>>, state_path: &std::path::Path, profile_dir: &std::path::Path) -> SigninDeps {
    let c = |w: &Arc<Mutex<World>>| w.clone();
    let (a, b, d, e, f, g, h) = (c(w), c(w), c(w), c(w), c(w), c(w), c(w));
    let profile = profile_dir.to_path_buf();
    SigninDeps {
        state_path: state_path.to_path_buf(),
        profile_dir: profile_dir.to_path_buf(),
        account: Arc::new(move || a.lock().expect("w").account.clone()),
        connected: Arc::new(move || b.lock().expect("w").connected),
        window: Arc::new(move |start, url| {
            let mut w = d.lock().expect("w");
            let r = if start && w.fail == Some("window") {
                Err("unit failed".to_string())
            } else {
                w.log.push(if start {
                    format!("window {}", url.unwrap_or_default())
                } else {
                    "window off".into()
                });
                if start {
                    std::fs::create_dir_all(&profile).expect("profile");
                }
                Ok(())
            };
            Box::pin(async move { r })
        }),
        browser: Arc::new(move |start| {
            let mut w = e.lock().expect("w");
            let r = if start && w.fail == Some("browser") {
                Err("no debugger".to_string())
            } else {
                w.log.push(if start { "browser on" } else { "browser off" }.into());
                Ok(())
            };
            Box::pin(async move { r })
        }),
        reserve: Arc::new(move |r| {
            f.lock()
                .expect("w")
                .log
                .push(if r { "reserved" } else { "released" }.into())
        }),
        busy: Arc::new(move || g.lock().expect("w").busy),
        accounts: Arc::new(move || {
            let w = h.lock().expect("w");
            let r = if w.fail == Some("accounts") || w.accounts_fail {
                Err("Google did not answer who is signed in".to_string())
            } else {
                Ok(w.signed_in.clone())
            };
            Box::pin(async move { r })
        }),
        timeout: Duration::from_secs(900),
    }
}

fn fixture(saved: Option<Value>) -> Fx {
    let dir = tempfile::tempdir().expect("dir");
    let state_path = dir.path().join("signin.json");
    let profile_dir = dir.path().join("profile");
    if let Some(s) = saved {
        std::fs::write(&state_path, s.to_string()).expect("write");
        std::fs::create_dir_all(&profile_dir).expect("profile");
    }
    let w = Arc::new(Mutex::new(World {
        account: Some(ACCOUNT.into()),
        signed_in: vec![ACCOUNT.into()],
        connected: true,
        ..Default::default()
    }));
    let signin = MeetingSignin::new(deps(&w, &state_path, &profile_dir));
    Fx {
        _dir: dir,
        state_path,
        profile_dir,
        w,
        signin,
    }
}

impl Fx {
    fn w(&self) -> std::sync::MutexGuard<'_, World> {
        self.w.lock().expect("w")
    }
    fn saved(&self) -> Value {
        serde_json::from_slice(&std::fs::read(&self.state_path).expect("read")).expect("json")
    }
}

fn ready() -> Option<Value> {
    Some(json!({"status": "ready", "email": ACCOUNT}))
}

#[test]
fn googles_account_list() {
    assert_eq!(
        parse_list_accounts(&listed(&[
            ("a@example.com", 0),
            ("gone@example.com", 1),
            ("b@example.com", 0)
        ])),
        Some(vec!["a@example.com".to_string(), "b@example.com".into()])
    );
    assert_eq!(
        parse_list_accounts(&json!(["gaia.l.a.r", []]).to_string()),
        Some(vec![])
    );
    // An error page, a sign-in page or another shape is "not known", never "nobody signed in".
    assert_eq!(parse_list_accounts("<html>Sign in</html>"), None);
    assert_eq!(parse_list_accounts(""), None);
    assert_eq!(
        parse_list_accounts(&json!({"accounts": ["a@example.com"]}).to_string()),
        None
    );
    assert_eq!(parse_list_accounts(&json!(["something.else", []]).to_string()), None);
    assert_eq!(
        signin_url("a+b@example.com"),
        "https://accounts.google.com/AccountChooser?Email=a%2Bb%40example.com&continue=https%3A%2F%2Fmeet.google.com%2F"
    );
}

#[tokio::test]
async fn no_card_without_a_granted_account_and_sign_in_cannot_start() {
    let f = fixture(None);
    f.w().account = None;
    assert_eq!(f.signin.summary(), Value::Null);
    assert!(
        f.signin
            .start()
            .await
            .expect_err("refused")
            .contains("Connect a Google account")
    );
}

#[tokio::test]
async fn sign_in_the_window_opens_with_automation_blocked_done_keeps_the_accounts_session() {
    let f = fixture(None);
    // The window a previous process left is closed first (the TS did it in the constructor).
    drop(f.signin.chain.lock().await);
    assert_eq!(f.w().log, ["window off"]);
    f.w().log.clear();
    assert_eq!(f.signin.start().await.expect("start")["status"], "pending");
    assert_eq!(
        f.w().log,
        ["reserved", "browser off", &format!("window {}", signin_url(ACCOUNT))]
    );
    assert_eq!(f.saved()["status"], "pending");
    assert!(f.signin.pending());
    f.w().log.clear();
    let done = f.signin.finish(false).await.expect("finish");
    assert_eq!(done.get("error"), None);
    assert_eq!(done["signin"]["status"], "ready");
    // The window is closed before a browser with a debugger opens the profile.
    assert_eq!(f.w().log, ["window off", "browser on", "browser off", "released"]);
    assert_eq!(f.saved()["email"], ACCOUNT);
    assert!(f.signin.ready());
    assert!(f.signin.verify().await);
}

#[tokio::test]
async fn another_account_or_none_is_refused_and_the_profile_removed() {
    let f = fixture(None);
    f.signin.start().await.expect("start");
    f.w().signed_in = vec!["owner@example.com".into(), ACCOUNT.into()];
    let other = f.signin.finish(false).await.expect("finish");
    assert_eq!(
        other["error"],
        "That was owner@example.com. Sign in as agent@example.com."
    );
    assert_eq!(other["signin"]["status"], "none");
    assert!(!f.profile_dir.exists());
    f.signin.start().await.expect("start");
    f.w().signed_in = vec![];
    let none = f.signin.finish(false).await.expect("finish");
    assert!(
        none["error"]
            .as_str()
            .expect("error")
            .contains("No Google sign-in was found")
    );
    assert!(!f.profile_dir.exists());
}

#[tokio::test]
async fn a_session_google_ended_is_marked_and_the_join_goes_on_as_a_guest() {
    let f = fixture(Some(
        json!({"status": "ready", "email": ACCOUNT, "signedInAt": "2026-10-10T08:00:00.000Z"}),
    ));
    f.w().signed_in = vec![];
    assert!(!f.signin.verify().await);
    assert_eq!(f.signin.summary()["status"], "expired");
    assert!(!f.signin.ready());
    assert!(f.profile_dir.exists());
    // A failed check changes nothing.
    let g = fixture(ready());
    g.w().accounts_fail = true;
    assert!(!g.signin.verify().await);
    assert_eq!(g.signin.summary()["status"], "ready");
}

#[tokio::test]
async fn the_session_goes_with_the_grant() {
    let f = fixture(ready());
    f.w().busy = true;
    f.w().account = None;
    f.signin.sync();
    assert!(f.profile_dir.exists(), "not under a running meeting");
    f.w().busy = false;
    f.signin.sync();
    assert!(!f.profile_dir.exists());
    assert_eq!(f.saved()["status"], "none");
    let g = fixture(ready());
    g.w().account = Some("other@example.com".into());
    assert_eq!(g.signin.summary()["status"], "none");
    assert!(!g.profile_dir.exists());
}

#[tokio::test]
async fn sign_out_removes_the_profile_not_during_a_meeting() {
    let f = fixture(ready());
    f.w().busy = true;
    assert!(
        f.signin
            .clear()
            .await
            .expect_err("busy")
            .contains("Stop the current meeting")
    );
    assert!(
        f.signin
            .start()
            .await
            .expect_err("busy")
            .contains("Stop the current meeting")
    );
    f.w().busy = false;
    assert_eq!(f.signin.clear().await.expect("clear")["status"], "none");
    assert!(!f.profile_dir.exists());
}

#[tokio::test]
async fn a_sign_in_cut_short_by_a_restart_leaves_no_profile_behind() {
    let f = fixture(Some(json!({"status": "pending"})));
    assert!(!f.profile_dir.exists());
    assert_eq!(f.signin.summary()["status"], "none");
}

#[tokio::test]
async fn a_profile_that_cannot_be_removed_is_reported_on_sign_out_and_never_thrown_into_a_read() {
    let f = fixture(ready());
    // A directory where the state file would be replaced: saving the state fails.
    std::fs::remove_file(&f.state_path).expect("rm");
    std::fs::create_dir_all(f.state_path.join("x")).expect("dir");
    assert!(
        f.signin
            .clear()
            .await
            .expect_err("fails")
            .contains("could not be removed from this agent")
    );
    f.w().account = None;
    f.signin.sync();
    assert_eq!(f.signin.summary(), Value::Null);
}

#[tokio::test]
async fn a_check_that_could_not_be_made_keeps_the_sign_in_open() {
    for fail in ["accounts", "browser"] {
        let f = fixture(None);
        f.signin.start().await.expect("start");
        f.w().fail = Some(fail);
        f.w().log.clear();
        let first = f.signin.finish(false).await.expect("finish");
        assert!(
            first["error"]
                .as_str()
                .expect("e")
                .contains("could not be checked just now. Press Done again")
        );
        assert_eq!(first["signin"]["status"], "pending");
        assert!(f.profile_dir.exists(), "the sign-in the owner just did is kept");
        assert!(
            !f.w().log.contains(&"released".to_string()),
            "automation stays blocked while it is open"
        );
        assert_eq!(f.w().log.last().map(String::as_str), Some("browser off"));
        f.w().fail = None;
        let second = f.signin.finish(false).await.expect("finish");
        assert_eq!(second.get("error"), None);
        assert_eq!(second["signin"]["status"], "ready");
        assert_eq!(f.w().log.last().map(String::as_str), Some("released"));
    }
}

#[tokio::test]
async fn the_window_timing_out_ends_an_unchecked_sign_in() {
    let f = fixture(None);
    f.signin.start().await.expect("start");
    f.w().fail = Some("accounts");
    let ended = f.signin.finish(true).await.expect("finish");
    assert!(
        ended["error"]
            .as_str()
            .expect("e")
            .contains("could not be checked. Sign in again")
    );
    assert_eq!(ended["signin"]["status"], "none");
    assert!(!f.profile_dir.exists());
    assert_eq!(f.w().log.last().map(String::as_str), Some("released"));
}

#[tokio::test]
async fn at_join_google_not_answering_is_not_a_signed_out_session() {
    let f = fixture(ready());
    f.w().fail = Some("accounts");
    assert!(!f.signin.verify().await);
    assert_eq!(f.saved()["status"], "ready");
    f.w().fail = None;
    assert!(f.signin.verify().await);
}

#[tokio::test]
async fn sign_in_is_pending_before_the_window_opens_and_a_failed_start_puts_the_earlier_state_back() {
    let f = fixture(ready());
    let during: Arc<Mutex<String>> = Arc::default();
    let slot: Arc<Mutex<Weak<MeetingSignin>>> = Arc::default();
    let mut d = deps(&f.w, &f.state_path, &f.profile_dir);
    let (dd, s, path) = (during.clone(), slot.clone(), f.state_path.clone());
    // A join arriving here asks pending(): it must already be true.
    d.window = Arc::new(move |start, _| {
        if start {
            let me = s.lock().expect("s").upgrade().expect("signin");
            let saved: Value = serde_json::from_slice(&std::fs::read(&path).expect("read")).expect("json");
            *dd.lock().expect("d") = format!("{} {}", me.pending(), saved["status"].as_str().unwrap_or_default());
            return Box::pin(async { Err("unit failed".to_string()) });
        }
        Box::pin(async { Ok(()) })
    });
    let slow = MeetingSignin::new(d);
    *slot.lock().expect("s") = Arc::downgrade(&slow);
    assert_eq!(slow.start().await, Err("unit failed".into()));
    assert_eq!(*during.lock().expect("d"), "true pending");
    assert!(!slow.pending());
    assert_eq!(f.saved()["status"], "ready");
    assert!(f.profile_dir.exists());
}

#[tokio::test]
async fn a_failing_connection_is_shown_but_does_not_end_the_session() {
    let f = fixture(ready());
    f.w().connected = false;
    let card = f.signin.summary();
    assert_eq!(card["status"], "ready");
    assert_eq!(card["connected"], false);
    assert!(f.profile_dir.exists());
}
