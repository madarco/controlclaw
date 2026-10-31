//! W8: meetings (docs/plans/rust-workstreams/W8.md): joining, the meeting browser, captions,
//! notes, invites and the calendar, the meetings pages.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use cc_http::{BoxFuture, Router};
use futures_util::FutureExt;

use crate::app::App;
use crate::contracts::{BackupHooks, MeetingControl};

/// The meetings archive and caption cleanup (`meeting-notes.ts`).
#[allow(dead_code)] // the meetings service (M3b)
pub mod archive;
/// Meet's captions: the page observer's rows and the context for the voice adapter.
#[allow(dead_code)] // the meetings service (M3b)
pub mod captions;
/// The meeting browser's loopback debugger.
pub mod cdp;
/// What the agent does after a meeting (`meeting-followup.ts`).
pub mod followup;
/// Calendar invites; the schedule (M4) reads them.
#[allow(dead_code)]
pub mod ics;
/// How JavaScript reads strings and numbers.
pub mod js;
/// The voice meeting browser's microphone settings (`meeting-mic.ts`).
#[allow(dead_code)] // the meetings service (M3b)
pub mod mic;
/// What the Meetings page reads (`@controlclaw/meetings/archive`).
pub mod pages;
/// The meetings settings (`@controlclaw/meetings`).
#[allow(dead_code)] // the firewall-side functions are ported and parity-tested with the rest
pub mod policy;
/// Meetings the agent joins by itself (`meeting-schedule.ts`).
pub mod schedule;
/// The JavaScript carried from the TS.
pub mod scripts;
/// The meetings service (`meetings.ts`).
pub mod service;
/// Google sign-in for meetings (`meeting-signin.ts`).
pub mod signin;
/// Where scheduled meetings come from (`meeting-sources.ts`).
pub mod sources;
/// Meeting notes through the notes program (`meeting-summary.ts`).
#[allow(dead_code)] // the meetings service (M3b)
pub mod summary;
/// The voice adapter's log, lease and tasks (`meeting-voice-log.ts`).
#[allow(dead_code)] // the meetings service (M3b)
pub mod voice_log;

/// The Meetings routes (`routes/meetings.ts`).
pub mod routes;

/// The node the notes program runs on (`process.execPath` of the Node build).
const NODE: &str = "/usr/bin/node";

/// The meetings service once the box has OpenClaw's gateway (`meetings`, null without one).
#[derive(Default)]
struct Handle {
    service: OnceLock<Arc<service::MeetingService>>,
    /// Built with the service (`meetingSchedule`, null without one).
    schedule: OnceLock<Arc<schedule::MeetingSchedule>>,
    /// Only on a box whose role has the sign-in window (`meetingSignin`).
    signin: OnceLock<Arc<signin::MeetingSignin>>,
}

impl Handle {
    fn get(&self) -> Option<Arc<service::MeetingService>> {
        self.service.get().cloned()
    }
}

impl MeetingControl for Handle {
    fn busy(&self) -> bool {
        self.get().is_some_and(|s| s.busy())
    }
    fn stop(&self) -> BoxFuture<Result<(), String>> {
        let s = self.get();
        Box::pin(async move {
            match s {
                Some(s) => s.stop().await,
                None => Ok(()),
            }
        })
    }
    fn listed(&self) -> bool {
        self.get().is_some_and(|s| s.metadata()["enabled"] == true)
    }
}

/// What a restore does around the meetings (`beforeRestore`, `sanitizeRestore`, `restoreFinished`).
struct Restore {
    handle: Arc<Handle>,
    tombstones: PathBuf,
}

impl BackupHooks for Restore {
    /// A meeting whose cleanup failed stops the restore ("Retry meeting cleanup before restoring").
    fn before_restore(&self) -> BoxFuture<Result<(), String>> {
        let s = self.handle.get();
        Box::pin(async move {
            match s {
                Some(s) => s.prepare_restore().await,
                None => Ok(()),
            }
        })
    }
    /// Any failure stops the restore before the swap: otherwise meetings the owner deleted would
    /// come back.
    fn sanitize_restore(&self, kind: &str, staging: &Path) -> Result<(), String> {
        let root = if kind == "workspace" {
            staging.join("meetings")
        } else {
            staging.join("workspace").join("meetings")
        };
        let archive = archive::MeetingArchive::new(&root, &self.tombstones);
        let deleted = archive.deleted()?;
        if kind == "state" {
            let ids: Vec<String> = deleted
                .values()
                .filter_map(serde_json::Value::as_array)
                .flatten()
                .filter_map(serde_json::Value::as_str)
                .map(String::from)
                .collect();
            archive::erase_native_meetings(staging, &ids)?;
            if let Some(s) = self.handle.get() {
                s.sanitize_restored_config(staging)?;
            }
        }
        if kind == "workspace" {
            for id in deleted.keys() {
                archive.remove(id)?;
            }
        }
        Ok(())
    }
    fn restore_finished(&self) {
        if let Some(s) = self.handle.get() {
            s.restore_finished();
        }
    }
}

/// `MemTotal` from `/proc/meminfo` (`os.totalmem()`), read once.
fn total_memory() -> u64 {
    static TOTAL: OnceLock<u64> = OnceLock::new();
    *TOTAL.get_or_init(read_total_memory)
}

fn read_total_memory() -> u64 {
    std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|m| {
            m.lines()
                .find_map(|l| l.strip_prefix("MemTotal:"))
                .and_then(|v| v.trim().trim_end_matches("kB").trim().parse::<u64>().ok())
        })
        .map_or(0, |kb| kb * 1024)
}

/// `statfsSync(path)`: blocks free to this user times the block size.
fn free_bytes(path: &Path) -> Option<u64> {
    let s = rustix::fs::statvfs(path).ok()?;
    Some(s.f_bavail.saturating_mul(s.f_frsize))
}

/// `reserveMeetingBrowser`: the marker that blocks the agent's own browser automation.
fn reserve(app: &App) -> Arc<dyn Fn(bool) + Send + Sync> {
    let path = app.config.state_dir.join("meeting-browser-reserved");
    Arc::new(move |on| {
        if on {
            let _ = cc_store::write_file(&path, b"reserved", 0o600);
        } else {
            let _ = std::fs::remove_file(&path);
        }
    })
}

/// `systemctl --user start|stop <unit>` within 15 s (`defaultExec`).
async fn user_unit(runner: &dyn cc_proc::Runner, unit: &str, start: bool) -> Result<(), String> {
    let cmd = cc_proc::Cmd::new("/usr/bin/systemctl")
        .args(["--user", if start { "start" } else { "stop" }, unit])
        .timeout(Duration::from_secs(15));
    match runner.run(cmd).await {
        Ok(out) if out.success() => Ok(()),
        Ok(_) => Err("Command failed: /usr/bin/systemctl".into()),
        Err(e) => Err(e.to_string()),
    }
}

/// The meeting browser (`meetingBrowser` in index.ts): its markers, its unit, and once its debugger
/// answers, the microphone settings for a voice meeting.
fn browser(app: &Arc<App>) -> service::BrowserFn {
    let (runner, state) = (app.runner.clone(), app.config.state_dir.clone());
    let mic: Arc<Mutex<Option<Arc<mic::MeetingMic>>>> = Arc::default();
    Arc::new(move |start, voice, signed_in| {
        let (runner, state, mic) = (runner.clone(), state.clone(), mic.clone());
        Box::pin(async move {
            let marker = |name: &str, on: bool, text: &str| {
                let path = state.join(name);
                if on {
                    let _ = cc_store::write_file(&path, text.as_bytes(), 0o600);
                } else {
                    let _ = std::fs::remove_file(&path);
                }
            };
            marker("meeting-browser-voice", start && voice, "bidi");
            // Read by the unit's launcher: which profile this start uses.
            marker("meeting-browser-signed", start && signed_in, "signed");
            if let Some(m) = mic.lock().unwrap_or_else(|e| e.into_inner()).take() {
                m.close();
            }
            user_unit(runner.as_ref(), "cc-meeting-browser.service", start).await?;
            if !start {
                return Ok(());
            }
            let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
            while tokio::time::Instant::now() < deadline {
                if let Ok(v) = cdp::debugger_json("http://127.0.0.1:9223", "/json/version").await
                    && v.get("webSocketDebuggerUrl").is_some_and(serde_json::Value::is_string)
                {
                    // Before OpenClaw opens Meet: the agent's voice goes out without echo
                    // cancellation or noise suppression, so the chimes are not turned down.
                    if voice {
                        let m = mic::MeetingMic::new();
                        *mic.lock().unwrap_or_else(|e| e.into_inner()) = Some(m.clone());
                        if let Err(e) = m.start().await {
                            tracing::warn!("[meetings] microphone settings not applied: {e}");
                        }
                    }
                    return Ok(());
                }
                // Chrome has started but its loopback debugger is not ready yet.
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            Err("Meeting browser did not become ready".into())
        })
    })
}

/// `POST <origin>/__cc/meetings/media` with the firewall's media token; redirects refused. On the
/// agent's shared client (`app.http`), which trusts the firewall's CA once the bootstrap installed
/// it: a client of its own, built at start-up on a new box, had no CA and failed every join with
/// "error sending request" (UnknownIssuer).
fn media(http: cc_client::HttpClient) -> service::MediaFn {
    Arc::new(move |url, token, body| {
        let client = http.get_no_redirect();
        Box::pin(async move {
            let res = client
                .post(url)
                .bearer_auth(token)
                .json(&body)
                .timeout(Duration::from_secs(10))
                .send()
                .await
                // The URL carries no secret, but the error text never leaves this box anyway.
                .map_err(|e| e.without_url().to_string())?;
            if !res.status().is_success() {
                return Err("Meeting media permission ended".into());
            }
            res.json::<serde_json::Value>()
                .await
                .map_err(|e| e.without_url().to_string())
        })
    })
}

/// What the service needs from the box. The archive and the after-meeting run are shared with the
/// rest, as the TS shares them.
fn deps(
    app: &Arc<App>,
    archive: Arc<archive::MeetingArchive>,
    browser: service::BrowserFn,
    signin: Option<Arc<dyn service::Signin>>,
    follow_up: Option<Arc<dyn service::FollowUp>>,
) -> service::Deps {
    let home = app.config.home.join(".openclaw");
    let state = app.config.state_dir.clone();
    let a = Arc::downgrade(app);
    let writer = {
        let a = a.clone();
        Arc::new(move || a.upgrade()?.contracts.openclaw.get().map(|o| o.config.clone()))
    };
    let runner = app.runner.clone();
    let unit = app.config.service.clone();
    let update = crate::platform::update::state_path(app);
    service::Deps {
        vm_id: app.keys.vm_id().unwrap_or_default(),
        state_path: state.join("meetings.json"),
        archive,
        openclaw_state_dir: home,
        writer,
        browser,
        reserve: reserve(app),
        summarize: {
            let runner = runner.clone();
            Arc::new(move |captions| {
                let runner = runner.clone();
                Box::pin(async move { summary::summarize_meeting(runner.as_ref(), NODE, &captions).await })
            })
        },
        notes_retry: service::NOTES_RETRY
            .iter()
            .map(|m| Duration::from_secs(m * 60))
            .collect(),
        notes_resume: Duration::from_secs(60),
        service: {
            let runner = runner.clone();
            Arc::new(move |action| {
                let (runner, unit) = (runner.clone(), unit.clone());
                // `runAction`: `sudo -n systemctl <action> <unit>` (W6 keeps its own copy private),
                // noted as the agent's own short stop for the watchdog.
                Box::pin(async move {
                    let own = crate::platform::stop_mark::OWN_STOP_MS;
                    crate::platform::stop_mark::STOP_MARK.note(action, Some(own));
                    let cmd = cc_proc::Cmd::sudo("systemctl")
                        .args([action, unit.as_str()])
                        .timeout(Duration::from_secs(90));
                    runner.run(cmd).await.is_ok_and(|o| o.success())
                })
            })
        },
        media: media(app.http.clone()),
        memory_bytes: Arc::new(total_memory),
        free_bytes: Arc::new(free_bytes),
        update_status: Some(Arc::new(move || crate::platform::update::status(&update))),
        gateway_ready: {
            let a = a.clone();
            Arc::new(move |timeout| {
                let o = a.upgrade().and_then(|a| a.contracts.openclaw.get());
                Box::pin(async move {
                    match o {
                        Some(o) => o.client.when_connected(timeout).await,
                        None => true,
                    }
                })
            })
        },
        owner_chat: {
            let a = a.clone();
            Arc::new(move || {
                let channels = a
                    .upgrade()
                    .and_then(|a| a.contracts.platform.get())
                    .and_then(|p| p.channels.get().cloned());
                Box::pin(async move {
                    let approved = match channels {
                        Some(c) => c.approved().await,
                        None => Vec::new(),
                    };
                    let rows: Vec<(String, String, String)> =
                        approved.into_iter().map(|r| (r.kind, r.sender_id, r.at)).collect();
                    voice_log::owner_chat(&rows)
                })
            })
        },
        wake_check: {
            let runner = runner.clone();
            Arc::new(move |words| {
                let runner = runner.clone();
                Box::pin(async move {
                    voice_log::check_wake_names(runner.as_ref(), &words, voice_log::local_wake_installed()).await
                })
            })
        },
        voice_flush: Duration::from_secs(2),
        caption_tap: Arc::new(|url, on| Arc::new(captions::CaptionTap::new(url, on)) as Arc<dyn service::Tap>),
        follow_up,
        signin,
        consult_choices: Some({
            let a = a.clone();
            Arc::new(move || {
                let llm = a
                    .upgrade()
                    .and_then(|a| a.contracts.platform.get())
                    .and_then(|p| p.llm.get().cloned());
                Box::pin(async move {
                    let Some(llm) = llm else { return Ok(Vec::new()) };
                    let status = llm.status().await?;
                    let providers: Vec<String> = status["providers"]
                        .as_array()
                        .map(|p| {
                            p.iter()
                                .filter_map(serde_json::Value::as_str)
                                .map(String::from)
                                .collect()
                        })
                        .unwrap_or_default();
                    let mut listed = serde_json::Map::new();
                    for p in policy::consult_providers()
                        .into_iter()
                        .filter(|p| providers.iter().any(|x| x == p))
                    {
                        let ids: Vec<serde_json::Value> = llm
                            .models(p)
                            .await?
                            .iter()
                            .filter_map(|m| m.get("id").cloned())
                            .collect();
                        listed.insert(p.to_string(), serde_json::Value::Array(ids));
                    }
                    Ok(policy::consult_model_choices(&providers, &listed))
                })
            })
        }),
        poll: Duration::from_secs(5),
        update_wait: service::UPDATE_WAIT,
    }
}

/// The meetings archive and its tombstones: `(~/.openclaw/workspace/meetings, state/meeting-deletions.json)`.
pub fn archive_paths(app: &App) -> (PathBuf, PathBuf) {
    (
        app.config.home.join(".openclaw").join("workspace").join("meetings"),
        app.config.state_dir.join("meeting-deletions.json"),
    )
}

/// The after-meeting run's box side (`MeetingFollowUpService` in index.ts): W7's Gmail wake for the
/// hook, the console's Requests queue (not on a pool box), the meeting's page on this box.
fn follow_up_deps(
    app: &Arc<App>,
    archive: Arc<archive::MeetingArchive>,
    handle: std::sync::Weak<Handle>,
) -> followup::FollowUpDeps {
    let a = Arc::downgrade(app);
    let host = app.keys.read("vm_hostname").filter(|h| !h.is_empty());
    let base = (!app.config.pool_marker.exists())
        .then(|| crate::boxside::saas_base_url(app))
        .flatten();
    let permission = base.map(|base| {
        let url = format!("{base}/api/vm-agent/permission");
        let (console, console2, url2) = (app.console.clone(), app.console.clone(), url.clone());
        let post: followup::PostFn = Arc::new(move |body| {
            let (console, url) = (console.clone(), url.clone());
            Box::pin(async move {
                let answer = console.post_json(&url, &body, Duration::from_secs(15)).await.ok()?;
                // Not JSON (`res.json()` throws) is no answer; JSON without a status is pending.
                if !(200..300).contains(&answer.status) || !answer.body.is_object() {
                    return None;
                }
                Some(
                    answer
                        .body
                        .get("status")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("pending")
                        .to_string(),
                )
            })
        });
        let status: followup::StatusFn = Arc::new(move |id| {
            let (console, url) = (console2.clone(), url2.clone());
            Box::pin(async move {
                let target = format!(
                    "{url}?permission_id={}",
                    crate::boxside::shell::encode_uri_component(&id)
                );
                let answer = console.get_json(&target, Duration::from_secs(15)).await.ok()?;
                if !(200..300).contains(&answer.status) {
                    return None;
                }
                answer
                    .body
                    .get("status")
                    .and_then(serde_json::Value::as_str)
                    .map(String::from)
            })
        });
        (post, status)
    });
    // The box's shared redactor (reloaded when its secrets change), else one loaded here.
    let own = Arc::new(crate::boxside::logs::Redaction::load(&app.config.keys_dir));
    let shared = Arc::downgrade(app);
    let (h1, h2) = (handle.clone(), handle);
    followup::FollowUpDeps {
        archive,
        workspace: app.config.home.join(".openclaw").join("workspace"),
        state_path: app.config.state_dir.join("meeting-orders.json"),
        hooks: Arc::new(move || {
            a.upgrade()
                .and_then(|a| a.contracts.gmail_wake.get())
                .map(|w| Arc::new(w) as Arc<dyn followup::Hooks>)
        }),
        enabled: Arc::new(move || h1.upgrade().and_then(|h| h.get()).is_some_and(|s| s.follow_up_on())),
        names: Arc::new(move || {
            h2.upgrade()
                .and_then(|h| h.get())
                .map(|s| s.wake_names())
                .unwrap_or_default()
        }),
        page_url: Arc::new(move |id| host.as_ref().map(|h| format!("https://{h}/__cc/meetings/{id}"))),
        permission,
        redact: Arc::new(move |t| {
            let logs = shared
                .upgrade()
                .and_then(|a| a.contracts.access.get())
                .and_then(|a| a.logs.get().cloned());
            match logs {
                Some(l) => l.redaction.redact(t),
                None => own.redact(t),
            }
        }),
    }
}

/// The sign-in window's unit; older boxes keep the guest join.
const SIGNIN_UNIT: &str = "/etc/systemd/user/cc-meeting-signin.service";

/// The sign-in's box side: the window's unit and the page it opens, the meeting browser on the
/// signed-in profile, W7's Google grant.
fn signin_deps(app: &Arc<App>, browser: service::BrowserFn, handle: std::sync::Weak<Handle>) -> signin::SigninDeps {
    let state = app.config.state_dir.clone();
    let (a1, a2) = (Arc::downgrade(app), Arc::downgrade(app));
    let runner = app.runner.clone();
    signin::SigninDeps {
        state_path: state.join("meeting-signin.json"),
        profile_dir: state.join("meeting-profile"),
        account: Arc::new(move || {
            a1.upgrade()
                .and_then(|a| a.contracts.google.get())
                .and_then(|g| g.account())
        }),
        connected: Arc::new(move || {
            a2.upgrade()
                .and_then(|a| a.contracts.google.get())
                .is_some_and(|g| g.connected())
        }),
        window: Arc::new(move |start, url| {
            let (runner, path) = (runner.clone(), state.join("meeting-signin-url"));
            Box::pin(async move {
                // The launcher opens exactly this page; without the file it does not start.
                match url.filter(|_| start) {
                    Some(u) => cc_store::write_file(&path, u.as_bytes(), 0o600).map_err(|e| e.to_string())?,
                    None => {
                        let _ = std::fs::remove_file(&path);
                    }
                }
                user_unit(runner.as_ref(), "cc-meeting-signin.service", start).await
            })
        }),
        browser: Arc::new(move |start| browser(start, false, true)),
        reserve: reserve(app),
        busy: Arc::new(move || handle.upgrade().is_some_and(|h| h.busy())),
        accounts: Arc::new(|| Box::pin(signin::signed_in_accounts("http://127.0.0.1:9223"))),
        timeout: Duration::from_secs(15 * 60),
    }
}

/// `(inbox, token)` of the agent's own AgentMail inbox: the placeholder from OpenClaw's `.env`, the
/// inbox from W7's AgentMail status or else OpenClaw's config.
fn mailbox(app: &App) -> Option<(String, String)> {
    let home = app.config.home.join(".openclaw");
    let token = sources::env_file(&home.join(".env"))
        .remove("AGENTMAIL_API_KEY")
        .filter(|t| !t.is_empty())?;
    let from_status = app
        .contracts
        .agentmail
        .get()
        .and_then(|a| a.status())
        .and_then(|s| s.get("inboxId").cloned())
        .filter(|v| crate::phone::model::truthy(Some(v)));
    let inbox = from_status.or_else(|| {
        let raw = std::fs::read(home.join("openclaw.json")).ok()?;
        let config: serde_json::Value = serde_json::from_slice(&raw).ok()?;
        config.pointer("/channels/agentmail/inboxId").cloned()
    })?;
    Some((inbox.as_str().filter(|i| !i.is_empty())?.to_string(), token))
}

/// The connected Google account for the calendar: its placeholder and address, when the box's
/// Google grant includes the calendar (`state/gog.env`).
fn calendar_account(app: &App) -> Option<(String, Option<String>)> {
    let mut env = sources::env_file(&app.config.state_dir.join("gog.env"));
    let token = env.remove("GOG_ACCESS_TOKEN").filter(|t| !t.is_empty())?;
    let services = env.remove("CC_GOOGLE_SERVICES").unwrap_or_default();
    services
        .split(',')
        .any(|s| s == "calendar")
        .then(|| (token, env.remove("CC_GOOGLE_ACCOUNT")))
}

fn schedule_deps(app: &Arc<App>, service: Arc<service::MeetingService>) -> schedule::ScheduleDeps {
    let http = sources::Http::new(app.http.clone());
    let (a1, a2) = (Arc::downgrade(app), Arc::downgrade(app));
    let (s1, s2, s3, s4, s5) = (
        service.clone(),
        service.clone(),
        service.clone(),
        service.clone(),
        service,
    );
    let mail_http = http.clone();
    schedule::ScheduleDeps {
        state_path: app.config.state_dir.join("meeting-schedule.json"),
        settings: Arc::new(move || s1.auto_join()),
        busy: Arc::new(move || s2.busy()),
        join: Arc::new(move |url, auto, leave_at| {
            let s = s3.clone();
            Box::pin(async move {
                s.join_scheduled(&url, auto, leave_at).await.map_err(|e| match e {
                    service::MeetingError::AutoJoinRefused(r) => schedule::JoinFailed {
                        refusal: Some(r),
                        message: "Automatic join refused".into(),
                    },
                    service::MeetingError::Failed(m) => schedule::JoinFailed {
                        refusal: None,
                        message: m,
                    },
                })
            })
        }),
        admit: Arc::new(move |auto| {
            let s = s4.clone();
            Box::pin(async move { s.admit(&auto).await.map_err(|e| e.to_string()) })
        }),
        leave: Arc::new(move |id| {
            let s = s5.clone();
            Box::pin(async move { s.stop_scheduled(&id).await })
        }),
        mail: Some(Arc::new(move |cursor| {
            let (http, mailbox) = (mail_http.clone(), a1.upgrade().and_then(|a| mailbox(&a)));
            Box::pin(async move {
                sources::read_invite_mail(&http, mailbox, cursor.as_deref(), crate::platform::time::now_ms()).await
            })
        })),
        calendar: Some(Arc::new(move |from, to, mode| {
            let app = a2.upgrade();
            let account = app.as_ref().and_then(|a| calendar_account(a));
            let agent = app.as_ref().and_then(|a| mailbox(a)).map(|m| m.0);
            let http = http.clone();
            Box::pin(async move { sources::read_calendar(&http, account, agent, from, to, &mode).await })
        })),
        now: Arc::new(crate::platform::time::now_ms),
    }
}

/// The schedule's timers (`setInterval`): a tick every 30 s, invite mail every minute, the
/// calendar every five, and both once 20 s after start.
fn start_schedule(schedule: Arc<schedule::MeetingSchedule>) {
    let every =
        |s: Arc<schedule::MeetingSchedule>, period: u64, step: fn(Arc<schedule::MeetingSchedule>) -> BoxFuture<()>| {
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(period)).await;
                loop {
                    step(s.clone()).await;
                    tokio::time::sleep(Duration::from_secs(period)).await;
                }
            });
        };
    every(schedule.clone(), 30, |s| Box::pin(async move { s.tick().await }));
    every(schedule.clone(), 60, |s| Box::pin(async move { s.sync_email().await }));
    every(schedule.clone(), 300, |s| {
        Box::pin(async move { s.sync_calendar().await })
    });
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(20)).await;
        let first = async {
            schedule.sync_email().await;
            schedule.sync_calendar().await;
        };
        if std::panic::AssertUnwindSafe(first).catch_unwind().await.is_err() {
            tracing::error!("[meetings] schedule: a step stopped unexpectedly");
        }
    });
}

pub fn register(router: &mut Router, app: &Arc<App>) {
    let handle = Arc::new(Handle::default());
    // A test may have put a fake there first.
    if app.contracts.meeting.get().is_none() {
        app.contracts.meeting.set(handle.clone());
    }
    // A restore always scrubs deleted meetings, with or without the service.
    app.contracts.backup_hooks.set(Arc::new(Restore {
        handle: handle.clone(),
        tombstones: archive_paths(app).1,
    }));
    let (h, hs, hg) = (handle.clone(), handle.clone(), handle.clone());
    routes::register(
        router,
        Arc::new(routes::Context {
            app: app.clone(),
            service: Arc::new(move || h.get()),
            schedule: Arc::new(move || hs.schedule.get().cloned()),
            signin: Arc::new(move || hg.signin.get().cloned()),
        }),
    );
    // The service needs OpenClaw's gateway, which W6 connects once the agent listens: built as
    // soon as it is there (the TS builds it when `client` exists, and not on a box without one).
    if tokio::runtime::Handle::try_current().is_err() {
        return;
    }
    let a = Arc::downgrade(app);
    tokio::spawn(async move {
        // However long that takes: a box without a gateway token never fills the slot, and then
        // this looks once a second, as cheaply as the TS's null service costs nothing.
        for n in 0u32.. {
            let Some(app) = a.upgrade() else { return };
            if app.contracts.openclaw.get().is_some() {
                // One meeting browser (and its microphone settings) for the service and the sign-in.
                let browser = browser(&app);
                let signin = std::path::Path::new(SIGNIN_UNIT).exists().then(|| {
                    handle
                        .signin
                        .get_or_init(|| {
                            signin::MeetingSignin::new(signin_deps(&app, browser.clone(), Arc::downgrade(&handle)))
                        })
                        .clone()
                });
                let archive = {
                    let (root, tombstones) = archive_paths(&app);
                    Arc::new(archive::MeetingArchive::new(&root, &tombstones))
                };
                let follow_up = followup::MeetingFollowUpService::new(follow_up_deps(
                    &app,
                    archive.clone(),
                    Arc::downgrade(&handle),
                ));
                let service = handle
                    .service
                    .get_or_init(|| {
                        service::MeetingService::new(deps(
                            &app,
                            archive,
                            browser,
                            signin.clone().map(|s| s as Arc<dyn service::Signin>),
                            Some(follow_up.clone() as Arc<dyn service::FollowUp>),
                        ))
                    })
                    .clone();
                // Requests from a meeting raised in the console's queue, and its answers taken.
                tokio::spawn(async move {
                    loop {
                        tokio::time::sleep(followup::REQUEST_POLL).await;
                        if std::panic::AssertUnwindSafe(follow_up.tick())
                            .catch_unwind()
                            .await
                            .is_err()
                        {
                            tracing::error!("[meeting-followup] a tick stopped unexpectedly");
                        }
                    }
                });
                if let Some(s) = signin {
                    // A grant that went away takes the session with it, after each Google apply.
                    if let Some(google) = app.contracts.google.get() {
                        let s2 = s.clone();
                        google.on_applied(Arc::new(move || s2.sync()));
                    }
                    s.sync();
                }
                let schedule = handle
                    .schedule
                    .get_or_init(|| schedule::MeetingSchedule::new(schedule_deps(&app, service.clone())))
                    .clone();
                drop(app);
                start_schedule(schedule);
                // The default model for meetings follows the agent's providers: resolved again a
                // little after start and every ten minutes.
                tokio::time::sleep(Duration::from_secs(90)).await;
                loop {
                    if let Err(e) = service.refresh_consult().await {
                        tracing::error!("[meetings] model for meetings not refreshed: {}", js::head16(&e, 200));
                    }
                    tokio::time::sleep(Duration::from_secs(600)).await;
                }
            }
            drop(app);
            tokio::time::sleep(Duration::from_millis(if n < 600 { 100 } else { 1000 })).await;
        }
    });
}

#[cfg(test)]
mod restore_tests {
    use super::*;
    use serde_json::json;

    /// `sanitizeRestore` throws when it cannot scrub, so the restore stops before the swap.
    #[tokio::test]
    async fn a_scrub_that_cannot_run_stops_the_restore() {
        let dir = tempfile::tempdir().expect("dir");
        let tombstones = dir.path().join("meeting-deletions.json");
        let restore = Restore {
            handle: Arc::new(Handle::default()),
            tombstones: tombstones.clone(),
        };
        // No service yet: nothing to stop, the restore goes on.
        assert_eq!(restore.before_restore().await, Ok(()));
        let staging = dir.path().join("staging");
        std::fs::create_dir_all(staging.join("meetings")).expect("dir");
        // A meeting deleted before the backup is taken out of the restored workspace.
        let id = "0f8e2b1a-1c2d-4e5f-8a9b-0c1d2e3f4a5b";
        std::fs::write(
            staging.join("meetings").join(format!("{id}.json")),
            json!({"id": id, "startedAt": "2026-10-01T10:00:00.000Z", "state": "complete", "transcript": []})
                .to_string(),
        )
        .expect("write");
        std::fs::write(&tombstones, json!({id: []}).to_string()).expect("write");
        assert_eq!(restore.sanitize_restore("workspace", &staging), Ok(()));
        assert!(!staging.join("meetings").join(format!("{id}.json")).exists());
        // A list of deleted meetings that cannot be read stops the restore.
        std::fs::write(&tombstones, "{not json").expect("write");
        assert!(restore.sanitize_restore("workspace", &staging).is_err());
        assert!(restore.sanitize_restore("state", &staging).is_err());
    }
}
