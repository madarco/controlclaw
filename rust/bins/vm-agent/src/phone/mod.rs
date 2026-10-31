//! W8: phone calls (docs/plans/rust-workstreams/W8.md): the voice-call plugin's install and
//! patches, the calls pages, call history and the `/phone/stream` relay.

use std::sync::Arc;

use cc_http::{FirewallBody, FirewallRequest, ReadBody, Router, firewall_request, send_json};
use serde_json::{Value, json};

use crate::app::App;
use crate::contracts::{AgentPages, CallSession, ExportRecords, PhoneControl};
use crate::stages;

pub mod apply;
pub mod compat;
pub mod history;
/// The phone reply model; W6's `/llm/apply` calls `model::phone_model_entry`.
pub mod model;
pub mod page;
pub mod setup;
pub mod stream;

use history::{PhoneCallLog, PluginCallStore};
use setup::PhoneService;
use stream::Relay;

/// What the phone parts share.
pub struct Phone {
    pub service: Arc<PhoneService>,
    /// The call history's notes; the calls pages read them.
    pub log: Arc<PhoneCallLog>,
    /// The voice-call plugin's own call records.
    pub calls: Arc<PluginCallStore>,
    pub relay: Arc<Relay>,
    /// The plugin's records as last read, and when; the read runs off the runtime's threads.
    seen: Arc<std::sync::Mutex<Seen>>,
}

/// What the last read of the plugin's records found.
#[derive(Default)]
struct Seen {
    in_progress: bool,
    any: bool,
    at: Option<std::time::Instant>,
    reading: bool,
    /// Bumped by every change to the records (a delete): a read that started before it is stale
    /// when it finishes, and is not kept.
    generation: u64,
}

impl Phone {
    /// The last read's findings; a new read starts on a blocking thread when that one is older
    /// than a few seconds, since SQLite can wait on the plugin's lock for seconds.
    fn seen(&self) -> (bool, bool) {
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        // Never read yet, or the records changed since: read now, so the page lists what is there.
        if seen.at.is_none() {
            let generation = seen.generation;
            *seen = Self::read_seen(&self.calls, generation);
        }
        let stale = seen.at.is_none_or(|at| at.elapsed() > IN_CALL_FRESH);
        if stale && !seen.reading && tokio::runtime::Handle::try_current().is_ok() {
            seen.reading = true;
            let generation = seen.generation;
            let (calls, slot) = (self.calls.clone(), self.seen.clone());
            tokio::task::spawn_blocking(move || {
                let fresh = Self::read_seen(&calls, generation);
                let mut seen = slot.lock().unwrap_or_else(|e| e.into_inner());
                if seen.generation == generation {
                    *seen = fresh;
                } else {
                    // The records changed while this read ran: it may show a call already gone.
                    seen.reading = false;
                }
            });
        }
        (seen.in_progress, seen.any)
    }

    fn read_seen(calls: &PluginCallStore, generation: u64) -> Seen {
        let now = history::now_ms() as f64;
        let list = calls.calls().unwrap_or_default();
        Seen {
            in_progress: list.iter().any(|c| history::call_in_progress(c, now)),
            any: !list.is_empty(),
            at: Some(std::time::Instant::now()),
            reading: false,
            generation,
        }
    }

    /// The records changed (a delete): what was read before, or is being read now, no longer
    /// counts, and the next question reads them again.
    pub fn forget_seen(&self) {
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        seen.generation += 1;
        seen.at = None;
    }
}

/// How old the cached answer may be before a new read starts.
const IN_CALL_FRESH: std::time::Duration = std::time::Duration::from_secs(5);

impl PhoneControl for Phone {
    fn relay_busy(&self) -> bool {
        self.relay.busy()
    }

    /// `phoneCalls.calls().some(callInProgress)`; false when the records cannot be read.
    fn call_in_progress(&self) -> bool {
        self.seen().0
    }

    fn call_sessions(&self, now_ms: i64, lookback_ms: i64) -> Vec<CallSession> {
        call_sessions(
            &self.calls.calls().unwrap_or_default(),
            now_ms as f64,
            lookback_ms as f64,
        )
    }
}

/// `callSessions` (`session-shipper.ts`): answered calls started within the lookback, with when
/// they were answered and, once over, when they ended. `answeredAt !== undefined` is the TS's
/// test, so a null `answeredAt` counts as answered (from the start then).
fn call_sessions(calls: &[Value], now: f64, lookback: f64) -> Vec<CallSession> {
    use history::num;
    calls
        .iter()
        .filter_map(|c| {
            let started = num(c, "startedAt").filter(|s| now - s <= lookback)?;
            c.get("answeredAt")?;
            let answered = num(c, "answeredAt");
            let ended = (!history::call_in_progress(c, now)).then(|| num(c, "endedAt").or(answered).unwrap_or(started));
            Some(CallSession {
                call_id: c.get("callId").and_then(Value::as_str)?.to_string(),
                started_at: answered.unwrap_or(started) as i64,
                ended_at: ended.map(|e| e as i64),
            })
        })
        .collect()
}

/// Which optional pages the shared shell lists (`setShellNav`): meetings when they are on, calls
/// when a number is active or calls are on record.
struct Pages(Arc<Phone>, std::sync::Weak<App>);

impl AgentPages for Pages {
    fn meetings_listed(&self) -> bool {
        self.1
            .upgrade()
            .and_then(|a| a.contracts.meeting.get())
            .is_some_and(|m| m.listed())
    }
    fn phone_listed(&self) -> bool {
        self.0.service.active() || self.0.seen().1
    }
}

/// Meetings and calls for Download workspace. The meeting archive is read here rather than through
/// the meetings service, which exists only once the gateway is up; a download should not need it.
struct Records {
    phone: Arc<Phone>,
    meetings: std::path::PathBuf,
    tombstones: std::path::PathBuf,
}

impl ExportRecords for Records {
    fn meetings(&self) -> Vec<Value> {
        if !self.meetings.exists() {
            return Vec::new();
        }
        crate::meetings::archive::MeetingArchive::new(&self.meetings, &self.tombstones)
            .list()
            .unwrap_or_default()
    }
    /// `phoneCalls.calls().map((c) => callDetail(c, phoneCallLog))`.
    fn calls(&self) -> Vec<Value> {
        let now = history::now_ms() as f64;
        self.phone
            .calls
            .calls()
            .unwrap_or_default()
            .iter()
            .map(|c| Value::Object(history::call_detail(c, &self.phone.log, &[], now)))
            .collect()
    }
}

pub fn register(router: &mut Router, app: &Arc<App>) {
    let log = Arc::new(PhoneCallLog::open(&app.config.state_dir.join("phone-calls.json")));
    // The notes are written on a thread of their own, in the order they come: a save renames a
    // file and syncs it, which must not hold up the threads relaying the calls' audio.
    let (notes, queue) = std::sync::mpsc::channel::<(String, history::StreamPatch)>();
    let writer = log.clone();
    std::thread::Builder::new()
        .name("phone-call-log".into())
        .spawn(move || {
            for (sid, patch) in queue {
                writer.stream(&sid, &patch);
            }
        })
        .expect("phone call log thread");
    // The gateway's write queue and the restart are W6's; the slot is read at each apply, so an
    // empty one fails the setup closed (`gateway_unavailable`).
    let platform = crate::platform::common::Deps::of(app);
    let restart = platform.restart.clone();
    let mut deps = setup::Deps::new(
        platform.writer.clone(),
        app.runner.clone(),
        Arc::new(move || {
            let restart = restart.clone();
            Box::pin(async move {
                if let Err(e) = restart().await {
                    tracing::warn!("[phone] restart: {e}");
                }
            })
        }),
    );
    let (update, weak) = (crate::platform::update::state_path(app), Arc::downgrade(app));
    deps.settle = Some(setup::Settle {
        update: Arc::new(move || crate::platform::update::status(&update)),
        gateway_ready: Arc::new(move |timeout| {
            let o = weak.upgrade().and_then(|a| a.contracts.openclaw.get());
            Box::pin(async move {
                match o {
                    Some(o) => o.client.when_connected(timeout).await,
                    // `client?.whenConnected ? … : true` in index.ts.
                    None => true,
                }
            })
        }),
        sleep: None,
    });
    let settings_log = log.clone();
    deps.on_active = Arc::new(move |note| settings_log.settings(note));
    let service = PhoneService::new(deps);
    let binding = service.clone();
    let phone = Arc::new(Phone {
        service,
        log: log.clone(),
        calls: Arc::new(PluginCallStore::new(&history::plugin_db_path(
            &app.config.home.join(".openclaw"),
        ))),
        seen: Arc::default(),
        relay: Relay::new(
            Arc::new(move || binding.stream_binding()),
            Arc::new(move |sid, patch| {
                let _ = notes.send((sid.to_string(), patch.clone()));
            }),
        ),
    });
    app.contracts.phone.set(phone.clone());
    app.contracts
        .pages
        .set(Arc::new(Pages(phone.clone(), Arc::downgrade(app))));
    let (meetings, tombstones) = crate::meetings::archive_paths(app);
    app.contracts.export_records.set(Arc::new(Records {
        phone: phone.clone(),
        meetings,
        tombstones,
    }));
    page::register(
        router,
        Arc::new(page::PageContext {
            app: app.clone(),
            voice_dir: app.config.home.join(".openclaw").join("cc-voice"),
        }),
        phone.clone(),
    );
    // Node hands every upgrade to the relay, which refuses what is not the phone stream.
    if let Some(up) = router.upgrades_mut() {
        let (app, phone) = (app.clone(), phone.clone());
        up.route(
            stages::UPGRADE,
            |_, _| true,
            move |req, _| {
                let (app, phone) = (app.clone(), phone.clone());
                async move { phone.relay.upgrade(&app.firewall_auth, req).await }
            },
        );
    }
    // `routes/phone.ts`: the firewall's settings, before the console's gate.
    let app = app.clone();
    router.prefix(stages::PREFIXED, "/phone/", move |req, _| {
        let (app, phone) = (app.clone(), phone.clone());
        async move {
            let path = cc_http::pathname(&req.uri().to_string());
            let apply = req.method() == hyper::Method::POST && path == "/phone/apply";
            let read = if apply {
                ReadBody::Json { limit: 16384 }
            } else {
                ReadBody::No
            };
            let body = match firewall_request(&app.firewall_auth, req, "phone", 0, read).await {
                FirewallRequest::Refused { .. } => {
                    return send_json(401, &json!({"error": "Phone changes require the org firewall"}));
                }
                FirewallRequest::Accepted { parts, body, .. } => {
                    if parts.method == hyper::Method::GET && path == "/phone/status" {
                        let status = phone.service.status().map_or(Value::Null, Value::Object);
                        return send_json(200, &json!({"apply": status}));
                    }
                    if !apply {
                        return send_json(404, &json!({"error": "Not found"}));
                    }
                    body
                }
            };
            let raw = match body {
                FirewallBody::Json(m) => Some(Value::Object(m)),
                _ => None,
            };
            let Some(input) = apply::parse_phone_apply(raw.as_ref()) else {
                return send_json(400, &json!({"error": "Invalid phone configuration"}));
            };
            let mut out = serde_json::Map::new();
            out.insert("ok".into(), json!(true));
            out.extend(phone.service.start(input));
            send_json(200, &Value::Object(out))
        }
    });
}

#[cfg(test)]
mod session_tests {
    use super::*;

    /// `session-shipper.test.ts`'s call cases: answered calls only, within the lookback, open while
    /// in progress.
    #[test]
    fn answered_calls_within_the_lookback() {
        let h = 3_600_000.0;
        let now = 100.0 * h;
        let calls = vec![
            json!({"callId": "done", "state": "completed", "startedAt": now - 3.0 * h, "answeredAt": now - 3.0 * h + 5000.0, "endedAt": now - 2.0 * h}),
            json!({"callId": "live", "state": "active", "startedAt": now - 60_000.0, "answeredAt": now - 50_000.0}),
            json!({"callId": "missed", "state": "no-answer", "startedAt": now - h}),
            json!({"callId": "old", "state": "completed", "startedAt": now - 49.0 * h, "answeredAt": now - 49.0 * h}),
            json!({"callId": "noend", "state": "hangup-user", "startedAt": now - h, "answeredAt": now - h + 1000.0}),
        ];
        let mut calls = calls;
        // `c3` of the TS test: ended, never answered.
        calls.push(
            json!({"callId": "c3", "state": "no-answer", "startedAt": now - 30_000.0, "endedAt": now - 10_000.0}),
        );
        let s = |id: &str, start: f64, end: Option<f64>| CallSession {
            call_id: id.into(),
            started_at: start as i64,
            ended_at: end.map(|e| e as i64),
        };
        assert_eq!(
            call_sessions(&calls, now, 48.0 * h),
            vec![
                s("done", now - 3.0 * h + 5000.0, Some(now - 2.0 * h)),
                s("live", now - 50_000.0, None),
                s("noend", now - h + 1000.0, Some(now - h + 1000.0)),
            ]
        );
        // A null answer time is "answered" in the TS (`!== undefined`): the call counts from its start.
        let nulled = vec![
            json!({"callId": "n", "state": "completed", "startedAt": now - h, "answeredAt": null, "endedAt": now - h + 9000.0}),
        ];
        assert_eq!(
            call_sessions(&nulled, now, 48.0 * h),
            vec![s("n", now - h, Some(now - h + 9000.0))]
        );
    }
}

#[cfg(test)]
mod seen_tests {
    use super::*;

    /// A delete while a background read is under way: that read's answer is dropped, and the next
    /// question reads the records again (Bugbot on #544).
    #[tokio::test]
    async fn a_delete_wins_over_a_read_already_running() {
        let dir = tempfile::tempdir().expect("dir");
        let db = history::tests::plugin_db(
            dir.path(),
            &[history::tests::rec(history::tests::A, serde_json::json!({}))],
        );
        let calls = Arc::new(PluginCallStore::new(&db));
        let seen: Arc<std::sync::Mutex<Seen>> = Arc::default();
        // A read that started before the delete, finishing after it.
        let stale = Phone::read_seen(&calls, 0);
        assert!(stale.any);
        {
            let mut s = seen.lock().expect("seen");
            s.reading = true;
            s.generation += 1; // the delete
            s.at = None;
        }
        calls.remove(None).expect("remove");
        {
            let mut s = seen.lock().expect("seen");
            if s.generation == 0 {
                *s = stale;
            } else {
                s.reading = false;
            }
        }
        let s = seen.lock().expect("seen");
        assert!(s.at.is_none() && !s.reading, "the stale answer was not kept");
        drop(s);
        assert!(!Phone::read_seen(&calls, 1).any);
    }
}
