//! Meetings the agent joins by itself (`meeting-schedule.ts`, docs/plans/meetjoin.md): from
//! calendar invites mailed to it and from the connected Google Calendar. The schedule is kept on
//! this box only. The firewall holds the settings and checks every such join again when the media
//! lease is asked for; the console never sees a link, a title or an organizer.
//!
//! The TS held one object per entry, so a tick waiting on the firewall saw a sync's changes and the
//! owner's Cancel. Here the entries live in the store under one lock, never held across an await,
//! and each step reads the entry again by its id. An entry a sync dropped meanwhile is worked on
//! as the copy the tick holds, as the TS kept working on the detached object.

use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, MutexGuard};

use cc_http::BoxFuture;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use super::archive::atomic_json;
use super::ics::{MAX_ICS_BYTES, expand_invites, invite_uids};
use super::js::{head16, len16};
use super::policy::{OP_ID, auto_join_refusal};
use super::sources::{CalendarEvent, MailBatch};
use crate::platform::time::iso_ms;

const MINUTE: i64 = 60_000;
/// Join this long before the start, so the agent is there when people arrive.
pub const JOIN_EARLY_MS: i64 = MINUTE;
/// A meeting whose start was missed is still joined this long after it.
pub const JOIN_LATE_MS: i64 = 10 * MINUTE;
/// Leave this long after the scheduled end.
pub const LEAVE_AFTER_MS: i64 = 15 * MINUTE;
const INVITE_WINDOW_MS: i64 = 7 * 24 * 60 * MINUTE;
const CALENDAR_WINDOW_MS: i64 = 24 * 60 * MINUTE;
const KEEP_PAST_MS: i64 = 7 * 24 * 60 * MINUTE;
const ADMIT_EVERY_MS: i64 = 10 * MINUTE;
const MAX_INVITES: usize = 300;
const MAX_FILES_PER_INVITE: usize = 20;
const MAX_ENTRIES: usize = 1000;
/// After this many tries an invite file that cannot be fetched is given up, so later mail is read.
const MAX_MAIL_RETRIES: i64 = 5;

/// One scheduled join. Fields this build does not know are kept.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub id: String,
    pub source: String,
    /// Stable per occurrence: `<uid>|<original start>` for an invite, the event id for the calendar.
    pub key: String,
    pub start: i64,
    pub end: i64,
    pub url: String,
    pub title: String,
    pub organizer: String,
    /// `scheduled`, `cancelled` (the owner pressed Cancel), `joined` or `skipped`.
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Why the firewall would not let the agent join, when it was last asked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checked_at: Option<i64>,
    /// Another meeting was running when this one was due.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub waited: Option<bool>,
    /// When the agent first learned of it; an invite can arrive after the meeting started.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub added_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meeting_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// What a source says about one occurrence.
#[derive(Debug, Clone)]
struct Wanted {
    key: String,
    start: i64,
    end: i64,
    url: String,
    title: String,
    organizer: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Stored {
    #[serde(default)]
    entries: Vec<Entry>,
    /// One event's invite files, oldest first, and who mailed the first one: `{from, files, at}`.
    #[serde(default)]
    invites: Map<String, Value>,
    #[serde(default)]
    seen: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    email_cursor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    email_failures: Option<i64>,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

impl Stored {
    /// As the TS reads it (`saved.entries ?? []`, ...): one field or entry that does not fit is
    /// left out, not the whole schedule.
    fn loose(v: &Value) -> Self {
        let entries = v
            .get("entries")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|e| {
                let mut e = e.clone();
                // A time written as a float reads as whole milliseconds.
                for k in ["start", "end", "checkedAt", "addedAt"] {
                    if let Some(f) = e.get(k).and_then(Value::as_f64) {
                        e[k] = json!(f as i64);
                    }
                }
                serde_json::from_value::<Entry>(e).ok()
            })
            .collect();
        let mut extra = v.as_object().cloned().unwrap_or_default();
        for k in ["entries", "invites", "seen", "emailCursor", "emailFailures"] {
            extra.remove(k);
        }
        Self {
            entries,
            invites: v
                .get("invites")
                .and_then(Value::as_object)
                .map(|m| {
                    m.iter()
                        .filter(|(_, i)| i.is_object())
                        .map(|(k, i)| (k.clone(), i.clone()))
                        .collect()
                })
                .unwrap_or_default(),
            seen: v
                .get("seen")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_str).map(String::from).collect())
                .unwrap_or_default(),
            email_cursor: v.get("emailCursor").and_then(Value::as_str).map(String::from),
            email_failures: v.get("emailFailures").and_then(Value::as_i64),
            extra,
        }
    }
}

type Fut<T> = BoxFuture<T>;

/// A join the schedule asked for that did not happen: the firewall's refusal, if it was one, and why.
#[derive(Debug, Clone, PartialEq)]
pub struct JoinFailed {
    pub refusal: Option<String>,
    pub message: String,
}

pub type JoinFn = Arc<dyn Fn(String, Value, i64) -> Fut<Result<(String, String), JoinFailed>> + Send + Sync>;
pub type AdmitFn = Arc<dyn Fn(Value) -> Fut<Result<Option<String>, String>> + Send + Sync>;
pub type MailFn = Arc<dyn Fn(Option<String>) -> Fut<Result<Option<MailBatch>, String>> + Send + Sync>;
pub type CalendarFn = Arc<dyn Fn(i64, i64, String) -> Fut<Result<Option<Vec<CalendarEvent>>, String>> + Send + Sync>;

#[derive(Clone)]
pub struct ScheduleDeps {
    pub state_path: PathBuf,
    /// The automatic-joining settings, or `None` when it is off.
    pub settings: Arc<dyn Fn() -> Option<Value> + Send + Sync>,
    pub busy: Arc<dyn Fn() -> bool + Send + Sync>,
    /// `(url, claim, leave at)` -> `(meeting id, mode)`.
    pub join: JoinFn,
    pub admit: AdmitFn,
    /// End a meeting the schedule joined; nothing when the agent is in another one by now.
    pub leave: Arc<dyn Fn(String) -> Fut<()> + Send + Sync>,
    /// Invite mails since the cursor; `None` in the answer: no mailbox on this agent.
    pub mail: Option<MailFn>,
    /// Events with a Meet link in the window; `None` in the answer: no calendar.
    pub calendar: Option<CalendarFn>,
    pub now: Arc<dyn Fn() -> i64 + Send + Sync>,
}

pub struct MeetingSchedule {
    deps: ScheduleDeps,
    store: Mutex<Stored>,
    ticking: AtomicBool,
    syncing_email: AtomicBool,
    syncing_calendar: AtomicBool,
    /// Ids the owner cancelled, so a join that returns finds the Cancel even if a sync dropped the
    /// entry meanwhile (the TS held the same object, which kept its state).
    cancelled: Mutex<std::collections::HashSet<String>>,
}

use crate::platform::common::Flag;

fn take(flag: &AtomicBool) -> Option<Flag<'_>> {
    Flag::take(flag)
}

fn truthy(v: Option<&Value>) -> bool {
    crate::phone::model::truthy(v)
}

impl MeetingSchedule {
    pub fn new(deps: ScheduleDeps) -> Arc<Self> {
        // An unreadable schedule is rebuilt from the mailbox and the calendar.
        let store = std::fs::read(&deps.state_path)
            .ok()
            .and_then(|raw| serde_json::from_slice::<Value>(&raw).ok())
            .map(|v| Stored::loose(&v))
            .unwrap_or_default();
        Arc::new(Self {
            deps,
            store: Mutex::new(store),
            ticking: AtomicBool::new(false),
            syncing_email: AtomicBool::new(false),
            syncing_calendar: AtomicBool::new(false),
            cancelled: Mutex::default(),
        })
    }

    fn store(&self) -> MutexGuard<'_, Stored> {
        self.store.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn now(&self) -> i64 {
        (self.deps.now)()
    }

    fn save_locked(&self, store: &mut Stored) {
        let cutoff = self.now() - KEEP_PAST_MS;
        store.entries.retain(|e| e.end > cutoff);
        store.entries.sort_by_key(|e| e.start);
        let n = store.entries.len();
        store.entries.drain(..n.saturating_sub(MAX_ENTRIES));
        let n = store.seen.len();
        store.seen.drain(..n.saturating_sub(2000));
        let value = serde_json::to_value(&*store).unwrap_or(Value::Null);
        if let Err(e) = atomic_json(&self.deps.state_path, &value) {
            tracing::error!("[meetings] the schedule could not be saved: {e}");
        }
    }

    /// For the Meetings page: what is coming up, and what was skipped or joined in the last day.
    pub fn list(&self) -> Value {
        let settings = (self.deps.settings)();
        let now = self.now();
        let entries: Vec<Value> = match &settings {
            None => Vec::new(),
            Some(_) => self
                .store()
                .entries
                .iter()
                .filter(|e| e.end > now - 24 * 60 * MINUTE && (e.state != "joined" || e.end > now))
                .map(|e| {
                    let note = if e.state == "skipped" {
                        e.reason.clone().map_or(Value::Null, Value::String)
                    } else if e.state == "scheduled" {
                        e.refusal
                            .as_deref()
                            .and_then(auto_join_refusal)
                            .map_or(Value::Null, |r| json!(r))
                    } else {
                        Value::Null
                    };
                    json!({
                        "id": e.id, "source": e.source, "start": iso_ms(e.start), "end": iso_ms(e.end),
                        "title": e.title, "organizer": e.organizer, "state": e.state, "meetingId": e.meeting_id,
                        "note": note,
                    })
                })
                .collect(),
        };
        json!({
            "enabled": settings.is_some(),
            "mode": settings.as_ref().and_then(|s| s.get("mode")).filter(|m| !m.is_null()).cloned().unwrap_or(json!("transcript")),
            "entries": entries,
        })
    }

    /// Cancel or bring back one scheduled join. The owner's choice survives a later sync.
    pub fn set(&self, raw: &Map<String, Value>, state: &str) -> Result<Value, String> {
        let id = raw.get("id").and_then(Value::as_str).unwrap_or_default();
        if raw.keys().any(|k| k != "id") || !OP_ID.is_match(id) {
            return Err("Invalid scheduled meeting".into());
        }
        let now = self.now();
        let mut store = self.store();
        let from = if state == "cancelled" { "scheduled" } else { "cancelled" };
        let Some(entry) = store
            .entries
            .iter_mut()
            .find(|e| e.id == id)
            .filter(|e| e.state == from)
        else {
            return Err("This meeting can no longer be changed".into());
        };
        if state == "scheduled" && entry.start + JOIN_LATE_MS <= now {
            return Err("This meeting has started".into());
        }
        entry.state = state.to_string();
        entry.checked_at = None;
        let id = entry.id.clone();
        self.save_locked(&mut store);
        drop(store);
        let mut cancelled = self.cancelled.lock().unwrap_or_else(|e| e.into_inner());
        if state == "cancelled" {
            cancelled.insert(id);
        } else {
            cancelled.remove(&id);
        }
        Ok(json!({"ok": true}))
    }

    /// `reconcile`: replace one source's future entries with what it says now. An entry the owner
    /// cancelled stays cancelled, a past or running one is history and is left alone, and one that
    /// is gone from the source (moved, deleted, cancelled by the organizer) goes.
    /// `held`: invites that could not be read this time; what they had scheduled is kept as it is.
    fn reconcile(&self, store: &mut Stored, source: &str, wanted: Vec<Wanted>, until: i64, held: &[String]) {
        let now = self.now();
        let mut by_key: Vec<Wanted> = Vec::new();
        for w in wanted {
            // `new Map(...)`: the last one for a key wins, in the place of the first.
            match by_key.iter_mut().find(|x| x.key == w.key) {
                Some(x) => *x = w,
                None => by_key.push(w),
            }
        }
        let mut kept: Vec<Entry> = Vec::new();
        for mut entry in std::mem::take(&mut store.entries) {
            if entry.source != source
                || entry.state == "joined"
                || entry.state == "skipped"
                || entry.start >= until
                || held
                    .iter()
                    .any(|uid| entry.key.split_once('|').is_some_and(|(u, _)| u == uid))
            {
                kept.push(entry);
                continue;
            }
            let Some(at) = by_key.iter().position(|w| w.key == entry.key) else {
                // Gone from the source. What already started is kept as it was.
                if entry.start <= now {
                    kept.push(entry);
                }
                continue;
            };
            let next = by_key.remove(at);
            if entry.start != next.start || entry.url != next.url || entry.organizer != next.organizer {
                entry.checked_at = None;
                entry.refusal = None;
                entry.waited = None;
            }
            entry.key = next.key;
            entry.start = next.start;
            entry.end = next.end;
            entry.url = next.url;
            entry.title = next.title;
            entry.organizer = next.organizer;
            kept.push(entry);
        }
        for next in by_key {
            if next.end <= now {
                continue;
            }
            // The same meeting from the mailbox and from the calendar is one entry: the first stays.
            if kept
                .iter()
                .any(|e| e.url == next.url && (e.start - next.start).abs() < MINUTE)
            {
                continue;
            }
            // A meeting already joined or skipped at this time is not scheduled a second time; one
            // the organizer moved to a new time is.
            if kept
                .iter()
                .any(|e| e.source == source && e.key == next.key && e.start == next.start)
            {
                continue;
            }
            kept.push(Entry {
                id: uuid::Uuid::new_v4().to_string(),
                source: source.to_string(),
                key: next.key,
                start: next.start,
                end: next.end,
                url: next.url,
                title: next.title,
                organizer: next.organizer,
                state: "scheduled".into(),
                reason: None,
                refusal: None,
                checked_at: None,
                waited: None,
                added_at: Some(now),
                meeting_id: None,
                mode: None,
                extra: Map::new(),
            });
        }
        store.entries = kept;
    }

    /// `syncEmail`: new invite mails into the store, then the schedule from every invite kept.
    /// The invites are expanded outside the store's lock.
    pub async fn sync_email(&self) {
        let settings = (self.deps.settings)();
        let Some(mail) = self.deps.mail.clone() else { return };
        if !truthy(settings.as_ref().and_then(|s| s.get("email"))) {
            return;
        }
        let Some(_flag) = take(&self.syncing_email) else { return };
        let cursor = self.store().email_cursor.clone();
        let outcome: Result<(), String> = async {
            let Some(batch) = mail(cursor).await? else {
                return Ok(());
            };
            let now = self.now();
            let invites = {
                let mut store = self.store();
                for m in &batch.mails {
                    if store.seen.contains(&m.id) || len16(&m.ics) > MAX_ICS_BYTES {
                        continue;
                    }
                    store.seen.push(m.id.clone());
                    for uid in invite_uids(&m.ics) {
                        let invite = store
                            .invites
                            .entry(uid)
                            .or_insert_with(|| json!({"from": m.from, "files": [], "at": now}));
                        let mut files: Vec<Value> = invite
                            .get("files")
                            .and_then(Value::as_array)
                            .cloned()
                            .unwrap_or_default();
                        files.push(json!(m.ics));
                        let n = files.len();
                        files.drain(..n.saturating_sub(MAX_FILES_PER_INVITE));
                        if let Some(o) = invite.as_object_mut() {
                            o.insert("files".into(), Value::Array(files));
                            o.insert("at".into(), json!(now));
                        }
                    }
                }
                // The cursor waits for a file that could not be fetched, but not for ever.
                let failures = if batch.incomplete {
                    store.email_failures.unwrap_or(0) + 1
                } else {
                    0
                };
                store.email_failures = Some(failures);
                if !batch.incomplete || failures >= MAX_MAIL_RETRIES {
                    store.email_cursor = Some(batch.cursor.clone());
                    store.email_failures = Some(0);
                }
                store.invites.clone()
            };
            let (wanted, forget, held) = tokio::task::spawn_blocking(move || expand(&invites, now))
                .await
                .map_err(|e| e.to_string())?;
            let mut store = self.store();
            for uid in forget {
                store.invites.remove(&uid);
            }
            self.reconcile(&mut store, "email", wanted, now + INVITE_WINDOW_MS, &held);
            self.save_locked(&mut store);
            Ok(())
        }
        .await;
        if let Err(e) = outcome {
            tracing::warn!("[meetings] invite mail was not read: {}", head16(&e, 200));
        }
    }

    /// `syncCalendar`.
    pub async fn sync_calendar(&self) {
        let Some(settings) = (self.deps.settings)() else { return };
        let mode = settings
            .get("calendar")
            .and_then(Value::as_str)
            .unwrap_or("off")
            .to_string();
        let Some(calendar) = self.deps.calendar.clone() else {
            return;
        };
        if mode == "off" {
            return;
        }
        let Some(_flag) = take(&self.syncing_calendar) else {
            return;
        };
        let now = self.now();
        let until = now + CALENDAR_WINDOW_MS;
        match calendar(now - JOIN_LATE_MS, until, mode).await {
            Ok(Some(events)) => {
                let wanted = events
                    .into_iter()
                    .map(|e| Wanted {
                        key: e.id,
                        start: e.start,
                        end: e.end,
                        url: e.url,
                        title: head16(&e.title, 200),
                        organizer: e.organizer,
                    })
                    .collect();
                let mut store = self.store();
                self.reconcile(&mut store, "calendar", wanted, until, &[]);
                self.save_locked(&mut store);
            }
            Ok(None) => {}
            Err(e) => tracing::warn!("[meetings] calendar was not read: {}", head16(&e, 200)),
        }
    }

    /// A source that was turned off no longer schedules anything; history stays.
    fn drop_disabled(&self, settings: &Value) {
        let email = truthy(settings.get("email"));
        let calendar = settings.get("calendar") != Some(&json!("off"));
        let mut store = self.store();
        let before = store.entries.len();
        store.entries.retain(|e| {
            e.state == "joined" || e.state == "skipped" || if e.source == "email" { email } else { calendar }
        });
        if store.entries.len() != before {
            self.save_locked(&mut store);
        }
    }

    fn get(&self, id: &str) -> Option<Entry> {
        self.store().entries.iter().find(|e| e.id == id).cloned()
    }

    /// Change the entry in the store, or the tick's own copy when a sync dropped it.
    fn update(&self, copy: &mut Entry, f: impl FnOnce(&mut Entry)) {
        let mut store = self.store();
        match store.entries.iter_mut().find(|e| e.id == copy.id) {
            Some(e) => {
                f(e);
                *copy = e.clone();
            }
            None => f(copy),
        }
    }

    /// `tick`, every 30 seconds: join what is due, mark what was missed, ask the firewall about
    /// what is coming.
    pub async fn tick(&self) {
        let Some(settings) = (self.deps.settings)() else { return };
        let Some(_flag) = take(&self.ticking) else { return };
        self.drop_disabled(&settings);
        let now = self.now();
        let mut due: Vec<Entry> = self
            .store()
            .entries
            .iter()
            .filter(|e| e.state == "scheduled")
            .cloned()
            .collect();
        due.sort_by_key(|e| e.start);
        let mut changed = false;
        for snapshot in due {
            let mut entry = self.get(&snapshot.id).unwrap_or(snapshot);
            if now >= (entry.start + JOIN_LATE_MS).min(entry.end) {
                self.update(&mut entry, |e| {
                    e.state = "skipped".into();
                    e.reason = Some(
                        if e.waited == Some(true) {
                            "Another meeting was running"
                        } else if let Some(r) = e.refusal.as_deref().and_then(auto_join_refusal) {
                            r
                        } else if e.added_at.unwrap_or(0) > e.start {
                            "The invite arrived after the meeting started"
                        } else {
                            "The agent was not running at the start time"
                        }
                        .to_string(),
                    );
                });
                changed = true;
                continue;
            }
            let auto = json!({"source": entry.source, "organizer": entry.organizer});
            if now < entry.start - JOIN_EARLY_MS {
                // Asked ahead for the next day's meetings, so the page can say why one will not be joined.
                if entry.start - now < 24 * 60 * MINUTE
                    && entry.checked_at.unwrap_or(0) < now - ADMIT_EVERY_MS
                    && let Ok(refusal) = (self.deps.admit)(auto).await
                {
                    self.update(&mut entry, |e| {
                        e.refusal = refusal;
                        e.checked_at = Some(now);
                    });
                    changed = true;
                }
                continue;
            }
            // One meeting at a time: the earlier start has the agent, this one waits for it to end.
            if (self.deps.busy)() {
                if entry.waited != Some(true) {
                    self.update(&mut entry, |e| e.waited = Some(true));
                    changed = true;
                }
                // A scheduled meeting that has run past its own end makes room for the next one.
                if now >= entry.start {
                    let over = self
                        .store()
                        .entries
                        .iter()
                        .find(|e| {
                            e.state == "joined"
                                && e.meeting_id.is_some()
                                && e.end <= now
                                && e.end + LEAVE_AFTER_MS > now
                        })
                        .and_then(|e| e.meeting_id.clone());
                    if let Some(id) = over {
                        (self.deps.leave)(id).await;
                    }
                }
                continue;
            }
            self.cancelled
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&entry.id);
            let joined = (self.deps.join)(entry.url.clone(), auto, entry.end + LEAVE_AFTER_MS).await;
            let cancelled = match self.get(&entry.id) {
                Some(e) => e.state == "cancelled",
                None => self
                    .cancelled
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .contains(&entry.id),
            };
            match joined {
                Ok((meeting_id, mode)) => {
                    if cancelled {
                        // The owner pressed Cancel while the firewall was being asked: leave again.
                        (self.deps.leave)(meeting_id).await;
                    } else {
                        let mut store = self.store();
                        let source = entry.source.clone();
                        let mark = |e: &mut Entry| {
                            e.state = "joined".into();
                            e.meeting_id = Some(meeting_id.clone());
                            e.mode = Some(mode.clone());
                            e.refusal = None;
                        };
                        match store.entries.iter_mut().find(|e| e.id == entry.id) {
                            Some(e) => mark(e),
                            None => {
                                // A sync that ran meanwhile dropped it; what was joined stays on record.
                                mark(&mut entry);
                                store.entries.push(entry.clone());
                            }
                        }
                        drop(store);
                        tracing::info!(
                            "[meetings] joined a scheduled meeting from {}",
                            if source == "email" { "an invite" } else { "the calendar" }
                        );
                    }
                }
                Err(failed) => {
                    if cancelled {
                        changed = true;
                        break;
                    }
                    self.update(&mut entry, |e| {
                        e.state = "skipped".into();
                        e.reason = Some(match failed.refusal.as_deref().and_then(auto_join_refusal) {
                            Some(r) => r.to_string(),
                            None => "The agent could not join. Check its Meetings settings and size.".into(),
                        });
                    });
                    tracing::warn!(
                        "[meetings] scheduled meeting not joined: {}",
                        failed.refusal.unwrap_or_else(|| head16(&failed.message, 200))
                    );
                }
            }
            changed = true;
            // Whatever else is due waits for the next tick, when the agent is seen to be busy.
            break;
        }
        if changed {
            let mut store = self.store();
            self.save_locked(&mut store);
        }
    }
}

/// `expandInvites`: every invite kept, as occurrences in the next week, and the invites to forget
/// (nothing left to join and untouched for a month; the oldest beyond the limit), and the invites
/// held as they were. Rust only: an invite that cannot be read (its files make the calendar parser
/// fail) is held, what it had scheduled kept, and the rest go on; it is forgotten like any other
/// once untouched for a month. In the TS it stopped the whole sync, so nothing new was scheduled.
fn expand(invites: &Map<String, Value>, now: i64) -> (Vec<Wanted>, Vec<String>, Vec<String>) {
    let until = now + INVITE_WINDOW_MS;
    let mut wanted = Vec::new();
    let mut forget = Vec::new();
    let mut held = Vec::new();
    for (uid, invite) in invites {
        let files: Vec<String> = invite
            .get("files")
            .and_then(Value::as_array)
            .map(|f| f.iter().filter_map(Value::as_str).map(String::from).collect())
            .unwrap_or_default();
        let at = invite.get("at").and_then(Value::as_i64).unwrap_or(0);
        let occurrences = match expand_invites(uid, &files, now - JOIN_LATE_MS, until) {
            Ok(o) => o,
            Err(e) => {
                tracing::warn!(
                    "[meetings] invite {} could not be read; what it scheduled is kept: {}",
                    head16(uid, 120),
                    head16(&e, 200)
                );
                if at < now - 30 * 24 * 60 * MINUTE {
                    forget.push(uid.clone());
                } else {
                    held.push(uid.clone());
                }
                continue;
            }
        };
        // An invite with nothing left to join, not touched for a month, is forgotten.
        if occurrences.is_empty() && at < now - 30 * 24 * 60 * MINUTE {
            forget.push(uid.clone());
            continue;
        }
        let from = invite
            .get("from")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        for o in occurrences {
            wanted.push(Wanted {
                key: o.key,
                start: o.start,
                end: o.end,
                url: o.url,
                title: o.title,
                organizer: from.clone(),
            });
        }
    }
    // The oldest of the invites still kept go beyond the limit.
    let mut live: Vec<(&String, f64)> = invites
        .iter()
        .filter(|(u, _)| !forget.contains(u))
        .map(|(u, i)| (u, i.get("at").and_then(Value::as_f64).unwrap_or(0.0)))
        .collect();
    live.sort_by(|a, b| a.1.total_cmp(&b.1));
    let over = live.len().saturating_sub(MAX_INVITES);
    forget.extend(live.into_iter().take(over).map(|(u, _)| u.clone()));
    (wanted, forget, held)
}

#[cfg(test)]
mod tests;
