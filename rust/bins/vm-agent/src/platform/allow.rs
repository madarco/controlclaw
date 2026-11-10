//! Who OpenClaw itself will talk to, and who is waiting to be approved, read straight out of its
//! state database (`openclaw-allow.ts`, T-83).
//!
//! `~/.openclaw/state/openclaw.sqlite` (OpenClaw 2026.9 and later):
//!
//! - `channel_pairing_allow_entries (channel_key, account_id, entry, sort_order, updated_at)`
//! - `channel_pairing_requests (channel_key, account_id, request_id, code, created_at, last_seen_at, meta_json)`
//!
//! The allow list is a suggestion, never an approval: the agent can write to it by itself. It is
//! another program's database, so it is opened read-only, never created, and nothing here fails
//! the agent. The customer is never shown SQLite's own words.

use std::path::Path;
use std::time::Duration;

use rusqlite::types::ValueRef;
use rusqlite::{Connection, OpenFlags};
use serde_json::Value;

use super::time::iso_ms;

/// Bounds the read and the response.
const ENTRY_CAP: usize = 200;

#[derive(Debug, Clone, PartialEq)]
pub struct AllowedSender {
    pub channel: String,
    pub account_id: String,
    pub sender_id: String,
    pub label: Option<String>,
    pub at: Option<String>,
}

/// Why a list came back short, when it did not simply find nothing.
#[derive(Debug, Clone, PartialEq)]
pub struct ReadError {
    pub busy: bool,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct AllowListRead {
    pub senders: Vec<AllowedSender>,
    pub error: Option<ReadError>,
    /// The canonical store answered: what came back is the whole truth, empty or not.
    pub canonical: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PendingRow {
    pub channel: String,
    pub sender_id: String,
    pub code: String,
    pub label: Option<String>,
    pub created_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct PendingRead {
    pub pairings: Vec<PendingRow>,
    pub error: Option<ReadError>,
    pub canonical: bool,
}

fn looks_busy(m: &str) -> bool {
    let l = m.to_lowercase();
    ["ebusy", "eagain", "sqlite_busy", "sqlite_protocol"]
        .iter()
        .any(|w| word(&l, w))
        || l.contains("database is locked")
        || l.contains("database table is locked")
        || l.contains("locking protocol")
}

fn looks_unopenable(m: &str) -> bool {
    let l = m.to_lowercase();
    [
        "sqlite_cantopen",
        "sqlite_readonly_cantinit",
        "sqlite_readonly_recovery",
    ]
    .iter()
    .any(|w| word(&l, w))
        || l.contains("unable to open database file")
}

/// `\bword\b`.
fn word(haystack: &str, w: &str) -> bool {
    let is_word = |c: char| c.is_ascii_alphanumeric() || c == '_';
    haystack.match_indices(w).any(|(i, _)| {
        let before = haystack[..i].chars().next_back();
        let after = haystack[i + w.len()..].chars().next();
        !before.is_some_and(is_word) && !after.is_some_and(is_word)
    })
}

fn allow_failure(m: &str) -> ReadError {
    if looks_busy(m) {
        return ReadError {
            busy: true,
            message: "The agent is busy right now, so who it has allowed could not be read.".into(),
        };
    }
    let message = if looks_unopenable(m) {
        "Your agent's own list could not be opened. Restarting the agent clears this."
    } else {
        "Your agent's own list could not be read."
    };
    ReadError {
        busy: false,
        message: message.into(),
    }
}

fn pairing_failure(m: &str) -> ReadError {
    if looks_busy(m) {
        return ReadError {
            busy: true,
            message: "The agent is busy right now, so who is waiting could not be read.".into(),
        };
    }
    let message = if looks_unopenable(m) {
        "Your agent's pairing list could not be opened. Restarting the agent clears this."
    } else {
        "Your agent's pairing list could not be read."
    };
    ReadError {
        busy: false,
        message: message.into(),
    }
}

/// The driver's message in the words node:sqlite uses for the cases told apart above.
fn sqlite_message(e: &rusqlite::Error) -> String {
    match e {
        rusqlite::Error::SqliteFailure(f, m) => {
            let code = match f.code {
                rusqlite::ErrorCode::DatabaseBusy => "SQLITE_BUSY",
                rusqlite::ErrorCode::DatabaseLocked => "database table is locked",
                rusqlite::ErrorCode::CannotOpen => "SQLITE_CANTOPEN",
                // A WAL database a read-only connection cannot bring up: OpenClaw has to open it first.
                rusqlite::ErrorCode::ReadOnly => match f.extended_code {
                    rusqlite::ffi::SQLITE_READONLY_CANTINIT => "SQLITE_READONLY_CANTINIT",
                    rusqlite::ffi::SQLITE_READONLY_RECOVERY => "SQLITE_READONLY_RECOVERY",
                    _ => "",
                },
                _ => "",
            };
            format!("{code} {}", m.clone().unwrap_or_else(|| f.to_string()))
        }
        other => other.to_string(),
    }
}

/// Read-only, never create, a 2 s busy wait.
fn open(path: &Path) -> Result<Connection, String> {
    let db = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX)
        .map_err(|e| sqlite_message(&e))?;
    let _ = db.busy_timeout(Duration::from_millis(2000));
    Ok(db)
}

fn text(v: ValueRef<'_>) -> Option<String> {
    match v {
        ValueRef::Text(t) if !t.is_empty() => Some(String::from_utf8_lossy(t).into_owned()),
        _ => None,
    }
}

/// `updated_at`: epoch ms, or seconds from an older build; anything implausible is dropped.
fn stamp(v: f64) -> Option<String> {
    if !v.is_finite() || v <= 0.0 {
        return None;
    }
    let ms = if v < 1e11 { v * 1000.0 } else { v };
    // `Date` holds ±8.64e15 ms.
    (ms <= 8.64e15).then(|| iso_ms(ms as i64))
}

fn stamp_ref(v: ValueRef<'_>) -> Option<String> {
    match v {
        ValueRef::Integer(i) => stamp(i as f64),
        ValueRef::Real(f) => stamp(f),
        _ => None,
    }
}

/// `created_at`: a TEXT column holding ISO time or epoch ms as text.
fn text_stamp(v: ValueRef<'_>) -> Option<String> {
    match v {
        ValueRef::Integer(_) | ValueRef::Real(_) => stamp_ref(v),
        _ => {
            let raw = text(v)?;
            if raw.bytes().all(|b| b.is_ascii_digit()) {
                return stamp(raw.parse::<f64>().ok()?);
            }
            super::time::parse_iso_z(&raw)
                .or_else(|| parse_offset_iso(&raw))
                .map(iso_ms)
        }
    }
}

/// The ISO forms `new Date(raw)` takes that OpenClaw or SQLite may write: a space for the `T`,
/// more than three fraction digits (cut to milliseconds), an offset as `±HH:MM` or `±HHMM`, or no
/// zone at all (local time, which is UTC on a box).
fn parse_offset_iso(raw: &str) -> Option<i64> {
    let raw = raw.trim();
    if !raw.is_ascii() || raw.len() < 19 {
        return None;
    }
    let (date_time, zone) = match raw.find(['Z', '+']).or_else(|| raw[10..].rfind('-').map(|i| i + 10)) {
        Some(i) if i >= 19 => (&raw[..i], &raw[i..]),
        _ => (raw, ""),
    };
    let mut dt = date_time.replacen(' ', "T", 1);
    if let Some(dot) = dt.find('.') {
        let frac: String = dt[dot + 1..].chars().take(3).collect();
        if frac.is_empty() || !dt[dot + 1..].bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        dt = format!("{}.{frac}", &dt[..dot]);
    }
    let t = super::time::parse_iso_z(&format!("{dt}Z"))?;
    let offset_min = match zone {
        "" | "Z" => 0,
        z => {
            let sign = if z.starts_with('-') { -1 } else { 1 };
            let digits: String = z[1..].chars().filter(|c| *c != ':').collect();
            if digits.len() != 4 || !digits.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            let h: i64 = digits[..2].parse().ok()?;
            let m: i64 = digits[2..].parse().ok()?;
            sign * (h * 60 + m)
        }
    };
    Some(t - offset_min * 60_000)
}

/// The console's limit on a sender label (`approvePairingSchema`, the firewall beat's `senderLabel`).
/// Longer, and the approval the label travels with would be refused.
const LABEL_MAX_CHARS: usize = 120;

/// The name on a request's meta, as the console shows it.
///
/// What OpenClaw puts there (2026.11): Slack and WhatsApp `name` (Slack's display name, WhatsApp's
/// push name); Telegram `firstName`, `lastName` and `username`, and no `name`. So a Telegram user
/// reads "Ada Lovelace (@ada)", "Ada Lovelace" or "@ada", and the id only when none is set.
pub fn label_of(meta: &Value) -> Option<String> {
    let field = |k: &str| {
        super::common::text(meta.get(k))
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    };
    let full = [field("firstName"), field("lastName")]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" ");
    let name = field("name")
        .or_else(|| field("displayName"))
        .or_else(|| (!full.is_empty()).then_some(full));
    let username = field("username")
        .map(|u| u.trim_start_matches('@').to_string())
        .filter(|u| !u.is_empty());
    let label = match (name, username) {
        (Some(n), Some(u)) => format!("{n} (@{u})"),
        (Some(n), None) => n,
        (None, Some(u)) => format!("@{u}"),
        (None, None) => field("title")?,
    };
    Some(label.chars().take(LABEL_MAX_CHARS).collect())
}

fn label_from_meta(meta: Option<String>) -> Option<String> {
    label_of(&serde_json::from_str::<Value>(&meta?).ok()?)
}

fn is_sender(entry: &str) -> bool {
    entry != "*" && !entry.starts_with("accessGroup:")
}

/// OpenClaw's DM allow list for the given channels. No database or no tables: not an error.
pub fn read_allow_list(db_path: &Path, channels: &[&str], log: &dyn Fn(&str)) -> AllowListRead {
    if channels.is_empty() || !db_path.exists() {
        return AllowListRead::default();
    }
    let db = match open(db_path) {
        Ok(db) => db,
        Err(m) => {
            log(&format!("[channels] could not open OpenClaw's state database: {m}"));
            return AllowListRead {
                error: Some(allow_failure(&m)),
                ..Default::default()
            };
        }
    };
    let mut senders = Vec::new();
    for channel in channels {
        let rows: Vec<(Option<String>, Option<String>, Option<String>)> = match (|| {
            let mut st = db.prepare(
                "SELECT account_id, entry, updated_at FROM channel_pairing_allow_entries WHERE channel_key = ? ORDER BY account_id, sort_order, entry",
            )?;
            let mapped = st.query_map([channel], |r| {
                Ok((text(r.get_ref(0)?), text(r.get_ref(1)?), stamp_ref(r.get_ref(2)?)))
            })?;
            mapped.collect::<Result<Vec<_>, _>>()
        })() {
            Ok(rows) => rows,
            Err(e) => {
                let m = sqlite_message(&e);
                if m.to_lowercase().contains("no such table") {
                    return AllowListRead::default();
                }
                log(&format!("[channels] could not read OpenClaw's allow list: {m}"));
                return AllowListRead {
                    error: Some(allow_failure(&m)),
                    ..Default::default()
                };
            }
        };
        // Labels are a nicety; an id is still a true answer.
        let requests: Vec<(Option<String>, Option<String>)> = if rows.is_empty() {
            Vec::new()
        } else {
            (|| {
                let mut st =
                    db.prepare("SELECT request_id, meta_json FROM channel_pairing_requests WHERE channel_key = ?")?;
                let mapped = st.query_map([channel], |r| Ok((text(r.get_ref(0)?), text(r.get_ref(1)?))))?;
                mapped.collect::<Result<Vec<_>, _>>()
            })()
            .unwrap_or_default()
        };
        for (account, entry, at) in rows {
            let Some(entry) = entry.filter(|e| is_sender(e)) else {
                continue;
            };
            let label = requests
                .iter()
                .find(|(id, _)| id.as_deref() == Some(entry.as_str()))
                .and_then(|(_, meta)| label_from_meta(meta.clone()));
            senders.push(AllowedSender {
                channel: channel.to_string(),
                account_id: account.unwrap_or_else(|| "default".into()),
                sender_id: entry,
                label,
                at,
            });
            if senders.len() >= ENTRY_CAP {
                return AllowListRead {
                    senders,
                    error: None,
                    canonical: true,
                };
            }
        }
    }
    AllowListRead {
        senders,
        error: None,
        canonical: true,
    }
}

/// Pending pairing requests for the given channels, read straight from the store.
pub fn read_pending(db_path: &Path, channels: &[&str], log: &dyn Fn(&str)) -> PendingRead {
    if channels.is_empty() || !db_path.exists() {
        return PendingRead::default();
    }
    let db = match open(db_path) {
        Ok(db) => db,
        Err(m) => {
            log(&format!("[channels] could not open OpenClaw's state database: {m}"));
            return PendingRead {
                error: Some(pairing_failure(&m)),
                ..Default::default()
            };
        }
    };
    let mut pairings = Vec::new();
    for channel in channels {
        let rows = (|| {
            let mut st = db.prepare(
                "SELECT request_id, code, created_at, meta_json FROM channel_pairing_requests WHERE channel_key = ? ORDER BY created_at",
            )?;
            let mapped = st.query_map([channel], |r| {
                Ok((
                    text(r.get_ref(0)?),
                    text(r.get_ref(1)?),
                    text_stamp(r.get_ref(2)?),
                    text(r.get_ref(3)?),
                ))
            })?;
            mapped.collect::<Result<Vec<_>, _>>()
        })();
        let rows = match rows {
            Ok(r) => r,
            Err(e) => {
                let m = sqlite_message(&e);
                if m.to_lowercase().contains("no such table") {
                    return PendingRead::default();
                }
                log(&format!("[channels] could not read OpenClaw's pending pairings: {m}"));
                return PendingRead {
                    error: Some(pairing_failure(&m)),
                    ..Default::default()
                };
            }
        };
        for (id, code, created, meta) in rows {
            let (Some(sender_id), Some(code)) = (id, code) else {
                continue;
            };
            pairings.push(PendingRow {
                channel: channel.to_string(),
                sender_id,
                code,
                label: label_from_meta(meta),
                created_at: created,
            });
            if pairings.len() >= ENTRY_CAP {
                return PendingRead {
                    pairings,
                    error: None,
                    canonical: true,
                };
            }
        }
    }
    PendingRead {
        pairings,
        error: None,
        canonical: true,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A database shaped like OpenClaw 2026.9's, with these rows.
    pub fn db(
        dir: &Path,
        allow: &[(&str, &str, &str, i64)],
        requests: &[(&str, &str, &str, &str, &str)],
    ) -> std::path::PathBuf {
        let p = dir.join("openclaw.sqlite");
        let c = Connection::open(&p).expect("open");
        c.execute_batch(
            "CREATE TABLE channel_pairing_allow_entries (channel_key TEXT, account_id TEXT, entry TEXT, sort_order INTEGER, updated_at INTEGER);
             CREATE TABLE channel_pairing_requests (channel_key TEXT, account_id TEXT, request_id TEXT, code TEXT, created_at TEXT, last_seen_at TEXT, meta_json TEXT);",
        )
        .expect("schema");
        for (i, (ch, acct, entry, at)) in allow.iter().enumerate() {
            c.execute(
                "INSERT INTO channel_pairing_allow_entries VALUES (?, ?, ?, ?, ?)",
                rusqlite::params![ch, acct, entry, i as i64, at],
            )
            .expect("row");
        }
        for (ch, id, code, created, meta) in requests {
            c.execute(
                "INSERT INTO channel_pairing_requests VALUES (?, 'default', ?, ?, ?, NULL, ?)",
                rusqlite::params![ch, id, code, created, meta],
            )
            .expect("row");
        }
        p
    }

    fn quiet(_: &str) {}

    #[test]
    fn the_allow_list_with_labels_from_pending_requests() {
        let d = tempfile::tempdir().expect("dir");
        let p = db(
            d.path(),
            &[
                ("telegram", "default", "111", 1_760_000_000_000),
                ("telegram", "default", "*", 0),
                ("telegram", "default", "accessGroup:team", 0),
                ("telegram", "default", "222", 1_760_000_000),
                ("slack", "default", "U1", -5),
            ],
            &[(
                "telegram",
                "222",
                "ABCD",
                "2026-10-12T09:59:00.000Z",
                r#"{"username":"lydia"}"#,
            )],
        );
        let r = read_allow_list(&p, &["telegram", "slack", "whatsapp"], &quiet);
        assert!(r.canonical);
        assert_eq!(r.error, None);
        let ids: Vec<&str> = r.senders.iter().map(|s| s.sender_id.as_str()).collect();
        assert_eq!(ids, ["111", "222", "U1"]);
        assert_eq!(r.senders[1].label.as_deref(), Some("@lydia"));
        assert_eq!(r.senders[0].at.as_deref(), Some("2025-10-09T08:53:20.000Z"));
        assert_eq!(
            r.senders[1].at.as_deref(),
            Some("2025-10-09T08:53:20.000Z"),
            "seconds read as seconds"
        );
        assert_eq!(r.senders[2].at, None, "not shown as 1970");
    }

    #[test]
    fn no_database_or_no_tables_is_not_an_error_and_a_broken_one_says_so_plainly() {
        let d = tempfile::tempdir().expect("dir");
        let none = read_allow_list(&d.path().join("missing.sqlite"), &["telegram"], &quiet);
        assert_eq!(none, AllowListRead::default());
        let p = d.path().join("old.sqlite");
        Connection::open(&p)
            .expect("open")
            .execute_batch("CREATE TABLE other (x);")
            .expect("t");
        assert_eq!(read_allow_list(&p, &["telegram"], &quiet), AllowListRead::default());
        assert_eq!(read_pending(&p, &["telegram"], &quiet), PendingRead::default());
        let junk = d.path().join("junk.sqlite");
        std::fs::write(&junk, b"not a database at all, just some bytes that go on long enough").expect("w");
        let r = read_allow_list(&junk, &["telegram"], &quiet);
        assert!(!r.canonical);
        let e = r.error.expect("error");
        assert!(!e.busy);
        assert!(e.message.starts_with("Your agent's own list could not"));
    }

    #[test]
    fn pending_requests_in_order_with_their_codes() {
        let d = tempfile::tempdir().expect("dir");
        let p = db(
            d.path(),
            &[],
            &[
                ("telegram", "9", "ZZZZ", "1760000000000", "{}"),
                (
                    "telegram",
                    "8",
                    "AAAA",
                    "2026-10-12T09:59:00+02:00",
                    r#"{"name":"Ann"}"#,
                ),
                ("telegram", "", "BBBB", "x", "{}"),
            ],
        );
        let r = read_pending(&p, &["telegram"], &quiet);
        assert!(r.canonical);
        assert_eq!(r.pairings.len(), 2);
        assert_eq!(r.pairings[0].sender_id, "9");
        assert_eq!(r.pairings[0].created_at.as_deref(), Some("2025-10-09T08:53:20.000Z"));
        assert_eq!(r.pairings[1].label.as_deref(), Some("Ann"));
        assert_eq!(r.pairings[1].created_at.as_deref(), Some("2026-10-12T07:59:00.000Z"));
    }

    #[test]
    fn labels_from_what_each_channel_stores() {
        use serde_json::json;
        let l = |v: Value| label_of(&v);
        // Telegram: first and last name and username, no `name`. Read as `name` alone, a Telegram
        // user with no username showed as a bare id.
        assert_eq!(
            l(json!({"firstName": "Ada", "lastName": "Lovelace", "username": "ada", "accountId": "default"}))
                .as_deref(),
            Some("Ada Lovelace (@ada)")
        );
        assert_eq!(
            l(json!({"firstName": "Ada", "accountId": "default"})).as_deref(),
            Some("Ada")
        );
        assert_eq!(l(json!({"lastName": " Lovelace "})).as_deref(), Some("Lovelace"));
        assert_eq!(l(json!({"username": "@ada"})).as_deref(), Some("@ada"));
        assert_eq!(
            l(json!({"accountId": "default"})),
            None,
            "the console falls back to the id"
        );
        // Slack and WhatsApp: `name`.
        assert_eq!(
            l(json!({"name": "Ann", "teamId": "T1", "senderId": "U1"})).as_deref(),
            Some("Ann")
        );
        assert_eq!(l(json!({"displayName": "Ann"})).as_deref(), Some("Ann"));
        assert_eq!(l(json!({"title": "Ops room"})).as_deref(), Some("Ops room"));
        assert_eq!(l(json!({"name": "  ", "firstName": ""})), None);
        // Capped at what the console accepts with an approval, on a char boundary.
        let long = l(json!({"firstName": "\u{00e9}".repeat(200)})).expect("label");
        assert_eq!(long.chars().count(), 120);
    }

    #[test]
    fn the_date_forms_date_takes() {
        let t = |s: &str| parse_offset_iso(s).map(iso_ms);
        assert_eq!(t("2026-10-12 09:59:00").as_deref(), Some("2026-10-12T09:59:00.000Z"));
        assert_eq!(
            t("2026-10-12T09:59:00.123456Z").as_deref(),
            Some("2026-10-12T09:59:00.123Z")
        );
        assert_eq!(
            t("2026-10-12T09:59:00+0200").as_deref(),
            Some("2026-10-12T07:59:00.000Z")
        );
        assert_eq!(
            t("2026-10-12T09:59:00-01:30").as_deref(),
            Some("2026-10-12T11:29:00.000Z")
        );
        assert_eq!(
            t("aaaaaaaaaaaaaaaaaaaaaa€aaaa"),
            None,
            "no panic on text that is not a date"
        );
        assert_eq!(t("2026-10-12T09:59:00+2"), None);
    }

    #[test]
    fn busy_words_are_told_apart() {
        assert!(allow_failure("SQLITE_BUSY database is locked").busy);
        assert!(!allow_failure("SQLITE_CANTOPEN unable to open database file").busy);
        assert_eq!(
            allow_failure("unable to open database file").message,
            "Your agent's own list could not be opened. Restarting the agent clears this."
        );
        assert!(pairing_failure("database is locked").busy);
    }

    #[test]
    fn a_wal_database_that_cannot_be_brought_up_gets_the_restart_hint() {
        for code in [
            rusqlite::ffi::SQLITE_READONLY_CANTINIT,
            rusqlite::ffi::SQLITE_READONLY_RECOVERY,
        ] {
            let e = rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(code), None);
            assert_eq!(
                allow_failure(&sqlite_message(&e)).message,
                "Your agent's own list could not be opened. Restarting the agent clears this."
            );
        }
        let plain = rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_READONLY), None);
        assert_eq!(
            allow_failure(&sqlite_message(&plain)).message,
            "Your agent's own list could not be read."
        );
    }
}
