//! The SQLite file behind the local control plane: one connection, behind a lock, migrated by
//! `user_version`. Every table here stands in for a SaaS table the contract reads or writes.

use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use rusqlite::Connection;

/// Version 1, then each later one (2: the panel's API; 3 and 4: pairing; 5: WireGuard). Later versions append to
/// [`MIGRATIONS`]; a migration that ran is never edited.
pub(crate) const MIGRATIONS: &[&str] = &[
    r#"
CREATE TABLE agents (
    vm_id TEXT PRIMARY KEY,
    role TEXT NOT NULL,              -- mitm (this firewall), openclaw, gbrain
    name TEXT NOT NULL,
    private_ip TEXT,
    hostname TEXT,
    access_hostname TEXT,
    public_key TEXT,                 -- SPKI PEM; a box token from this vm verifies with it
    status TEXT NOT NULL DEFAULT 'running',
    created_at INTEGER NOT NULL
);
CREATE TABLE egress_rules (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    match_domain TEXT NOT NULL,
    match_path TEXT,
    match_method TEXT,
    match_port INTEGER,
    vm_id TEXT,
    effect TEXT NOT NULL DEFAULT 'allow',
    exit TEXT,
    exit_country TEXT,
    priority INTEGER NOT NULL DEFAULT 1000,
    enabled INTEGER NOT NULL DEFAULT 1,
    ai_review INTEGER NOT NULL DEFAULT 0,
    ai_policy TEXT,
    created_at INTEGER NOT NULL
);
CREATE TABLE ai_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    settings TEXT NOT NULL           -- the `ai` object of /egress-rules, or null
);
CREATE TABLE permission_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vm_id TEXT NOT NULL,             -- the box that raised it
    external_id TEXT NOT NULL,       -- the box's permission_id
    kind TEXT NOT NULL,
    title TEXT NOT NULL,
    detail TEXT NOT NULL,            -- JSON
    status TEXT NOT NULL DEFAULT 'pending',
    agent_vm_ids TEXT NOT NULL DEFAULT '[]',
    expires_at INTEGER,
    resolved_by TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE (vm_id, external_id)
);
CREATE TABLE activity_raw (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vm_id TEXT,
    source TEXT NOT NULL,
    status TEXT NOT NULL,
    dedupe_key TEXT NOT NULL UNIQUE,
    occurred_at INTEGER NOT NULL,
    summary TEXT NOT NULL,
    record TEXT NOT NULL,            -- the record as the box sent it
    created_at INTEGER NOT NULL
);
CREATE INDEX activity_raw_occurred ON activity_raw (occurred_at);
CREATE TABLE activity_hourly (
    hour INTEGER NOT NULL,           -- epoch seconds at the top of the hour
    vm_id TEXT NOT NULL,             -- '' for traffic with no agent
    source TEXT NOT NULL,
    status TEXT NOT NULL,
    count INTEGER NOT NULL,
    PRIMARY KEY (hour, vm_id, source, status)
);
CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE admin_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,     -- argon2id, PHC string
    created_at INTEGER NOT NULL
);
CREATE TABLE sessions (
    token_hash TEXT PRIMARY KEY,     -- sha256 of the cookie; the cookie itself is never stored
    user_id INTEGER NOT NULL REFERENCES admin_users (id) ON DELETE CASCADE,
    csrf TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
"#,
    r#"
ALTER TABLE egress_rules ADD COLUMN updated_at INTEGER;
-- The panel's activity tabs and overview read by source and time.
CREATE INDEX activity_raw_source ON activity_raw (source, occurred_at);
UPDATE egress_rules SET updated_at = created_at;
-- The user's own model keys, as the panel lists them. The key itself is only on the firewall
-- (its LLM store); here a hint, the placeholder agents hold, and whether the firewall took it.
CREATE TABLE llm_keys (
    id TEXT PRIMARY KEY,             -- the firewall's credentialId
    provider TEXT NOT NULL UNIQUE,   -- openai, anthropic, google, openrouter, vercel_gateway
    label TEXT,
    hint TEXT NOT NULL,
    placeholder TEXT NOT NULL,
    state TEXT NOT NULL,             -- active, failed
    last_error TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
"#,
    r#"
CREATE TABLE pairing_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT NOT NULL UNIQUE,       -- normalized; kept until used or expired (the HMAC needs it)
    name TEXT,                       -- the agent's name, when the admin gave one
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
ALTER TABLE agents ADD COLUMN paired_at INTEGER;
"#,
    r#"
ALTER TABLE pairing_codes ADD COLUMN address TEXT;  -- the agent's address, when the admin gave one
ALTER TABLE pairing_codes ADD COLUMN replace INTEGER NOT NULL DEFAULT 0; -- may replace an agent there
ALTER TABLE agents ADD COLUMN unpair_sha256 TEXT;    -- sha256 of the secret that unpairs it (POST /unpair)
"#,
    r#"
ALTER TABLE agents ADD COLUMN wg_public_key TEXT;    -- its WireGuard key, when it pairs over the tunnel
-- A key is one peer: two agents with it would be one tunnel with two addresses.
CREATE UNIQUE INDEX agents_wg_public_key ON agents (wg_public_key) WHERE wg_public_key IS NOT NULL;
"#,
    r#"
ALTER TABLE agents ADD COLUMN agent_addr TEXT;       -- ip:port where its vm-agent listens, from pairing
"#,
];

/// The rule a new database file starts with, so a new firewall lets nothing out until the admin adds
/// rules (`[]` would let everything out). Written in the same transaction as the first migration:
/// a database that exists has it, or had it and the admin deleted it, and it never comes back.
pub const BLOCK_ALL_ID: &str = "block-all";
pub const BLOCK_ALL_NAME: &str = "Block everything until you add rules";
/// Last: a rule the admin adds runs before it.
pub const BLOCK_ALL_PRIORITY: i64 = 100_000;

pub struct Db {
    conn: Mutex<Connection>,
    /// The file was new at this open (no migration had run).
    created: bool,
}

impl Db {
    /// The firewall's file; a new one starts with the block-all rule.
    pub fn open(path: &Path) -> rusqlite::Result<Self> {
        Self::from(Connection::open(path)?, true)
    }

    /// For tests and the conformance facade: empty, no rule.
    pub fn memory() -> rusqlite::Result<Self> {
        Self::from(Connection::open_in_memory()?, false)
    }

    fn from(c: Connection, seed: bool) -> rusqlite::Result<Self> {
        c.execute_batch("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;")?;
        let version: usize = c.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        for (i, m) in MIGRATIONS.iter().enumerate().skip(version) {
            let rule = if i == 0 && seed {
                format!(
                    "INSERT INTO egress_rules (id, name, match_domain, effect, priority, enabled, created_at)
                     VALUES ('{BLOCK_ALL_ID}', '{BLOCK_ALL_NAME}', '*', 'block', {BLOCK_ALL_PRIORITY}, 1, {});",
                    now_s()
                )
            } else {
                String::new()
            };
            c.execute_batch(&format!("BEGIN; {m} {rule} PRAGMA user_version = {}; COMMIT;", i + 1))?;
        }
        Ok(Self {
            conn: Mutex::new(c),
            created: version == 0,
        })
    }

    /// The database was made at this open, not found from an earlier one.
    pub fn created(&self) -> bool {
        self.created
    }

    /// The connection. A panic while it was held does not poison it for everyone after.
    pub fn lock(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn setting(&self, key: &str) -> Option<String> {
        self.lock()
            .query_row("SELECT value FROM settings WHERE key = ?1", [key], |r| r.get(0))
            .ok()
    }

    pub fn delete_setting(&self, key: &str) -> rusqlite::Result<()> {
        self.lock().execute("DELETE FROM settings WHERE key = ?1", [key])?;
        Ok(())
    }

    pub fn set_setting(&self, key: &str, value: &str) -> rusqlite::Result<()> {
        self.lock().execute(
            "INSERT INTO settings (key, value) VALUES (?1, ?2) ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            [key, value],
        )?;
        Ok(())
    }
}

/// Seconds since the epoch.
pub fn now_s() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(db: &Db) -> Vec<String> {
        let c = db.lock();
        let mut q = c.prepare("SELECT id FROM egress_rules").expect("q");
        q.query_map([], |r| r.get(0))
            .expect("rows")
            .collect::<rusqlite::Result<_>>()
            .expect("ids")
    }

    #[test]
    fn a_new_file_has_the_block_all_rule_from_its_first_migration() {
        let d = tempfile::tempdir().expect("dir");
        let p = d.path().join("local.db");
        let db = Db::open(&p).expect("open");
        assert!(db.created());
        assert_eq!(rules(&db), [BLOCK_ALL_ID]);
        // Version 1 commits with the rule in it: a start that stops after it still has the rule.
        let at_v1: i64 = db
            .lock()
            .query_row("SELECT COUNT(*) FROM egress_rules WHERE id = ?1", [BLOCK_ALL_ID], |r| {
                r.get(0)
            })
            .expect("count");
        assert_eq!(at_v1, 1);
        db.lock().execute("DELETE FROM egress_rules", []).expect("delete");
        drop(db);
        let db = Db::open(&p).expect("reopen");
        assert!(rules(&db).is_empty(), "a deleted rule does not come back");
        assert!(
            Db::memory().map(|m| rules(&m).is_empty()).expect("memory"),
            "not in a test database"
        );
    }

    #[test]
    fn a_crash_after_the_first_migration_still_has_the_rule() {
        // The first migration and the rule in one transaction, as `from` runs it, then a stop
        // before the later migrations: the next open finds version 1 and the rule.
        let d = tempfile::tempdir().expect("dir");
        let p = d.path().join("local.db");
        {
            let c = Connection::open(&p).expect("conn");
            c.execute_batch(&format!(
                "BEGIN; {} INSERT INTO egress_rules (id, name, match_domain, effect, priority, enabled, created_at)
                 VALUES ('{BLOCK_ALL_ID}', 'x', '*', 'block', 1, 1, 0); PRAGMA user_version = 1; COMMIT;",
                MIGRATIONS[0]
            ))
            .expect("v1");
        }
        let db = Db::open(&p).expect("open");
        assert!(!db.created());
        assert_eq!(rules(&db), [BLOCK_ALL_ID]);
    }

    #[test]
    fn migrates_once_and_keeps_settings() {
        let d = tempfile::tempdir().expect("dir");
        let p = d.path().join("local.db");
        let db = Db::open(&p).expect("open");
        assert!(db.created());
        db.set_setting("a", "1").expect("set");
        db.set_setting("a", "2").expect("set again");
        drop(db);
        let db = Db::open(&p).expect("reopen");
        assert!(!db.created(), "found, not made");
        assert_eq!(db.setting("a").as_deref(), Some("2"));
        let v: usize = db.lock().query_row("PRAGMA user_version", [], |r| r.get(0)).expect("v");
        assert_eq!(v, MIGRATIONS.len());
    }
}
