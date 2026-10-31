//! The admin's password after setup: `POST /api/admin/password {current, new}` from a signed-in
//! session, and [`reset`] for the operator who forgot it (`mitm-agent reset-admin`).

use std::net::IpAddr;

use rusqlite::{OptionalExtension, params};
use serde_json::json;

use super::{Admin, PASSWORD_MIN, SETUP_HASH, Session, reply, sha, token};
use crate::db::Db;

impl Admin {
    /// Checks the current password as login does (the same throttle and argon2 permits), sets the
    /// new one and ends every other session. This one stays signed in.
    pub(super) async fn change_password(&self, ip: IpAddr, sess: &Session, current: &str, new: &str) -> cc_http::Resp {
        // Checked first: it tests no password, so it takes nothing from the login budget.
        if new.chars().count() < PASSWORD_MIN {
            return reply(
                400,
                json!({"error": format!("The password needs at least {PASSWORD_MIN} characters")}),
            );
        }
        if !self.try_begin(ip) {
            return reply(429, json!({"error": "Too many tries. Wait a minute."}));
        }
        let hash: Option<String> = self
            .db
            .lock()
            .query_row(
                "SELECT password_hash FROM admin_users WHERE id = ?1",
                [sess.user_id],
                |r| r.get(0),
            )
            .optional()
            .ok()
            .flatten();
        let Some(hash) = hash else {
            return reply(409, json!({"error": "No admin. Set one up."}));
        };
        let (pw, verified) = (current.to_string(), hash.clone());
        if !self
            .argon(move || Self::check_password(&pw, &verified))
            .await
            .unwrap_or(false)
        {
            // Not 401: the session is fine, and the panel reads a 401 as "signed out".
            return reply(400, json!({"error": "The current password is wrong"}));
        }
        let pw = new.to_string();
        let hashed = self
            .argon(move || Self::hash_password(&pw))
            .await
            .unwrap_or_else(|| Err("argon2 did not run".into()));
        let changed = hashed.and_then(|h| self.store_password(sess, &hash, &h));
        match changed {
            Ok(None) => reply(
                409,
                json!({"error": "The password was changed or reset meanwhile. Sign in again and retry."}),
            ),
            Ok(Some(ended)) => {
                self.succeeded(ip);
                tracing::info!("[cc-local] the admin password was changed; {ended} other session(s) ended");
                reply(200, json!({"ok": true, "signedOut": ended}))
            }
            Err(e) => {
                tracing::error!("[cc-local] password change: {e}");
                reply(500, json!({"error": "Failed"}))
            }
        }
    }
}

impl Admin {
    /// Sets `new_hash` only while the admin's hash is still `verified`, the one the current password
    /// was checked against, and ends every other session. `None` when another change or a reset
    /// came first: nothing is written.
    pub(super) fn store_password(
        &self,
        sess: &Session,
        verified: &str,
        new_hash: &str,
    ) -> Result<Option<usize>, String> {
        let mut c = self.db.lock();
        let tx = c.transaction().map_err(|e| e.to_string())?;
        let updated = tx
            .execute(
                "UPDATE admin_users SET password_hash = ?1 WHERE id = ?2 AND password_hash = ?3",
                params![new_hash, sess.user_id, verified],
            )
            .map_err(|e| e.to_string())?;
        if updated != 1 {
            return Ok(None);
        }
        let ended = tx
            .execute(
                "DELETE FROM sessions WHERE user_id = ?1 AND token_hash <> ?2",
                params![sess.user_id, sess.token_hash],
            )
            .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(Some(ended))
    }
}

/// A forgotten password: removes the admin, ends every session and returns a fresh one-time setup
/// token. A running firewall reads the database each time, so it asks for setup at once.
pub fn reset(db: &Db) -> Result<String, String> {
    let t = token();
    let mut c = db.lock();
    let tx = c.transaction().map_err(|e| e.to_string())?;
    tx.execute("DELETE FROM sessions", []).map_err(|e| e.to_string())?;
    tx.execute("DELETE FROM admin_users", []).map_err(|e| e.to_string())?;
    tx.execute(
        "INSERT INTO settings (key, value) VALUES (?1, ?2) ON CONFLICT (key) DO UPDATE SET value = excluded.value",
        params![SETUP_HASH, sha(&t)],
    )
    .map_err(|e| e.to_string())?;
    tx.commit().map_err(|e| e.to_string())?;
    Ok(t)
}
