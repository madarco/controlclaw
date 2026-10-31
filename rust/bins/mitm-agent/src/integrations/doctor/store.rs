//! Doctor's transcripts (`doctor-store.ts`): one sealed file a session, kept seven days. Content is
//! never backed up or returned through the command queue.

use std::path::PathBuf;
use std::sync::LazyLock;

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::capture::CaptureRecord;
use super::repair::RepairRecord;
use super::stream::Event;
use crate::integrations::js;

pub const DOCTOR_RETENTION_MS: i64 = 7 * 24 * 60 * 60_000;
static ID: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_-]{8,80}$").expect("pattern"));

pub fn valid_id(id: &str) -> bool {
    ID.is_match(id)
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Transcript {
    pub session_id: String,
    pub vm_id: String,
    pub created_at: i64,
    pub retain_until: i64,
    /// Absent from a record written before the field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub state: String,
    pub events: Vec<Event>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repair: Option<RepairRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture: Option<CaptureRecord>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

pub struct DoctorStore {
    dir: PathBuf,
    box_key: String,
    org_id: String,
    box_id: String,
    now: super::Clock,
}

impl DoctorStore {
    pub fn new(
        dir: PathBuf,
        box_key: String,
        org_id: String,
        box_id: String,
        now: super::Clock,
    ) -> Result<Self, String> {
        {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&dir)
                .map_err(|_| "the Doctor transcript folder could not be made".to_string())?;
        }
        let s = Self {
            dir,
            box_key,
            org_id,
            box_id,
            now,
        };
        s.prune();
        Ok(s)
    }

    fn path(&self, id: &str) -> Result<PathBuf, String> {
        if !valid_id(id) {
            return Err("Invalid Doctor session.".into());
        }
        Ok(self.dir.join(format!("{id}.enc")))
    }

    fn aad(&self, id: &str) -> String {
        format!("{}:{}:doctor:transcript:{id}", self.org_id, self.box_id)
    }

    /// The transcript, or None (none, past its time, or one that will not open).
    pub fn get(&self, id: &str) -> Result<Option<Transcript>, String> {
        let path = self.path(id)?;
        let v = cc_crypto::enc_file::load_encrypted_json(&path, &self.box_key, &self.aad(id))
            .map_err(|_| "Doctor transcript unreadable.".to_string())?;
        let Some(v) = v else { return Ok(None) };
        let r: Transcript = serde_json::from_value(v).map_err(|_| "Doctor transcript unreadable.".to_string())?;
        if r.retain_until <= (self.now)() {
            self.delete(id)?;
            return Ok(None);
        }
        Ok(Some(r))
    }

    pub fn create(&self, id: &str, vm_id: &str, kind: &str, repair: Option<RepairRecord>) -> Result<(), String> {
        if self.get(id)?.is_some() {
            return Err("Doctor transcript already exists.".into());
        }
        let now = (self.now)();
        self.save(&Transcript {
            session_id: id.into(),
            vm_id: vm_id.into(),
            created_at: now,
            retain_until: now + DOCTOR_RETENTION_MS,
            kind: Some(kind.into()),
            state: "proposed".into(),
            events: vec![],
            repair,
            capture: (kind == "template-capture").then(CaptureRecord::default),
            extra: Map::new(),
        })
    }

    pub fn set_capture(&self, id: &str, capture: CaptureRecord) -> Result<(), String> {
        let mut r = self.get(id)?.ok_or("Doctor transcript unavailable.")?;
        r.capture = Some(capture);
        self.save(&r)
    }

    pub fn set_repair(&self, id: &str, repair: RepairRecord) -> Result<(), String> {
        let mut r = self.get(id)?.ok_or("Doctor transcript unavailable.")?;
        r.repair = Some(repair);
        self.save(&r)
    }

    fn save(&self, r: &Transcript) -> Result<(), String> {
        let v = serde_json::to_value(r).map_err(|_| "Doctor transcript could not be written.".to_string())?;
        cc_crypto::enc_file::save_encrypted_json(
            &self.path(&r.session_id)?,
            &v,
            &self.box_key,
            &self.aad(&r.session_id),
        )
        .map_err(|_| "Doctor transcript could not be written.".to_string())
    }

    pub fn append(&self, id: &str, event: Event, state: &str) -> Result<(), String> {
        let mut r = self.get(id)?.ok_or("Doctor transcript unavailable.")?;
        r.events.push(event);
        r.state = state.into();
        // Bound disk and browser memory: the newest completed events, with their sequence numbers.
        while r.events.len() > 2000
            || js::stringify(&serde_json::to_value(&r.events).unwrap_or(Value::Null)).len() > 8 * 1024 * 1024
        {
            r.events.remove(0);
        }
        self.save(&r)
    }

    pub fn delete(&self, id: &str) -> Result<(), String> {
        match std::fs::remove_file(self.path(id)?) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err("Doctor transcript could not be deleted.".into()),
        }
    }

    pub fn prune(&self) {
        let Ok(dir) = std::fs::read_dir(&self.dir) else { return };
        for f in dir.flatten() {
            let name = f.file_name().to_string_lossy().into_owned();
            if let Some(id) = name.strip_suffix(".enc.tmp")
                && valid_id(id)
            {
                let _ = std::fs::remove_file(f.path());
                continue;
            }
            let Some(id) = name.strip_suffix(".enc").filter(|i| valid_id(i)) else {
                continue;
            };
            // Unreadable ciphertext is never copied or served; its mtime bounds retention too.
            if self.get(id).is_err() {
                let old = f
                    .metadata()
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_millis() as i64 + DOCTOR_RETENTION_MS <= (self.now)())
                    .unwrap_or(false);
                if old {
                    let _ = self.delete(id);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicI64, Ordering};

    #[test]
    fn content_is_sealed_to_org_box_and_session_kept_across_a_restart_and_gone_on_expiry() {
        let dir = tempfile::tempdir().expect("dir");
        let key = cc_crypto::secret_store::generate_box_key();
        let clock = Arc::new(AtomicI64::new(1000));
        let c = clock.clone();
        let now: super::super::Clock = Arc::new(move || c.load(Ordering::SeqCst));
        let s = DoctorStore::new(
            dir.path().to_path_buf(),
            key.clone(),
            "org".into(),
            "box".into(),
            now.clone(),
        )
        .expect("store");
        s.create("session-one", "agent", "repair-agent", None).expect("create");
        s.append(
            "session-one",
            Event {
                seq: 1,
                kind: "text".into(),
                text: "private-marker".into(),
                title: None,
            },
            "running",
        )
        .expect("append");
        let raw = std::fs::read_to_string(dir.path().join("session-one.enc")).expect("file");
        assert!(!raw.contains("private-marker"));
        assert!(
            s.create("session-one", "agent", "repair-agent", None).is_err(),
            "one transcript a session"
        );
        assert!(s.get("bad id").is_err());
        // Another box's key or another session's name does not open it.
        let other = DoctorStore::new(
            dir.path().to_path_buf(),
            key.clone(),
            "org".into(),
            "other-box".into(),
            now.clone(),
        )
        .expect("store");
        assert!(other.get("session-one").is_err());
        std::fs::copy(dir.path().join("session-one.enc"), dir.path().join("session-two.enc")).expect("copy");
        assert!(s.get("session-two").is_err());
        // A restart reads it again.
        let again = DoctorStore::new(dir.path().to_path_buf(), key, "org".into(), "box".into(), now).expect("store");
        assert_eq!(
            again.get("session-one").expect("get").expect("record").events[0].text,
            "private-marker"
        );
        clock.fetch_add(DOCTOR_RETENTION_MS, Ordering::SeqCst);
        assert!(again.get("session-one").expect("get").is_none());
        assert!(!dir.path().join("session-one.enc").exists());
    }
}
