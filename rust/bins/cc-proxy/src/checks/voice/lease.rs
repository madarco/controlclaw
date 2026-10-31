//! The leases a voice socket lives under (addon.py `meeting_lease`, `phone_lease`,
//! `kill_switched`). The files are read again on every call: missing, truncated or unreadable
//! revokes every lease, and so does the agent's kill switch.

use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Map, Value};

use super::Voice;

pub const MEETING_MAX_BYTES: f64 = 512.0 * 1024.0 * 1024.0;
pub const MEETING_MAX_SECONDS: f64 = 4.0 * 60.0 * 60.0;

#[allow(clippy::expect_used)] // fixed expressions, checked by the tests
static MEETING_ID: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-f0-9]{32}$").expect("valid"));
#[allow(clippy::expect_used)]
static PHONE_ID: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-f0-9]{64}$").expect("valid"));

/// `type(v) in (int, float)`: a number, never a boolean.
fn num(lease: &Map<String, Value>, key: &str) -> Option<f64> {
    match lease.get(key) {
        Some(Value::Number(n)) => n.as_f64(),
        _ => None,
    }
}

fn read_map(path: &std::path::Path) -> Option<Map<String, Value>> {
    let raw = std::fs::read(path).ok()?;
    let text = std::str::from_utf8(&raw).ok()?;
    match crate::checks::json::loads(text).ok()? {
        Value::Object(m) => Some(m),
        _ => None,
    }
}

impl Voice {
    /// `kill_switched`: this agent is under an emergency stop. An agent the map does not name is not.
    pub fn kill_switched(&self, vm_id: &str) -> bool {
        self.identities
            .all()
            .iter()
            .find(|e| e.get("vm_id").and_then(Value::as_str) == Some(vm_id))
            .is_some_and(|e| e.get("locked") == Some(&Value::Bool(true)))
    }

    /// `meeting_lease`.
    pub fn meeting_lease(&self, vm_id: &str, lease_id: Option<&str>) -> Option<Map<String, Value>> {
        if vm_id.is_empty() || self.kill_switched(vm_id) {
            return None;
        }
        let lease = match read_map(&self.meeting_path)?.remove(vm_id)? {
            Value::Object(l) => l,
            _ => return None,
        };
        let now = crate::checks::content::rules::now();
        let (start, expiry, deadline, budget) = (
            num(&lease, "started")?,
            num(&lease, "expires")?,
            num(&lease, "deadline")?,
            num(&lease, "max_bytes")?,
        );
        if !(self.started <= start
            && start <= now
            && now < expiry
            && expiry <= deadline.min(now + 60.0)
            && start < deadline
            && deadline <= start + MEETING_MAX_SECONDS
            && 0.0 < budget
            && budget <= MEETING_MAX_BYTES)
        {
            return None;
        }
        let id = lease.get("id").and_then(Value::as_str)?;
        if !MEETING_ID.is_match(id) || lease_id.is_some_and(|l| l != id) {
            return None;
        }
        Some(lease)
    }

    /// `phone_lease`: the call lease `lease_id`, or without one the first that is neither reserved
    /// nor in use.
    pub fn phone_lease(&self, vm_id: &str, lease_id: Option<&str>) -> Option<Map<String, Value>> {
        let usage = self.usage.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        self.phone_lease_in(&usage, vm_id, lease_id)
    }

    /// [`Self::phone_lease`] with the counters already held, so a request picks a free lease and
    /// reserves it in one step.
    pub(super) fn phone_lease_in(
        &self,
        usage: &std::collections::HashMap<String, super::Usage>,
        vm_id: &str,
        lease_id: Option<&str>,
    ) -> Option<Map<String, Value>> {
        if vm_id.is_empty() || self.kill_switched(vm_id) {
            return None;
        }
        let leases = match read_map(&self.phone_path)?.remove(vm_id) {
            Some(Value::Array(a)) => a,
            Some(v) => vec![v],
            None => vec![Value::Null],
        };
        let now = crate::checks::content::rules::now();
        let mut found = None;
        {
            for v in leases {
                let Value::Object(l) = v else { continue };
                let id = l.get("id");
                let pick = match lease_id {
                    Some(want) => id.and_then(Value::as_str) == Some(want),
                    None => {
                        // An id that cannot be a key (a list) raised in the addon: no lease.
                        if id.is_some_and(|i| i.is_array() || i.is_object()) {
                            return None;
                        }
                        let u = id.and_then(Value::as_str).and_then(|i| usage.get(i));
                        u.is_none_or(|u| u.reserved_until <= now && u.active.is_none())
                    }
                };
                if pick {
                    found = Some(l);
                    break;
                }
            }
        }
        let lease = found?;
        if lease.get("purpose").and_then(Value::as_str) != Some("phone") {
            return None;
        }
        let id = lease.get("id").and_then(Value::as_str)?;
        if !PHONE_ID.is_match(id) {
            return None;
        }
        let (start, expiry, deadline) = (
            num(&lease, "started")?,
            num(&lease, "expires")?,
            num(&lease, "deadline")?,
        );
        if !(self.started <= start
            && start <= now
            && now < expiry
            && expiry <= deadline.min(now + 5.0)
            && start < deadline
            && deadline <= start + 3600.0)
            || lease_id.is_some_and(|l| l != id)
        {
            return None;
        }
        Some(lease)
    }

    /// `voice_lease`: the lease this socket was admitted under, still bound to the same model.
    pub fn voice_lease(&self, voice: &Map<String, Value>) -> Option<Map<String, Value>> {
        let s = |k: &str| voice.get(k).and_then(Value::as_str).unwrap_or("");
        let lease = if s("purpose") == "phone" {
            self.phone_lease(s("vm_id"), Some(s("lease_id")))
        } else {
            self.meeting_lease(s("vm_id"), Some(s("lease_id")))
        }?;
        let speech = lease.get("speech").and_then(Value::as_object)?;
        (speech.get("provider").and_then(Value::as_str) == Some(s("provider"))
            && speech.get("model").and_then(Value::as_str) == Some(s("model")))
        .then_some(lease)
    }
}

/// `wake_sessions`: how many sessions of a wake-mode meeting may carry audio (0: not one).
pub fn wake_sessions(lease: &Map<String, Value>, family: &str, purpose: &str) -> u64 {
    let n = match lease.get("wake_sessions") {
        Some(Value::Number(n)) if !n.is_f64() => n.as_u64(),
        _ => None,
    };
    match n {
        Some(n) if purpose == "meeting" && family == "live" && 1 < n && n <= super::WAKE_MAX_SESSIONS => n,
        _ => 0,
    }
}
