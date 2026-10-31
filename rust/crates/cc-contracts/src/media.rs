//! `meeting-media.json` and `phone-media.json`: the voice and media leases the agent publishes
//! (meetings.ts `publish` every second, phone-stream.ts every 500 ms). The proxy re-reads them on
//! every call (`read_fresh`): missing, truncated or unreadable revokes every lease.
//!
//! The proxy checks every number's type and range itself (addon.py `meeting_lease`,
//! `phone_lease`), so these stay plain `Num`s rather than being validated here.

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

use crate::credentials::Speech;
use crate::{Extra, Maybe, Num};

/// One lease. Meetings: `id` is 32 hex; phone: 64 hex and `purpose: "phone"`.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct MediaLease {
    pub id: String,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub purpose: Maybe<String>,
    pub started: Num,
    pub expires: Num,
    pub deadline: Num,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub max_bytes: Maybe<Num>,
    /// Wake mode: voice sessions with audio allowed in this meeting.
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub wake_sessions: Maybe<Num>,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub full_agent: Maybe<bool>,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub present: Maybe<bool>,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub speech: Maybe<Speech>,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub voice_placeholder: Maybe<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// vm_id → that agent's meeting lease.
pub type MeetingMediaFile = IndexMap<String, MediaLease>;

/// vm_id → that agent's call leases. The addon also takes a single object (`[leases]`), which
/// only an older writer produced.
pub type PhoneMediaFile = IndexMap<String, OneOrMany<MediaLease>>;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum OneOrMany<T> {
    Many(Vec<T>),
    One(T),
}

impl<T> OneOrMany<T> {
    pub fn as_slice(&self) -> &[T] {
        match self {
            OneOrMany::Many(v) => v,
            OneOrMany::One(v) => std::slice::from_ref(v),
        }
    }
}

/// What the proxy reads: entries left as JSON, so one bad entry costs only its own agent its lease,
/// as in the addon (which checks each lease when it is asked for).
pub type RawLeases = IndexMap<String, serde_json::Value>;

/// That agent's meeting lease, if its entry has the shape (ranges are the proxy's to check).
pub fn meeting_lease_for(raw: &RawLeases, vm_id: &str) -> Option<MediaLease> {
    serde_json::from_value(raw.get(vm_id)?.clone()).ok()
}

/// That agent's call leases that have the shape; others are skipped.
pub fn phone_leases_for(raw: &RawLeases, vm_id: &str) -> Vec<MediaLease> {
    match raw.get(vm_id) {
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .filter_map(|v| serde_json::from_value(v.clone()).ok())
            .collect(),
        Some(v) => serde_json::from_value(v.clone()).into_iter().collect(),
        None => Vec::new(),
    }
}
