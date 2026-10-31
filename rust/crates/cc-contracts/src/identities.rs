//! `identities.json`: which agent a connection comes from, by source IP. The control plane sends
//! the map (`GET /api/vm-agent/identities`); the agent adds the flags it alone may set from its own
//! stores (`tailscale`, `locked`, `code_until`, `update_until`) and drops any the control plane
//! sent for them (index.ts `withKillSwitch`, `withUpdateWindows`).

use serde::{Deserialize, Serialize};

use crate::{Extra, Maybe, Num};

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct Identity {
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub vm_id: Maybe<String>,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub private_ip: Maybe<String>,
    /// The owner joined this box to their tailnet: `*.tailscale.com` passes through for it only.
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub tailscale: Maybe<bool>,
    /// Under an emergency stop: only the control plane passes.
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub locked: Maybe<bool>,
    /// Epoch seconds: a locked box may reach its channel hosts until then, to carry a code out.
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub code_until: Maybe<Num>,
    /// Epoch seconds: the box may reach the update package hosts until then.
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub update_until: Maybe<Num>,
    /// name, hostname, access_hostname, status, role from the control plane, and anything newer.
    #[serde(flatten)]
    pub extra: Extra,
}

impl Identity {
    /// The addon's checks are `is True`: only a real `true` counts.
    pub fn is_locked(&self) -> bool {
        self.locked.get() == Some(&true)
    }

    pub fn on_tailnet(&self) -> bool {
        self.tailscale.get() == Some(&true)
    }
}

pub type IdentitiesFile = Vec<Identity>;

/// `vm_id_for_ip`: the first entry whose `private_ip` is the source IP.
pub fn vm_id_for_ip<'a>(map: &'a [Identity], ip: &str) -> Option<&'a str> {
    if ip.is_empty() {
        return None;
    }
    map.iter()
        .find(|e| e.private_ip.get().map(String::as_str) == Some(ip))
        .and_then(|e| e.vm_id.get().map(String::as_str))
}
