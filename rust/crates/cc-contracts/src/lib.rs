//! The files and loopback calls between the firewall agent and the egress proxy.
//!
//! The mitm-agent writes JSON into the tmpfs `/run/mitm/config`; the proxy reloads each file when
//! it changes and calls the agent on loopback for live decisions. Both sides of that contract are
//! here, so the Rust proxy works with the TS agent and the Rust agent with `addon.py`
//! (docs/plans/rust-rewrite.md §5.1). Inventory: docs/plans/rust-rewrite/d-mitm-agent-internals.md
//! §2d and f-proxy-addon.md §1.5.
//!
//! Two rules hold for every type:
//! - unknown fields are kept (`extra`), so a file read and written again loses nothing;
//! - a field that was absent stays absent and a `null` stays `null` ([`Maybe`]), and numbers keep
//!   the form they were written in ([`serde_json::Number`]), so a round trip changes nothing a
//!   reader on the other side could see.
//!
//! Owner after the foundation: W3 (the writer). W1 and W2 read; additions go through W3.
//!
//! [`control_plane`] and [`commands`] are the other contract: between the firewall agent and its
//! control plane (docs/standalone/control-plane-contract.md).

pub mod commands;
pub mod content;
pub mod control_plane;
pub mod credentials;
pub mod exit;
pub mod files;
pub mod grants;
pub mod identities;
pub mod login_targets;
pub mod loopback;
pub mod maybe;
pub mod media;
pub mod pending;
pub mod rules;
pub mod traffic;

pub use files::{FileSpec, MissingPolicy, MtimeCache, OnError, ReadError, StatCache, read_fresh, write_atomic};
pub use maybe::Maybe;

/// Unknown fields of an object, kept in the order they came.
pub type Extra = serde_json::Map<String, serde_json::Value>;

/// Epoch seconds, or any JSON number whose exact form must survive a round trip: `1730000000`
/// stays an integer and `1730000000.25` a float, as the writer put them.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct Num(pub serde_json::Number);

impl Num {
    /// As f64, for comparisons such as "is this deadline in the future".
    pub fn as_f64(&self) -> Option<f64> {
        self.0.as_f64()
    }

    pub fn as_u64(&self) -> Option<u64> {
        self.0.as_u64()
    }

    /// A float, or `None` for NaN and infinities, which JSON cannot carry.
    pub fn from_f64(v: f64) -> Option<Self> {
        serde_json::Number::from_f64(v).map(Num)
    }
}

impl Default for Num {
    fn default() -> Self {
        Num(0.into())
    }
}

impl From<u64> for Num {
    fn from(v: u64) -> Self {
        Num(v.into())
    }
}

impl From<i64> for Num {
    fn from(v: i64) -> Self {
        Num(v.into())
    }
}
