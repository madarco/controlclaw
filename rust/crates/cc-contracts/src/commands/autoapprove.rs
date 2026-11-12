//! `autoapprove.*` payloads: the organization's Auto approve rules, kept on the firewall like the
//! integration rules (`core/auto_approve.rs` in the mitm-agent). A change uses the same shape as
//! `apps.propose`; the rule in a `put` is a [`crate::auto_approve::AutoRule`], checked by the firewall.

pub use super::apps::{Change, Propose};
