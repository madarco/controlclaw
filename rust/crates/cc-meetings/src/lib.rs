//! The meetings settings shared by the agent box and the firewall (`@controlclaw/meetings`): the
//! policy's shape and checks, what widens it, the auto-join claim, and the media limits. Moved out
//! of the vm-agent so the firewall's meetings module (W4) reads the same code.

pub mod js;
pub mod policy;

/// The most a meeting's media may run, and its size (`MEDIA_MAX_SECONDS`, `MEDIA_MAX_BYTES`).
pub const MEDIA_MAX_SECONDS: i64 = 4 * 60 * 60;
pub const MEDIA_MAX_BYTES: i64 = 512 * 1024 * 1024;
/// How long a media lease lives between renewals (`MEDIA_TTL_SECONDS`).
pub const MEDIA_TTL_SECONDS: i64 = 30;
/// The longest meeting instructions (`MEETING_ORDERS_MAX`, archive.ts).
pub const MEETING_ORDERS_MAX: usize = 4000;
