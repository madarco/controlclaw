//! W4's stores (docs/plans/rust-workstreams/W4.md): one row per store it ports, with the path the
//! Node build uses. W4 owns this file. The per-day records (`content-stopped/stopped.<day>.enc`,
//! `ai-review-traces/<agent>.<day>.enc`) are left out: they are rewritten whole each day, and one
//! that does not open is started over, never a reason to hold a box back. So is `email-counters.json`, which
//! starts at zero when it does not read.

use crate::store::{Format, Role, Store};

const fn enc(name: &'static str, path: &'static str, env: Option<&'static str>, purpose: &'static str) -> Store {
    Store {
        role: Role::Firewall,
        name,
        path,
        env,
        format: Format::EncFile { purpose },
    }
}

pub const STORES: &[Store] = &[
    enc(
        "channels",
        "/opt/controlclaw/state/channels.enc",
        Some("CHANNEL_STORE_PATH"),
        "channels",
    ),
    enc("llm", "/opt/controlclaw/state/llm.enc", Some("LLM_STORE_PATH"), "llm"),
    enc("secrets", "/opt/controlclaw/state/secrets.enc", None, "secrets"),
    enc("agentmail", "/opt/controlclaw/state/agentmail.enc", None, "agentmail"),
    enc(
        "email-rules",
        "/opt/controlclaw/state/email-rules.enc",
        None,
        "email-rules",
    ),
    enc(
        "google",
        "/opt/controlclaw/state/google.enc",
        Some("GOOGLE_STORE_PATH"),
        "google",
    ),
    enc(
        "drive",
        "/opt/controlclaw/state/drive.enc",
        Some("DRIVE_STORE_PATH"),
        "drive",
    ),
    enc(
        "twilio-voice",
        "/opt/controlclaw/state/twilio-voice.enc",
        None,
        "twilio-voice",
    ),
    enc(
        "content-rules",
        "/opt/controlclaw/state/content-rules.enc",
        None,
        "content-rules",
    ),
    enc("meetings", "/opt/controlclaw/state/meetings.enc", None, "meetings"),
];
