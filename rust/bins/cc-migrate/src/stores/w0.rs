//! W0's stores: the key files and the firewall-token floor, which the foundation's crates read.
//! A floor that will not parse would be read as none, which loosens replay protection after a
//! restart, so it is checked like any store.

use crate::store::{Format, Role, Store};

pub const STORES: &[Store] = &[
    Store {
        role: Role::Agent,
        name: "firewall-tokens-bound.newest",
        path: "/opt/controlclaw/state/firewall-tokens-bound.newest",
        env: None,
        format: Format::Integer,
    },
    Store {
        role: Role::Agent,
        name: "session_secret",
        path: "/opt/controlclaw/keys/session_secret",
        env: None,
        format: Format::Hex(32),
    },
    Store {
        role: Role::Firewall,
        name: "box_key",
        path: "/opt/controlclaw/keys/box_key",
        env: Some("BOX_KEY_PATH"),
        format: Format::Base64(32),
    },
];
