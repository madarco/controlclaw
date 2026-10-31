//! The egress proxy that replaces mitmproxy and `addon.py` (docs/plans/rust-rewrite.md §2).
//!
//! Folders by owner: W1 has `config`, `flow`, `net`, `tls`, `http`, `ws`, `splice`, `residential`,
//! `log`; W2 has `checks`. Today it is the skeleton: CONNECT, ClientHello, SNI passthrough for the
//! control plane and the backup store, and everything else closed with a `drop` record.

pub mod checks;
pub mod config;
pub mod flow;
pub mod http;
pub mod log;
pub mod net;
pub mod residential;
pub mod splice;
pub mod tls;
pub mod ws;
