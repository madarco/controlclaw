//! The vm-agent's client for the local OpenClaw gateway websocket.
//!
//! A port of `packages/vm-agent/src/gateway.ts` (`GatewayClient`): the same handshake (protocol 4,
//! the "trusted local backend client" form with the shared gateway token from
//! `KEYS_DIR/openclaw_gateway_token`), the same frames, request ids and reconnect backoff, and the
//! same error texts, which callers and their tests compare.
//!
//! The config write queue and the activation watcher (`patchConfig`, `withConfigWrite` in
//! gateway.ts, config-activation.ts) are in [`config_queue`], which W6 owns.

mod client;
pub mod config_queue;
mod messages;

#[cfg(any(test, feature = "fake"))]
pub mod fake;

pub use client::{
    CONNECT_TIMEOUT, ConfigWritePhase, DEFAULT_CALL_TIMEOUT, DEFAULT_MAX_BACKOFF, DEFAULT_MIN_BACKOFF, GATEWAY_SCOPES,
    GatewayClient, GatewayError, GatewayEvent, GatewayOptions, PROTOCOL,
};
pub use config_queue::{ConfigActivation, ConfigError, ConfigGateway, ConfigWriter, PatchOptions, QueueOptions};
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;

pub use messages::{is_persisted_pending_restart, is_persisted_superseded, is_restart_window, is_stale_base_hash};
