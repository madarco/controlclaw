//! The order the firewall's listeners check routes in (`packages/mitm-agent/src/index.ts`).

/// Port 3100, plain: `RecoveryRoutes.serveStaged` (W3), then the TLS-only refusal (426) for the
/// recovery paths; anything else is a JSON 404.
pub const PLAIN_STAGED: &str = "staged";
pub const PLAIN_TLS_ONLY: &str = "tls-only";
pub const PLAIN: &[&str] = &[PLAIN_STAGED, PLAIN_TLS_ONLY];

/// Port 3100 over TLS: the recovery routes (W3); anything else is a JSON 404.
pub const RECOVERY: &str = "recovery";
pub const TLS: &[&str] = &[RECOVERY];

/// The ingress (index.ts:2496-2587), in its order: the pages' shared assets, then the pages each
/// workstream owns (fw logs, content rules, AI review, Doctor start, chat and terminal, meetings
/// media, website logins, team chat), then Open and enroll, then webhook deliveries. Anything else
/// is a 404 with no body.
pub const INGRESS_SHELL: &str = "shell";
pub const INGRESS_PAGES: &str = "pages";
pub const INGRESS_ACCESS: &str = "access";
pub const INGRESS_HOOKS: &str = "hooks";
pub const INGRESS: &[&str] = &[INGRESS_SHELL, INGRESS_PAGES, INGRESS_ACCESS, INGRESS_HOOKS];

/// Upgrades on the ingress (`server.on("upgrade")`): team chat's verify, `/phone-stream/`, the
/// Doctor terminal. Anything else gets a raw 403.
pub const INGRESS_UPGRADE: &str = "upgrade";
