//! The order the agent box checks routes in, from the dispatch chain in
//! `packages/vm-agent/src/index.ts`. Each workstream adds its routes to the stage its TS routes sit
//! in; within a stage the first match wins, so keep a prefix after the exact paths it would shadow.

/// `/meetings/*` and `/__cc/meetings*` (W8), checked before everything else.
pub const MEETINGS: &str = "meetings";
/// The calls pages under `/__cc/phone*` (W8).
pub const PHONE_PAGES: &str = "phone-pages";
/// Every other `/__cc/*`: sign-in, sessions and pages (W7).
pub const CC: &str = "cc";
/// The prefixed groups with their own auth (`/doctor/`, `/channels/`, `/llm/`, ... `/files/`):
/// W6, W7 and W8 each add theirs; prefixes do not overlap.
pub const PREFIXED: &str = "prefixed";
/// Behind the console's token (`requireAuth`): everything that reaches it without one is a 401,
/// whether or not a route exists.
pub const CONSOLE: &str = "console";

pub const AGENT_BOX: &[&str] = &[MEETINGS, PHONE_PAGES, CC, PREFIXED, CONSOLE];

/// Upgrade requests (`server.on("upgrade")`, the phone relay, W8). They never reach the stages above.
pub const UPGRADE: &str = "upgrade";

/// A brain box (`gbrain.ts`): its own short chain.
pub const BRAIN_OPEN: &str = "brain-open";
pub const BRAIN_BOX: &[&str] = &[BRAIN_OPEN, CONSOLE];
