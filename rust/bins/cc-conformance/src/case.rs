//! One conformance case: the agent to start, the state and helper answers it starts with, and the
//! requests (or heartbeat commands) with what must come back. Cases are YAML files under
//! `rust/conformance/cases/<workstream>/`.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Case {
    pub name: String,
    pub agent: Agent,
    /// `CC_SERVICE` for the vm-agent (`openclaw` or `gbrain`).
    #[serde(default = "default_service")]
    pub service: String,
    /// Files to create before the start, relative to the case's root (`keys/…`, `state/…`, `home/…`).
    #[serde(default)]
    pub files: BTreeMap<String, String>,
    /// Start as an unclaimed pool box. The Rust builds read `CC_POOL_MARKER`; the TS ones only
    /// `/etc/controlclaw/pool-unclaimed`, so their side runs in the Docker rig only.
    #[serde(default)]
    pub pool: bool,
    /// Helpers the TS build looks for only at `/usr/local/bin/<name>` (the Doctor's `cc-doctor-run`,
    /// `cc-fw-repair`, ...): written there with mode 0755 before the case and removed after it, so
    /// their side runs in the Docker rig only. A name is a file name, never a path.
    #[serde(default)]
    pub system_bins: BTreeMap<String, String>,
    /// Extra environment for the agent; `$ROOT` is the case's folder (where `files` go).
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Listeners of the agent's own beyond the main ones (a gate, a loopback service): a name for
    /// steps to use, and the environment variable that gives the agent a free port for it.
    #[serde(default)]
    pub ports: BTreeMap<String, String>,
    /// Answers for the shimmed helpers, first match wins, before the defaults.
    #[serde(default)]
    pub shims: Vec<ShimRule>,
    /// The fake console's answers by path before the start, each `[status, body]`, in order; the
    /// last repeats. Paths not named answer 200 `{}`.
    #[serde(default)]
    pub console: BTreeMap<String, Vec<(u16, Value)>>,
    /// Firewall cases: start a fake agent on `https://127.0.0.2` (`fake_agent.rs`), answering
    /// these paths (after `/__cc/agent`); paths not named answer 200 `{}`.
    #[serde(default)]
    pub fake_agent: Option<BTreeMap<String, Vec<(u16, Value)>>>,
    pub steps: Vec<Step>,
    /// Why a case is skipped on a target, for a gap that is known and owned (e.g. `rust: "W6"`).
    #[serde(default)]
    pub skip: BTreeMap<String, String>,
    /// The case file's folder, for `body_file`.
    #[serde(skip)]
    pub dir: std::path::PathBuf,
}

fn default_service() -> String {
    "openclaw".into()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Agent {
    VmAgent,
    MitmAgent,
}

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct ShimRule {
    /// The command line from the program's name on, matched as a prefix.
    pub argv: Vec<String>,
    #[serde(default)]
    pub stdout: String,
    #[serde(default)]
    pub stderr: String,
    #[serde(default)]
    pub code: i32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Step {
    #[serde(default)]
    pub name: Option<String>,
    /// Stop the agent and start it again on the same folder before the rest of the step.
    #[serde(default)]
    pub restart: bool,
    #[serde(default)]
    pub request: Option<Request>,
    /// Queue a heartbeat command for the firewall's next beat.
    #[serde(default)]
    pub command: Option<Command>,
    /// Wait for a beat and check it.
    #[serde(default)]
    pub beat: Option<BeatExpect>,
    /// Change the fake console's answers (as `console` on the case) at the start of the step.
    #[serde(default)]
    pub console: BTreeMap<String, Vec<(u16, Value)>>,
    /// Files under the case's root to write at the start of the step (after `remove`), as `files`
    /// on the case: what an operator or another program changes while the agent runs.
    #[serde(default)]
    pub write: BTreeMap<String, String>,
    /// Files under the case's root to remove at the start of the step.
    #[serde(default)]
    pub remove: Vec<String>,
    /// Files under the case's root to wait for, after the step's request or command.
    #[serde(default)]
    pub files: BTreeMap<String, FileExpect>,
    /// Requests the fake console must have received by now (waited for).
    #[serde(default)]
    pub received: Vec<ReceivedExpect>,
    /// Change the fake agent's answers at the start of the step.
    #[serde(default)]
    pub agent_answers: BTreeMap<String, Vec<(u16, Value)>>,
    /// Calls the fake agent must have received (waited for); `json_subset` is matched against
    /// `{method, path, query, claims, body}`.
    #[serde(default)]
    pub agent_received: Vec<ReceivedExpect>,
    #[serde(default)]
    pub expect: Option<Expect>,
    /// A standalone firewall's panel on this named port: set the admin up with the setup token
    /// from the agent's log, keep the session cookie in the jar and its CSRF token as `$csrf`
    /// (in a request's headers).
    #[serde(default)]
    pub panel_login: Option<String>,
    /// Values of the answer's JSON to use later as `$<name>` in a request's path or headers: name →
    /// dotted path (`id`, `keys.0.id`), or `set-cookie:<cookie>` for a cookie the answer set.
    #[serde(default)]
    pub keep: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum Listener {
    /// The vm-agent's port, or the firewall's 3100 in plain HTTP.
    #[default]
    Main,
    /// The firewall's 3100 over TLS.
    Tls,
    /// The firewall's ingress.
    Ingress,
    /// A loopback port the agent opens itself (the services the proxy calls: 3101, 8791-8794).
    /// The step waits for it to accept connections first.
    Port(u16),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub listener: Listener,
    /// One of the case's `ports` instead of `listener`.
    #[serde(default)]
    pub port: Option<String>,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    /// A body that does not end (server-sent events): read until this text arrived (10 s at most),
    /// then hang up; the expectations see what was read.
    #[serde(default)]
    pub read_until: Option<String>,
    /// A raw body, sent as it is (an upload).
    #[serde(default)]
    pub body: Option<String>,
    /// A JSON body, sent as compact JSON. A string `$ticket` in it is the step's `ticket`.
    #[serde(default)]
    pub json: Option<Value>,
    #[serde(default)]
    pub token: Option<Token>,
    /// Send the cookies the case's responses have set so far (a browser's jar), before any
    /// `cookie` header of the step's own.
    #[serde(default)]
    pub jar: bool,
    /// Keep cookies this answer clears (`Max-Age=0`) in the jar, to send a spent one again.
    #[serde(default)]
    pub keep_jar: bool,
    /// A sign-in ticket the firewall signs for this box (`/__cc/session`), sent as `{"token": …}`
    /// unless `json` places it.
    #[serde(default)]
    pub ticket: Option<Ticket>,
    /// A firewall recovery request: the body framed and signed as `npx @controlclaw/recover` does.
    #[serde(default)]
    pub recovery: Option<RecoverySign>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoverySign {
    /// The base64 Ed25519 signing secret (64 bytes).
    pub secret: String,
    pub head: Value,
    /// The archive after the head, as text.
    #[serde(default)]
    pub tail: String,
    /// Added to the timestamp, to test the replay window.
    #[serde(default)]
    pub timestamp_offset_ms: i64,
}

/// A firewall sign-in ticket: `{vmId, purpose, iss: "fw:fw_test", jti, deviceId: "dev_1", c}`,
/// 60 s, with `claims` merged over it. `c` is the hash of the newest `__Host-cc_bind_*` cookie in
/// the jar unless `claims` names one.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ticket {
    #[serde(default = "default_ticket_purpose")]
    pub purpose: String,
    #[serde(default)]
    pub claims: serde_json::Map<String, Value>,
    #[serde(default = "default_ticket_lifetime")]
    pub lifetime: i64,
    /// Send the ticket an earlier step sent (a replay).
    #[serde(default)]
    pub reuse: Option<String>,
}

fn default_ticket_purpose() -> String {
    "browser-login".into()
}

fn default_ticket_lifetime() -> i64 {
    60
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Signer {
    Console,
    Firewall,
    Box,
    /// HS256 with the box's `keys/session_secret` (hex), as the box signs its browser cookies.
    Session,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Token {
    pub signer: Signer,
    /// Merged over the defaults (`vmId` of the box; for the firewall also `purpose` and `iss`).
    #[serde(default)]
    pub claims: serde_json::Map<String, Value>,
    /// Seconds; negative makes a token that has already expired.
    #[serde(default = "default_lifetime")]
    pub lifetime: i64,
    /// Firewall tokens: bind to this request (`m p h b jti`).
    #[serde(default)]
    pub bind: bool,
    /// Issue the token this many seconds from now (negative: in the past); `exp` follows `lifetime`.
    #[serde(default)]
    pub iat_offset: i64,
    /// Firewall tokens with `bind`: sign the hash of this body instead of the one sent.
    #[serde(default)]
    pub body: Option<Value>,
    /// Use the token sent by an earlier step (a replay).
    #[serde(default)]
    pub reuse: Option<String>,
    /// Send it as this cookie instead of `Authorization: Bearer`.
    #[serde(default)]
    pub cookie: Option<String>,
    /// Or as this query parameter, added to the path.
    #[serde(default)]
    pub query: Option<String>,
}

fn default_lifetime() -> i64 {
    30
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Command {
    pub id: String,
    pub action: String,
    #[serde(default)]
    pub payload: Value,
    /// The result that must come back on a later beat (a subset match).
    #[serde(default)]
    pub result: Option<Value>,
    #[serde(default = "default_within")]
    pub within_ms: u64,
}

/// A file the agent wrote: its exact text, or its JSON (with matchers), or that it is not there.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileExpect {
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub json: Option<Value>,
    #[serde(default)]
    pub absent: bool,
    #[serde(default = "default_within")]
    pub within_ms: u64,
    /// Once it matches, it must keep matching this long (a write that must not happen).
    #[serde(default)]
    pub for_ms: u64,
}

/// A request the fake console received: its path, and a subset of its JSON body.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceivedExpect {
    pub path: String,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub json_subset: Option<Value>,
    #[serde(default = "default_within")]
    pub within_ms: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BeatExpect {
    #[serde(default = "default_within")]
    pub within_ms: u64,
    pub json_subset: Value,
}

fn default_within() -> u64 {
    10_000
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Expect {
    pub status: Option<u16>,
    /// Header subsets, lower-case names; the value `$absent` means it must not be there.
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    /// The whole JSON body, with matchers (`$any`, `$number`, `$string`, `$uuid`).
    pub json: Option<Value>,
    /// Only these keys, recursively in objects.
    pub json_subset: Option<Value>,
    /// Keys the JSON body must not have.
    #[serde(default)]
    pub absent: Vec<String>,
    /// The exact body text.
    pub body: Option<String>,
    /// The exact body text, from this file next to the case. `CC_WRITE_GOLDEN=1` writes what the TS
    /// build answered there instead of comparing.
    pub body_file: Option<String>,
    /// Texts the body must contain.
    #[serde(default)]
    pub body_contains: Vec<String>,
    /// Patterns each `Set-Cookie` line of the answer must be matched by one of, in any order; `*`
    /// is any run of characters. `[]` means none was set.
    pub set_cookies: Option<Vec<String>>,
    /// Helper calls that must have run by now: a command line (prefix match), or
    /// `{argv: [...], stdin: "..."}` to check what it was given too.
    #[serde(default)]
    pub calls_include: Vec<CallExpect>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum CallExpect {
    Argv(Vec<String>),
    WithStdin { argv: Vec<String>, stdin: String },
}

impl CallExpect {
    pub fn parts(&self) -> (&[String], Option<&str>) {
        match self {
            CallExpect::Argv(a) => (a, None),
            CallExpect::WithStdin { argv, stdin } => (argv, Some(stdin)),
        }
    }
}
