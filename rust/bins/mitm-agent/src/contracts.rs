//! What one workstream provides and others use on the firewall, decided before the fan-out so no
//! one waits on another's code. W0 owns this file. The provider fills its slot in its `register`;
//! users read the slot when they handle something (not in `register`, which runs in a fixed
//! order).
//!
//! While a slot is still empty, users fail closed (host rule): a change that needs a consent code
//! is refused without `ConsentCodes` (`Slot::require()`), never applied without one; no agent is
//! called without `IdentityMap`; with no `CredentialContributor` nothing is swapped. Refuse anything
//! that would loosen the firewall; `Slot::get()` only where an empty slot can only do less.

use std::sync::{Arc, RwLock};

use cc_http::{BoxFuture, RequiredSlot, Slot};
use serde_json::{Map, Value};

/// W0's first shape of the consent codes, kept so the modules that started from it build. Every
/// caller of it shares one namespace (it cannot say which module it is), so it cannot keep one
/// module's code from confirming another's that uses the same scope; it offers no buttons, no dev
/// route, no recovery-key fallback and no two-part message. Use [`CodeService::module`] instead:
/// content and email rules (codes typed outside the console's dialog, `no_buttons`), firewall and
/// agent updates (`recovery`), and every module whose scope holds a value from a command (a vm id)
/// must.
/// `ConsentCodes` in `consent-codes.ts`. Provided by W3; used by every `*.propose` / `*.confirm`
/// command in W3, W4 and W5. One instance holds every pending change, so the try count and the
/// expiry are checked and updated under one lock (`verify` is check-and-update, never two calls).
pub trait ConsentCodes: Send + Sync {
    /// `send`: mint a code for `scope`'s change and have an agent deliver it to the first route
    /// that reaches somebody. Replaces any change pending for the same scope.
    fn send(&self, req: CodeRequest) -> BoxFuture<SendResult>;
    /// `verify`: whitespace stripped, lower-cased, compared as SHA-256 in constant time. A wrong
    /// code costs a try; the last try drops the change.
    fn verify(&self, scope: &str, change_id: &str, code: &str) -> Verify;
    /// `cancel`: the pending change of `scope` (only `change_id`'s, when given).
    fn cancel(&self, scope: &str, change_id: Option<&str>) -> bool;
    /// `drop`.
    fn forget(&self, scope: &str);
}

/// What `send` takes. The routes (who can get a code, over which channel) are W3's to type; they
/// travel as the TS shapes them until then.
pub struct CodeRequest {
    pub scope: String,
    pub change_id: String,
    /// The change itself, handed back by `verify` when the code is right.
    pub proposal: Value,
    pub agent_name: String,
    pub summary: String,
    pub routes: Vec<Value>,
}

/// `SendResult`.
#[derive(Debug, Clone, PartialEq)]
pub struct SendResult {
    pub sent_via: Option<String>,
    pub error: Option<String>,
    /// A real person was tried and could not be reached (what the recovery key is for).
    pub delivery_failed: bool,
    pub expires_at_ms: i64,
}

/// `VerifyResult`.
#[derive(Debug, Clone, PartialEq)]
pub enum Verify {
    Ok(Value),
    Wrong { tries_left: u32 },
    Expired,
    Unknown,
}

/// `ConsentCodes` in `consent-codes.ts`, in full: typed routes, the two-part message, buttons, the
/// dev route and the recovery-key fallback (W3 C2). Provided by W3. Used by every `*.propose` /
/// `*.confirm` command: take your module's handle once, with a name fixed in your code, and keep it.
///
/// The TS had one `ConsentCodes<T>` per module. Here one instance holds every pending change, keyed
/// by `(module, scope)`: a handle sends, verifies, cancels and forgets only its own module's
/// changes, so a code sent for one module can never confirm another's, whatever the scopes are.
pub trait CodeService: Send + Sync {
    /// `name`: your module (`channels`, `llm`, `connectors`, …). Never a value from a command.
    fn module(&self, name: &'static str) -> Arc<dyn ModuleCodes>;
}

/// One module's consent codes. One pending change per scope, 5 tries, 10 minutes; `verify` is
/// check-and-update under one lock.
pub trait ModuleCodes: Send + Sync {
    /// `send`: mint a code for `scope`'s change and have an agent deliver it to the first route
    /// that reaches somebody. Replaces any change pending for the same scope.
    fn send(&self, req: CodeAsk) -> BoxFuture<CodeSent>;
    /// `verify`: whitespace stripped, lower-cased, compared as SHA-256 in constant time. A wrong
    /// code costs a try; the last try drops the change.
    fn verify(&self, scope: &str, change_id: &str, code: &str) -> CodeCheck;
    /// `cancel`: drop the pending change of `scope` when it is `change_id`'s (`None` matches none,
    /// as the TS's `null`).
    fn cancel(&self, scope: &str, change_id: Option<&str>) -> bool;
    /// `drop`.
    fn forget(&self, scope: &str);
}

/// The whole message for a code that confirms something other than a change (`message` in `send`).
pub type CodeText = Arc<dyn Fn(&str) -> Result<String, String> + Send + Sync>;

/// What `send` takes. Build it with `..Default::default()`: options are added over time.
#[derive(Clone, Default)]
pub struct CodeAsk {
    pub scope: String,
    pub change_id: String,
    /// The change itself, handed back by `verify` when the code is right.
    pub proposal: Value,
    /// What the message names as the thing being changed.
    pub agent_name: String,
    pub summary: String,
    pub routes: Vec<CodeRoute>,
    /// The message in two parts (`CodeParts`), for a caller that keeps its facts apart from text
    /// that came from elsewhere.
    pub parts: Option<crate::core::code_message::CodeParts>,
    /// The whole message (a browser's sign-in code). No buttons with it.
    pub message: Option<CodeText>,
    /// Opt in to sealing the code to the recovery key when no channel takes it (T-99).
    pub recovery: bool,
    /// Doctor only: recover even with nobody to send to (still the recovery key, never first use).
    pub recover_without_recipients: bool,
    /// `buttons: false`: a code typed somewhere other than the console's code dialog.
    pub no_buttons: bool,
}

/// Where a code can go: an agent box and the people approved to talk to it (`CodeRoute`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeRoute {
    pub vm_id: String,
    pub hostname: String,
    pub senders: Vec<CodeSender>,
    /// A Telegram connection the firewall can send the code on itself, with buttons.
    pub telegram: Option<TelegramRoute>,
}

/// A person a code can go to, or the dev route. `Dev` is only ever made in code, on a firewall
/// built from the test repo (`provenance`), never parsed: a sender that calls itself "dev" is a
/// `Person` and is skipped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodeSender {
    Person {
        kind: String,
        id: String,
        label: Option<String>,
    },
    Dev,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelegramRoute {
    pub connection_id: String,
    pub bot_token: String,
}

/// A code that could not be delivered, sealed to the recovery key instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryChallenge {
    /// base64 `crypto_box_seal` to the recovery wrap key.
    pub challenge: String,
    /// Why no channel could take the code.
    pub delivery_error: String,
}

/// `CodeSent`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodeSent {
    Sent {
        sent_via: String,
        /// ISO time.
        expires_at: String,
        attempts_left: u32,
        recovery: Option<RecoveryChallenge>,
    },
    Failed {
        message: String,
    },
}

impl CodeSent {
    /// `awaitingCodeData`: the `awaiting_code` fields every module reports.
    pub fn awaiting_code_data(&self) -> Option<serde_json::Map<String, Value>> {
        let CodeSent::Sent {
            sent_via,
            expires_at,
            attempts_left,
            recovery,
        } = self
        else {
            return None;
        };
        let mut m = serde_json::Map::new();
        m.insert("sentVia".into(), Value::String(sent_via.clone()));
        m.insert("expiresAt".into(), Value::String(expires_at.clone()));
        m.insert("attemptsLeft".into(), Value::from(*attempts_left));
        if let Some(r) = recovery {
            m.insert(
                "recovery".into(),
                serde_json::json!({"challenge": r.challenge, "deliveryError": r.delivery_error}),
            );
        }
        Some(m)
    }
}

/// `VerifyResult`.
#[derive(Debug, Clone, PartialEq)]
pub enum CodeCheck {
    Ok { proposal: Value, sent_via: String },
    Wrong { tries_left: u32 },
    Expired,
}

/// Approve with a button (`code-buttons.ts`). Provided by W4; the consent codes offer a code with
/// buttons when there is one.
pub trait CodeButtons: Send + Sync {
    /// `codeButtons()` is set: a tap can reach the firewall.
    fn available(&self) -> bool;
    /// Send the message with number buttons; the offer's nonce, or `None` when Telegram did not
    /// take it from the firewall (the agent then sends the plain code).
    fn offer(&self, offer: ButtonOffer) -> BoxFuture<Option<String>>;
    /// The change ended (`confirmed`, `closed`, `expired`): turn its buttons off.
    fn settle(&self, nonce: Option<&str>, how: &str);
}

/// `OfferInput`.
#[derive(Clone)]
pub struct ButtonOffer {
    pub change_id: String,
    pub route: TelegramRoute,
    pub sender_id: String,
    pub text: String,
    /// The same message with another last line of part one.
    pub render: CodeText,
    pub code: String,
    pub expires_at_ms: u64,
    pub owner: Arc<dyn TapOwner>,
}

/// What a button tap did (`TapOwner.tap`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tap {
    Ok,
    Wrong,
    Spent,
    Gone,
}

pub trait TapOwner: Send + Sync {
    fn tap(&self, correct: bool) -> Tap;
    fn cancel(&self);
}

/// Where codes can go (`channels.codeRoutes()` and friends). Provided by W4's channels; read by
/// every module that sends a code.
pub trait CodeRouteSource: Send + Sync {
    /// `codeRoutes()`, the dev route last on a dev-built firewall.
    fn routes(&self) -> Vec<CodeRoute>;
    /// `channelsReady`: the channel store could be read, so an empty list means nobody approved.
    fn ready(&self) -> bool;
    /// `agentAllowedCount()`: senders the agents allowed that nobody confirmed; `None` until read.
    fn agent_allowed_count(&self) -> Option<u32>;
}

/// The agents this firewall serves (`identities.ts`, synced from the console, pinned when the map
/// lacks one). Provided by W3; used by everything that calls an agent (W3, W4, W5). A call goes only
/// to an agent this map knows, never to an address a command names.
pub trait IdentityMap: Send + Sync {
    /// The OpenClaw agents (the TS `identities`): never the organization's brain.
    fn agents(&self) -> Vec<AgentIdentity>;
    fn agent(&self, vm_id: &str) -> Option<AgentIdentity>;
    /// Where the firewall calls a box (`agentHostFor`): the map's hostname of an agent or of the
    /// brain (`browserIdentities`), lower-cased, else the one pinned at first sight. No default:
    /// `agent()` alone leaves the brain out, which is how the brain's model push broke.
    fn host_for(&self, vm_id: &str) -> Option<String>;
    /// Where a call to the box's vm-agent goes. On a SaaS box, its hostname over HTTPS.
    fn route_for(&self, vm_id: &str) -> Option<AgentRoute> {
        self.host_for(vm_id).map(AgentRoute::https)
    }
}

/// Where an agent's Caddy serves its vm-agent (SaaS boxes).
pub const AGENT_PATH_PREFIX: &str = "/__cc/agent";

/// Where a call to an agent's vm-agent goes: `base` and the path, with a token signed for `host`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentRoute {
    pub host: String,
    pub base: String,
}

impl AgentRoute {
    /// The agent's hostname, whose Caddy serves the vm-agent under `/__cc/agent` (a SaaS box).
    pub fn https(host: String) -> Self {
        Self {
            base: format!("https://{host}{AGENT_PATH_PREFIX}"),
            host,
        }
    }

    /// The vm-agent itself at the address pairing gave (a standalone firewall's agents): plain
    /// HTTP on the private network or the tunnel, the token as on HTTPS.
    pub fn direct(addr: std::net::SocketAddrV4) -> Self {
        Self {
            host: addr.ip().to_string(),
            base: format!("http://{addr}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentIdentity {
    pub vm_id: String,
    pub private_ip: String,
    /// The name the firewall signs its tokens for (`h`) and calls it by.
    pub hostname: Option<String>,
    /// What people call the agent (`name` in the map): code messages name agents by it.
    pub name: Option<String>,
}

/// A module whose secrets the proxy swaps in: its entries go into `credentials.json` when W3's
/// sync writes the proxy config (`index.ts` 601-631). Provided by W3, W4 and W5 (one each per
/// module); the sync, W3's, writes them in [`CredentialOrder`] order so the file matches the TS.
pub trait CredentialContributor: Send + Sync {
    fn order(&self) -> CredentialOrder;
    /// The entries, as the proxy reads them (`cc_contracts::credentials`).
    fn credentials(&self) -> Vec<Value>;
}

/// The order the TS appends them in, after the console's own credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CredentialOrder {
    Channels,
    Llm,
    Meetings,
    Drive,
    Phone,
    Secrets,
    Logins,
    AgentMail,
    Google,
    Search,
}

/// Every contributor, in the order they were added; the sync sorts by [`CredentialContributor::order`].
#[derive(Default)]
pub struct Contributors(RwLock<Vec<Arc<dyn CredentialContributor>>>);

impl Contributors {
    /// A second contributor for one place stops the start (checked before the list is touched).
    pub fn add(&self, c: Arc<dyn CredentialContributor>) {
        let mut v = self.0.write().unwrap_or_else(|e| e.into_inner());
        let twice = v.iter().any(|x| x.order() == c.order());
        if !twice {
            v.push(c);
            return;
        }
        drop(v);
        panic!("credential contributor {:?} added twice", c.order());
    }

    pub fn sorted(&self) -> Vec<Arc<dyn CredentialContributor>> {
        let mut v = self.0.read().unwrap_or_else(|e| e.into_inner()).clone();
        v.sort_by_key(|c| c.order());
        v
    }
}

/// `channels.codeRoutes()`: where a confirmation code can go now (every agent with an approved
/// sender). Provided by W4; read by every `*.propose`. An empty slot is no route at all, as the
/// TS's `channels?.codeRoutes() ?? []`.
pub trait CodeRoutes: Send + Sync {
    fn routes(&self) -> Vec<Value>;
    /// `channelsReady`: the channel store opened, so an empty list means nobody, not "unknown".
    /// False unless the provider says so: a change that needs a code is then refused.
    fn ready(&self) -> bool {
        false
    }
}

/// The firewall's client to its agents (`agent-client.ts` `makeAgentClient`): HTTPS to the
/// agent's recorded hostname, one bound token per request, the purpose from the path. Provided by
/// W3; used by W3, W4 and W5. A call names the agent by id; the address is the client's to find.
pub trait AgentClient: Send + Sync {
    fn post(&self, vm_id: &str, path: &str, body: Value) -> BoxFuture<Result<Map<String, Value>, AgentError>>;
    fn get(&self, vm_id: &str, path: &str) -> BoxFuture<Result<Map<String, Value>, AgentError>>;
}

/// Why an agent call failed, with the TS's message (`agent 400: …`, a timeout, unreachable).
#[derive(Debug, Clone, PartialEq)]
pub struct AgentError {
    pub message: String,
    pub timed_out: bool,
}

/// The emergency stop (`kill.ts` `lockedVmIds`). Provided by W3.
pub trait EmergencyStop: Send + Sync {
    fn locked(&self, vm_id: &str) -> bool;
}

/// Approvals a person gave (`grants.ts`, written by the permission bridge). Provided by W3; read
/// by the connector gate and the MCP checks, which use each approval once.
pub trait PermissionGrants: Send + Sync {
    fn active(&self, permission_id: &str) -> bool;
    fn consume(&self, permission_id: &str);
}

/// OpenClaw's own approvals, which an agent's vm-agent sends to the 3940 gate (`/permission`).
/// Provided by W3 (`core::auto_approve`); used by the tools gate, which has already told the agent
/// by its source address. Answers are `(HTTP status, JSON body)`, as the control plane's.
pub trait AgentPermissions: Send + Sync {
    /// False until a control plane sent the Auto approve rules (an older one does not): the gate
    /// answers 404 and the agent asks its control plane itself.
    fn active(&self) -> bool;
    /// A raise: the rules answer Allow or Block here; Ask goes to the control plane.
    fn raise(&self, vm_id: &str, body: Value) -> BoxFuture<(u16, Value)>;
    /// `GET ?permission_id=`, forwarded for the agent.
    fn status(&self, vm_id: &str, permission_id: &str) -> BoxFuture<(u16, Value)>;
    /// A request the agent settled itself, forwarded with the agent's own box token (`token`), so the
    /// control plane checks the agent, not this firewall.
    fn settle(&self, vm_id: &str, body: Value, token: &str) -> BoxFuture<(u16, Value)>;
}

/// What the integration checks need from the content rules (`GateAppContent` in
/// `connector-gate.ts`, channel `apps`). Provided by W4; used by the connector gate, the MCP server
/// gate and the MCP checks (W5).
pub trait AppContent: Send + Sync {
    /// False while the content rules should run and are not up yet: calls are refused.
    fn loaded(&self) -> bool;
    fn applies(&self, direction: &str) -> bool;
    /// `bodyText` in `content-engine.ts`.
    fn body_text(&self, body: &[u8], content_type: &str) -> Option<String>;
    fn check(
        &self,
        direction: &str,
        text: String,
        vm_id: Option<String>,
    ) -> BoxFuture<Result<Option<CheckedRule>, ContentError>>;
    /// One line of the content rules' record; its id.
    fn record(
        &self,
        rule: &str,
        direction: &str,
        action: &str,
        vm_id: Option<&str>,
        extra: Map<String, Value>,
    ) -> Option<String>;
    /// `holdApp`: the hold's id, or `None` when nobody could be asked.
    fn hold(&self, hold: AppHold) -> BoxFuture<Option<String>>;
    fn stopped_here(&self, rule: &CheckedRule, direction: &str, vm_id: Option<&str>, text: &str, id: Option<&str>);
}

/// `CheckedRule`, with what the integrations put in their messages.
#[derive(Debug, Clone, PartialEq)]
pub struct CheckedRule {
    pub id: String,
    pub name: Option<String>,
    /// `block`, `hold` or `log`.
    pub action: String,
    pub reason: String,
    /// `by`: `found` or `failed` when the AI judged it.
    pub by: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ContentError {
    /// `ContentTooLong`.
    TooLong,
    Failed(String),
}

/// What `holdApp` takes. `send` runs the call when a person presses Send.
pub struct AppHold {
    pub vm_id: String,
    pub what: String,
    pub where_: String,
    pub text: String,
    pub rule: CheckedRule,
    pub send: Box<dyn FnOnce() -> BoxFuture<Result<(), String>> + Send>,
}

/// The firewall's AI (`AiJudge` in `ai/judge.ts`) where the integrations ask it. Provided by W4.
pub trait IntegrationJudge: Send + Sync {
    /// `integrationFits`: `fits`, `no`, or `unavailable` when it could not answer.
    fn integration_fits(
        &self,
        vm_id: &str,
        sentence: &str,
        integration: &str,
        tool: &str,
        input: &Value,
    ) -> BoxFuture<String>;
    /// `labelTool`: `read`, `write`, `destructive`, or None.
    fn label_tool(
        &self,
        server: &str,
        name: &str,
        description: Option<&str>,
        argument_names: &[String],
    ) -> BoxFuture<Option<String>>;
    /// `contentRules.aiPin()` as JSON: a new pin labels the tools again.
    fn label_epoch(&self) -> String;
}

/// An apply's consent to give one agent one of the organization's MCP servers (`apply.ts`
/// `hasMcpGrant` / `useMcpGrant`): a template apply whose code named the server. Provided by W3; used
/// by the server gate's `/servers/give`.
pub trait McpGrants: Send + Sync {
    fn has(&self, vm_id: &str, name: &str) -> bool;
    fn use_grant(&self, vm_id: &str, name: &str);
}

/// Who opened one of this firewall's own pages (`access.ts`, W3): an Open intent from the console
/// for `next`, posted from this firewall's origin, in a browser already enrolled for that person.
/// Provided by W3; used by every page W3, W4 and W5 serve on the ingress.
pub trait PageAccess: Send + Sync {
    /// `https://<this firewall's name>`, or None while it has none.
    fn origin(&self) -> Option<String>;
    /// `authorizeLogins`, `authorizeTeamChat`, `authorizeDoctor`, `authorizeFirewallPage`: the
    /// intent checked for `next` (with the rules that page has, such as `canWrite`), the jti used
    /// up, the browser's enrollment read from `headers`. None when any of it fails.
    fn authorize(&self, headers: &http::HeaderMap, intent: String, next: &str) -> BoxFuture<Option<PagePerson>>;
    /// `*DeviceActive`: the grant's browser is still enrolled for that person (and, for the
    /// firewall's own pages, the organization is not stopped). With `vm_id` (Doctor's pages,
    /// `doctorDeviceActive(userId, deviceId, vmId)`), the agent must also still be in the identity
    /// map and not under the emergency stop; false otherwise.
    fn device_active(
        &self,
        headers: &http::HeaderMap,
        next: &str,
        user_id: &str,
        device_id: &str,
        vm_id: Option<&str>,
    ) -> bool;
}

#[derive(Debug, Clone, PartialEq)]
pub struct PagePerson {
    pub user_id: String,
    pub device_id: String,
    pub email: Option<String>,
    pub can_write: bool,
    /// The rest of the intent a page reads (`sessionId`, `doctorChoices`, `doctorAgent`, `name`).
    pub extra: Map<String, Value>,
}

/// The frame every page of this firewall is drawn in (`fw-shell.ts`, W3).
pub trait FwShell: Send + Sync {
    /// `fwNotice({title, heading?, text, id?, script?})`.
    fn notice(&self, title: &str, heading: Option<&str>, text: &str, id: Option<&str>, script: Option<&str>) -> String;
    /// `fwShellPage({title, active, body, consoleUrl, tail})`.
    fn shell_page(&self, title: &str, active: &str, body: &str, console_url: Option<&str>, tail: &str) -> String;
    /// `fwMinimalPage({title, body, tail})`.
    fn minimal_page(&self, title: &str, body: &str, tail: &str) -> String;
    /// `fwContent(html)`.
    fn content(&self, html: &str) -> String;
}

/// Write the proxy's credentials again from the contributors now (`onCredentialsChanged`): a
/// login taken away must leave the proxy at once. Provided by W3's sync.
pub trait CredentialsSync: Send + Sync {
    fn changed(&self) -> BoxFuture<()>;
}

/// One channel write to an agent box (`ChannelWriter` in `channel-apply.ts`): `POST
/// /channels/apply` with an id, and how it ended. Provided by W4; used by Team chat (W5).
pub trait ChannelWriter: Send + Sync {
    /// `write(target, type, body)`: an error for a refusal that arrived in time, or a box that
    /// reports the write failed (its message).
    fn write(&self, vm_id: &str, hostname: &str, kind: &str, body: Value) -> BoxFuture<Result<ApplyOutcome, String>>;
}

/// `ApplyOutcome`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyOutcome {
    Applied,
    /// The answer did not arrive in time and the box did not say how it ended.
    Unconfirmed,
}

/// What the team chat gate needs from the content rules (`GateContent` in `teamchat-gate.ts`,
/// channel `teamchat`). Provided by W4; used by the 3930 gate (W5).
pub trait ChatContent: Send + Sync {
    /// False while the content rules should run and are not up yet: messages are refused.
    fn loaded(&self) -> bool;
    fn applies(&self, direction: &str) -> bool;
    /// `once`: the message id, so one message is judged once.
    fn check(
        &self,
        direction: &str,
        text: String,
        vm_id: Option<String>,
        once: Option<String>,
    ) -> BoxFuture<Result<Option<CheckedRule>, ContentError>>;
    fn record(
        &self,
        rule: &str,
        direction: &str,
        action: &str,
        vm_id: Option<&str>,
        extra: Map<String, Value>,
        once: Option<&str>,
    ) -> Option<String>;
    /// `holdTeamChat`: the hold's id, or `None` when nobody could be asked.
    fn hold(&self, hold: ChatHold) -> BoxFuture<Option<String>>;
    fn stopped_here(&self, rule: &CheckedRule, direction: &str, vm_id: Option<&str>, text: &str, id: Option<&str>);
}

/// What `holdTeamChat` takes. `send` posts the message when a person presses Send.
pub struct ChatHold {
    pub vm_id: String,
    pub where_: String,
    pub text: String,
    /// `ruleBrief(rule)` is the provider's to make.
    pub rule: CheckedRule,
    pub send: Box<dyn FnOnce() -> BoxFuture<Result<(), String>> + Send>,
}

/// The model credential a Doctor session is paid with (`llm.doctorCredential(id)`), as W4's store
/// keeps it (`StoredCredential`, as JSON, after a refresh that was due). Provided by W4; used by
/// Doctor (W5). None: no such credential.
pub trait DoctorCredential: Send + Sync {
    fn credential(&self, id: &str) -> BoxFuture<Option<Value>>;
}

/// Every secret value this firewall holds (`firewallSecrets` in `index.ts`): the stores' secrets,
/// the key files, the proxy CA and credentials, the Team chat tokens. What anything a person reads
/// is masked with. Provided by W3; used by Doctor (W5).
pub trait FirewallSecrets: Send + Sync {
    fn values(&self) -> Vec<String>;
}

/// Doctor's standing SSH key, `{pub, sig, fingerprint}`: what the CA registration and the ready
/// report carry (`doctor_ssh_pub`, `doctor_ssh_sig`). Provided by W5; used by W3.
pub trait DoctorPublicKey: Send + Sync {
    fn public_key(&self) -> Value;
}

/// The firewall's Logs page reader (`FwLogsReader.read` in `fw-logs.ts`): `{range, service}` in,
/// the `FwLogsResponse` as JSON out, already masked. Provided by W3; used by Firewall Doctor (W5).
pub trait FwLogs: Send + Sync {
    fn read(&self, range: &str, service: &str) -> BoxFuture<Result<Value, String>>;
}

/// This firewall's own update (`FirewallUpdate` in `firewall-update.ts`), as Firewall Doctor's
/// `update-retry` starts it: `supported()`, `status().phase` and `applyForDoctor()`. Provided by
/// W3; used by Firewall Doctor (W5).
pub trait SelfUpdate: Send + Sync {
    fn supported(&self) -> bool;
    fn phase(&self) -> String;
    fn apply_for_doctor(&self);
}

/// The contracts' slots, on [`crate::app::App`].
pub struct Contracts {
    /// Required: a change that needs a code is refused while there is no provider.
    pub consent: RequiredSlot<dyn ConsentCodes>,
    pub code_service: Slot<dyn CodeService>,
    pub buttons: Slot<dyn CodeButtons>,
    pub code_route_source: Slot<dyn CodeRouteSource>,
    /// Required: no agent is called while there is no provider.
    pub identities: RequiredSlot<dyn IdentityMap>,
    pub credentials: Contributors,
    pub code_routes: Slot<dyn CodeRoutes>,
    pub agents: Slot<dyn AgentClient>,
    pub emergency_stop: Slot<dyn EmergencyStop>,
    pub grants: Slot<dyn PermissionGrants>,
    pub agent_permissions: Slot<dyn AgentPermissions>,
    pub app_content: Slot<dyn AppContent>,
    pub judge: Slot<dyn IntegrationJudge>,
    pub mcp_grants: Slot<dyn McpGrants>,
    pub page_access: Slot<dyn PageAccess>,
    pub fw_shell: Slot<dyn FwShell>,
    pub credentials_sync: Slot<dyn CredentialsSync>,
    pub channel_writer: Slot<dyn ChannelWriter>,
    pub chat_content: Slot<dyn ChatContent>,
    pub doctor_credential: Slot<dyn DoctorCredential>,
    pub firewall_secrets: Slot<dyn FirewallSecrets>,
    pub doctor_public_key: Slot<dyn DoctorPublicKey>,
    pub fw_logs: Slot<dyn FwLogs>,
    pub self_update: Slot<dyn SelfUpdate>,
}

impl Default for Contracts {
    fn default() -> Self {
        Self {
            consent: RequiredSlot::new("ConsentCodes"),
            code_service: Slot::new("CodeService"),
            buttons: Slot::new("CodeButtons"),
            code_route_source: Slot::new("CodeRouteSource"),
            identities: RequiredSlot::new("IdentityMap"),
            credentials: Contributors::default(),
            code_routes: Slot::new("CodeRoutes"),
            agents: Slot::new("AgentClient"),
            emergency_stop: Slot::new("EmergencyStop"),
            grants: Slot::new("PermissionGrants"),
            agent_permissions: Slot::new("AgentPermissions"),
            app_content: Slot::new("AppContent"),
            judge: Slot::new("IntegrationJudge"),
            mcp_grants: Slot::new("McpGrants"),
            page_access: Slot::new("PageAccess"),
            fw_shell: Slot::new("FwShell"),
            credentials_sync: Slot::new("CredentialsSync"),
            channel_writer: Slot::new("ChannelWriter"),
            chat_content: Slot::new("ChatContent"),
            doctor_credential: Slot::new("DoctorCredential"),
            firewall_secrets: Slot::new("FirewallSecrets"),
            doctor_public_key: Slot::new("DoctorPublicKey"),
            fw_logs: Slot::new("FwLogs"),
            self_update: Slot::new("SelfUpdate"),
        }
    }
}
