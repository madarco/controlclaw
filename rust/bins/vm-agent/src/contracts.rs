//! What one workstream provides and others use on the agent box, decided before the fan-out. W0
//! owns this file. The provider fills its slot in its `register`; users read the slot when they
//! handle a request.
//!
//! While a slot is still empty, users fail closed (host rule): `Slot::require()` and refuse when
//! what they do would let somebody in or loosen anything (a page with no `Sessions` answers as an
//! unsigned-in request does); `Slot::get()` only where an empty slot can only do less (`/stop` with
//! no `MeetingControl` has no meeting to leave).

use std::sync::Arc;

use cc_http::{BoxFuture, RequiredSlot, Slot};

/// The meeting the agent is in (`MeetingsService` in `meetings.ts`). Provided by W8; used by W6:
/// `/stop` and `/restart` leave the meeting first, and the watchdog does not restart the
/// redirector during one.
pub trait MeetingControl: Send + Sync {
    /// In a meeting or about to be (`busy()`).
    fn busy(&self) -> bool;
    /// Leave and clean up (`stop()`). The error is logged by the caller; it never stops the stop.
    fn stop(&self) -> BoxFuture<Result<(), String>>;
    /// The meetings feature is on (`meetings.metadata().enabled`): the page shell lists Meetings.
    /// Added by W8 for its own `AgentPages`; false by default.
    fn listed(&self) -> bool {
        false
    }
}

/// The phone calls on this box. Provided by W8; used by W6's watchdog and its heal checks, which
/// leave the redirector and OpenClaw alone during a call. W6 reads an empty slot as "a call may be
/// on" (fail closed); on an agent box W8 always fills it.
pub trait PhoneControl: Send + Sync {
    /// The relay carries a call (`phoneRelay.busy()`).
    fn relay_busy(&self) -> bool;
    /// A call the voice plugin still has open (`phoneCalls.calls().some(callInProgress)`), false
    /// when its records cannot be read.
    fn call_in_progress(&self) -> bool;
    /// `callSessions(phoneCalls.calls(), callInProgress, now, lookback)` for W6's session shipper:
    /// each answered call started within `lookback_ms`. Reads SQLite, which can wait seconds on the
    /// plugin's lock: call it off the runtime's threads (`spawn_blocking`). Empty when the records
    /// cannot be read. Added by W8 for W6.
    fn call_sessions(&self, now_ms: i64, lookback_ms: i64) -> Vec<CallSession>;
}

/// One call on the console's timeline (`Session` with `kind: "call"`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallSession {
    pub call_id: String,
    /// `answeredAt ?? startedAt`, in ms.
    pub started_at: i64,
    /// `None` while the call is in progress, else `endedAt ?? answeredAt ?? startedAt`.
    pub ended_at: Option<i64>,
}

/// A browser's session on this box (`__Host-cc_session`, `session.ts`). Provided by W7; used by
/// W8's meetings and calls pages.
pub trait Sessions: Send + Sync {
    /// The request's valid session, or `None`. Reads the cookie the way `readUniqueCookie` does (a
    /// name sent twice counts as absent) and refuses a revoked device.
    fn session(&self, parts: &http::request::Parts) -> Option<Session>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    /// Owner or admin; a member gets false.
    pub can_write: bool,
    /// The firewall's name for the browser, when the session came from a firewall ticket.
    pub device_id: Option<String>,
}

/// The local OpenClaw gateway: the client and the config write queue every writer goes through
/// (`GatewayClient`, `patchConfig`). Provided by W6 when the box has a gateway token; used by W7
/// and W8. Empty when the TS `gateway` was null.
pub struct OpenClaw {
    pub client: cc_openclaw::GatewayClient,
    pub config: Arc<cc_openclaw::ConfigWriter>,
}

/// Which of the optional pages the shared page shell lists (`setShellNav` in index.ts). Provided
/// by W8; used by W7's page shell. An empty slot lists neither.
pub trait AgentPages: Send + Sync {
    /// The meetings feature is on (`meetings.metadata().enabled`).
    fn meetings_listed(&self) -> bool;
    /// A phone number is active, or calls are on record.
    fn phone_listed(&self) -> bool;
}

/// The WhatsApp link the channels service has open (`channels.whatsappLogin()`, handed to
/// `setWhatsappLoginProvider`). Provided by W6; used by W7's `/__cc/whatsapp` page and the sidebar.
pub trait WhatsappLogin: Send + Sync {
    /// `None` when there is no channels service.
    fn whatsapp_login(&self) -> Option<WhatsappLoginState>;
}

/// `{state, qrDataUrl, message}`; `state` is `idle` when no link is waiting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WhatsappLoginState {
    pub state: String,
    pub qr_data_url: Option<String>,
    pub message: Option<String>,
}

/// The review a template preview left for the file explorer (`readTemplateReview(STATE_DIR/
/// templates)` in templates.ts). Provided by W6; used by W7's `GET /files/template-review`. An
/// empty slot, or `None`, is `{template: null, files: []}`.
pub trait TemplateReview: Send + Sync {
    /// `{template, at, files}` as the TS returns it, or `None`.
    fn template_review(&self) -> Option<serde_json::Value>;
}

/// What a restore does around the meetings (`beforeRestore`, `sanitizeRestore`,
/// `restoreFinished` in index.ts). Provided by W8; used by W7's backup service. While the slot is
/// empty no restore runs: without the scrub a restore could bring back meetings an owner deleted.
pub trait BackupHooks: Send + Sync {
    /// Stop private capture before OpenClaw is stopped (`meetings.prepareRestore()`). An `Err` is
    /// the TS's throw: the restore stops before anything was stopped, with that message.
    fn before_restore(&self) -> BoxFuture<Result<(), String>>;
    /// Scrub the verified staging tree before it becomes the live one: deleted meetings out of the
    /// archive, and for `state` the native meeting records and the restored config. An `Err` stops
    /// the restore before the swap; OpenClaw is started again and the message is the answer.
    fn sanitize_restore(&self, kind: &str, staging: &std::path::Path) -> Result<(), String>;
    /// The restore ended, however it ended (`meetings.restoreFinished()`).
    fn restore_finished(&self);
}

/// Meetings and calls for Download workspace (W7's export). Provided by W8. An empty slot means
/// no `meetings/` and `calls/` folders in the zip.
pub trait ExportRecords: Send + Sync {
    /// `MeetingRecord`s as the TS JSON.
    fn meetings(&self) -> Vec<serde_json::Value>;
    /// `PhoneCallDetail`s as the TS JSON.
    fn calls(&self) -> Vec<serde_json::Value>;
}

/// OpenClaw's conversations for Download workspace (`openclaw-transcripts.ts`). Provided by W6.
/// An empty slot means no `conversations/` folder.
pub trait Transcripts: Send + Sync {
    /// `ConversationRef`s as the TS JSON (agentId, db, sessionId, sessionKey, createdAt, label, bytes, channels).
    fn list(&self) -> Vec<serde_json::Value>;
    /// The `Conversation` behind a ref, with its turns.
    fn read(&self, conversation_ref: &serde_json::Value) -> Option<serde_json::Value>;
}

/// The bootstrap steps on the box side (`mitm-ca.ts`, `egress.ts`, `https-ready.ts`,
/// `handle-certificate.ts`), and what `/status` and the ready report read from it. Provided by W7;
/// used by W6's bootstrap. Agreed with W7.
pub trait BoxSetup: Send + Sync {
    /// `reportHandleCertificate(KEYS_DIR)`: fire and forget, retries until accepted.
    fn report_handle_certificate(&self);
    /// `ensureMitmCaInstalled(KEYS_DIR).trusted`.
    fn install_ca(&self) -> BoxFuture<bool>;
    /// Pool box: `trustMitmCaInProcess()`.
    fn trust_ca_in_process(&self) -> bool;
    /// `enableTransparentEgress(KEYS_DIR)`.
    fn enable_egress(&self) -> BoxFuture<bool>;
    /// `waitForOwnCertificate(() => ownCertificateServes(hostname), { timeoutMs })`.
    fn own_certificate(&self, hostname: String, timeout: std::time::Duration) -> BoxFuture<bool>;
    /// `ssh.status()` for the ready report (W6 adds `at`); None without a rescue service.
    fn ssh_reading(&self) -> Option<serde_json::Value>;
    /// `drive.summary()`: `{folders, mounted, connected}` for `/status`, None without Drive.
    fn drive_summary(&self) -> Option<serde_json::Value>;
}

/// The contracts' slots, on [`crate::app::App`].
pub struct Contracts {
    pub meeting: Slot<dyn MeetingControl>,
    /// Required: a page with no provider answers as to a browser that is not signed in.
    pub sessions: RequiredSlot<dyn Sessions>,
    pub openclaw: Slot<OpenClaw>,
    pub pages: Slot<dyn AgentPages>,
    pub whatsapp: Slot<dyn WhatsappLogin>,
    /// W7's sign-in shim, for W8's pages: the shared page shell's context, the "not signed in"
    /// pages (`DENIED_MEETINGS_PAGE`, `DENIED_PHONE_PAGE`), the box's own origin.
    pub access: Slot<crate::boxside::Access>,
    pub template_review: Slot<dyn TemplateReview>,
    pub backup_hooks: Slot<dyn BackupHooks>,
    pub export_records: Slot<dyn ExportRecords>,
    pub transcripts: Slot<dyn Transcripts>,
    pub box_setup: Slot<dyn BoxSetup>,
    /// W7's org Google account (`google`), for W8's meeting sign-in. Empty without `gog`.
    pub google: Slot<crate::boxside::google::Google>,
    /// W7's Gmail push watcher, for W6's `/hooks/gmail` and `/hooks/gmail/status`. Empty without
    /// `gog` (the TS `gmailWatch` null: the routes' 501).
    pub gmail_watch: Slot<crate::boxside::gmail::GmailWatch>,
    /// W7's wake through OpenClaw's hook, for W6's `/hooks/gmail-wake`, W8's meeting follow-up and
    /// W7's website logins.
    pub gmail_wake: Slot<crate::boxside::gmail::GmailWake>,
    /// W7's AgentMail inbox apply, for W8's invite reader (`status().inboxId`).
    pub agentmail: Slot<crate::boxside::agentmail::AgentMail>,
    pub phone: Slot<dyn PhoneControl>,
    /// W6's own state, shared between its `register` and its `start` (not a contract).
    pub platform: Slot<crate::platform::Platform>,
}

impl Default for Contracts {
    fn default() -> Self {
        Self {
            meeting: Slot::new("MeetingControl"),
            sessions: RequiredSlot::new("Sessions"),
            openclaw: Slot::new("OpenClaw"),
            phone: Slot::new("PhoneControl"),
            pages: Slot::new("AgentPages"),
            whatsapp: Slot::new("WhatsappLogin"),
            access: Slot::new("Access"),
            template_review: Slot::new("TemplateReview"),
            backup_hooks: Slot::new("BackupHooks"),
            export_records: Slot::new("ExportRecords"),
            transcripts: Slot::new("Transcripts"),
            box_setup: Slot::new("BoxSetup"),
            google: Slot::new("Google"),
            gmail_watch: Slot::new("GmailWatch"),
            gmail_wake: Slot::new("GmailWake"),
            agentmail: Slot::new("AgentMail"),
            platform: Slot::new("Platform"),
        }
    }
}
