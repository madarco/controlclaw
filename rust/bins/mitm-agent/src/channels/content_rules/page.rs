//! The firewall's own Content rules page (`content-rules-page.ts`): the messages held now and what
//! the rules stopped in the last seven days, with the rule's reason and the text. The texts never
//! leave this firewall; the console sees only the audit's metadata. Same door as the Logs page: an
//! open intent for THIS firewall buys a two-hour cookie. Read-only: Send and Don't send stay in the
//! firewall's Telegram message. The body and script are the TS's, as it renders them.

use std::collections::HashSet;
use std::sync::Arc;

use serde_json::{Map, Value, json};

use super::firewall::ContentRulesFirewall;
use super::stopped::ContentStoppedStore;
use crate::core::access::AccessFirewall;
use crate::core::fw_logs::{FwPageDoor, PageReply, PageRequest};
use crate::core::fw_shell::{FwPage, fw_shell_page};

pub const CONTENT_PAGE_ROOT: &str = "/__cc/doctor/content-rules";
const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; font-src data:; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";
const PAGE_BODY: &str = include_str!("page_body.html");
const PAGE_JS: &str = include_str!("page_app.js");

pub fn owns_content_page_path(path: &str) -> bool {
    path == CONTENT_PAGE_ROOT || path.starts_with(&format!("{CONTENT_PAGE_ROOT}/"))
}

type NameOf = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

pub struct ContentRulesPage {
    door: FwPageDoor,
    rules: Arc<ContentRulesFirewall>,
    stopped: Option<Arc<ContentStoppedStore>>,
    /// The agent's name as the org knows it.
    agent_name: NameOf,
    /// Where "Back to console" goes.
    console_url: Arc<dyn Fn() -> Option<String> + Send + Sync>,
}

impl ContentRulesPage {
    pub fn new(
        access: Arc<AccessFirewall>,
        rules: Arc<ContentRulesFirewall>,
        stopped: Option<Arc<ContentStoppedStore>>,
        agent_name: NameOf,
        console_url: Arc<dyn Fn() -> Option<String> + Send + Sync>,
        now: Arc<dyn Fn() -> u64 + Send + Sync>,
    ) -> Self {
        // An owner or admin only: the texts are what the organization's agents wrote and were sent.
        Self {
            door: FwPageDoor::new(
                access,
                CONTENT_PAGE_ROOT,
                "__Secure-cc_fw_content",
                "content-rules",
                "Content rules",
                "Opening what the content rules stopped...",
                "Open it from the console (Security rules, then Content rules, then What was stopped) in an enrolled browser. Open a working agent first to enroll this browser.",
                CSP,
                now,
            ),
            rules,
            stopped,
            agent_name,
            console_url,
        }
    }

    pub async fn handle(&self, req: &PageRequest) -> PageReply {
        let root = CONTENT_PAGE_ROOT;
        if let Some(r) = self.door.handle(req).await {
            return r;
        }
        if req.path == format!("{root}/") {
            let html = fw_shell_page(
                "Content rules",
                Some(FwPage::Content),
                PAGE_BODY,
                Some((self.console_url)()),
                r#"<script src="app.js"></script>"#,
                None,
            );
            return self.door.send(200, &html, "text/html");
        }
        if req.path == format!("{root}/app.js") {
            return self.door.send(200, PAGE_JS, "text/javascript");
        }
        if req.path == format!("{root}/data") {
            let first = |k: &str| {
                url::form_urlencoded::parse(req.query.as_bytes())
                    .find(|(n, _)| n == k)
                    .map(|(_, v)| v.into_owned())
            };
            // `Number(query.get("before"))`, kept when finite and above 0.
            let raw = first("before")
                .map(|b| crate::core::ingress::js_number(Some(&json!(b))))
                .filter(|b| b.is_finite() && *b > 0.0);
            // A whole number is compared as it is; a fraction as the next one up, with no tie.
            let before = raw.map(|b| b.ceil() as i64);
            let before_id = first("beforeId")
                .filter(|s| !s.is_empty())
                .filter(|_| raw.is_some_and(|b| b.fract() == 0.0));
            let stopped = self
                .stopped
                .as_ref()
                .map(|s| s.list(before, before.and(before_id.as_deref()), Some(50)))
                .unwrap_or_default();
            let held: Vec<Value> = if first("before").is_some_and(|b| !b.is_empty()) {
                vec![]
            } else {
                self.rules.held_now()
            };
            let mut agents = Map::new();
            let mut seen = HashSet::new();
            let vms = stopped
                .iter()
                .filter_map(|e| e.vm_id.clone())
                .chain(held.iter().filter_map(|h| h["vmId"].as_str().map(str::to_string)));
            for vm in vms {
                if !seen.insert(vm.clone()) || vm.is_empty() {
                    continue;
                }
                if let Some(name) = (self.agent_name)(&vm).filter(|n| !n.is_empty()) {
                    agents.insert(vm, json!(name));
                }
            }
            let body = json!({"held": held, "stopped": stopped, "agents": agents});
            return self.door.send(200, &body.to_string(), "application/json");
        }
        self.door.send(404, "", "text/plain")
    }
}
