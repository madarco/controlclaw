//! H5: email rules and AgentMail (`email-rules*.ts`, `email-auth.ts`, `agentmail*.ts`).

pub mod agentmail;
pub mod auth;
pub mod rules;
pub mod schema;

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use serde_json::{Map, Value};

use crate::app::{App, Registry};
use crate::channels::agent::AgentCalls;
use crate::channels::google::GoogleFirewall;
use crate::channels::google::http::{GoogleHttp, Req};
use crate::contracts::{ConsentCodes, CredentialContributor, CredentialOrder};
use agentmail::api::{AgentMailCalls, LiveAgentMail};
use agentmail::{AgentMailFirewall, AgentMailOptions};
use rules::{EmailLookups, EmailOptions, EmailRulesFirewall};

/// The rules' own metadata reads: answered before the proxy's 20 s wait runs out.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(15);

type Codes = Arc<dyn Fn() -> Option<Arc<dyn ConsentCodes>> + Send + Sync>;
type Routes = Arc<dyn Fn() -> Result<Vec<Value>, &'static str> + Send + Sync>;

struct AgentMailCredentials(Arc<AgentMailFirewall>);

impl CredentialContributor for AgentMailCredentials {
    fn order(&self) -> CredentialOrder {
        CredentialOrder::AgentMail
    }

    fn credentials(&self) -> Vec<Value> {
        self.0.credentials()
    }
}

/// The rules' own metadata reads: AgentMail with the inbox's key, Gmail with the org account's.
/// No Google module means no account, so a Gmail send is refused.
struct Lookups {
    api: Arc<dyn AgentMailCalls>,
    agentmail: Option<Arc<AgentMailFirewall>>,
    google: Option<Arc<GoogleFirewall>>,
    http: Option<Arc<dyn GoogleHttp>>,
}

impl Lookups {
    fn get(&self, path: String, inbox_id: &str) -> cc_http::BoxFuture<Result<Map<String, Value>, ()>> {
        let key = self.agentmail.as_ref().and_then(|a| a.inbox_key(inbox_id));
        let api = self.api.clone();
        Box::pin(async move {
            let key = key.ok_or(())?;
            // Under the proxy's 20 s, so the firewall answers before the proxy gives up.
            match tokio::time::timeout(LOOKUP_TIMEOUT, api.request("GET", &path, Some(&key), None)).await {
                Ok(Ok(Value::Object(m))) => Ok(m),
                _ => Err(()),
            }
        })
    }
}

impl EmailLookups for Lookups {
    fn agentmail_message(
        &self,
        inbox_id: &str,
        message_id: &str,
    ) -> cc_http::BoxFuture<Result<Map<String, Value>, ()>> {
        let enc = agentmail::api::enc;
        self.get(
            format!("/inboxes/{}/messages/{}", enc(inbox_id), enc(message_id)),
            inbox_id,
        )
    }

    fn agentmail_draft(&self, inbox_id: &str, draft_id: &str) -> cc_http::BoxFuture<Result<Map<String, Value>, ()>> {
        let enc = agentmail::api::enc;
        self.get(format!("/inboxes/{}/drafts/{}", enc(inbox_id), enc(draft_id)), inbox_id)
    }

    /// `To:`/`Cc:`/`Bcc:` of a Gmail draft, read with the account's own token.
    fn gmail_draft_head(&self, draft_id: &str) -> cc_http::BoxFuture<Result<String, ()>> {
        let access = self.google.as_ref().and_then(|g| g.gmail_access());
        let http = self.http.clone();
        let url = format!(
            "https://gmail.googleapis.com/gmail/v1/users/me/drafts/{}?format=metadata&metadataHeaders=To&metadataHeaders=Cc&metadataHeaders=Bcc",
            agentmail::api::enc(draft_id)
        );
        Box::pin(async move {
            let ((_, token), http) = access.zip(http).ok_or(())?;
            let mut req = Req::get(url, &token);
            req.timeout = std::time::Duration::from_secs(15);
            let res = http.send(req).await.map_err(|_| ())?;
            if !res.ok() {
                return Err(());
            }
            let body: Value = serde_json::from_slice(&res.body).map_err(|_| ())?;
            let headers = body
                .get("message")
                .and_then(|m| m.get("payload"))
                .and_then(|p| p.get("headers"))
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            Ok(headers
                .iter()
                .map(|h| {
                    let f = |k: &str| h.get(k).and_then(Value::as_str).unwrap_or("").to_string();
                    format!("{}: {}", f("name"), f("value"))
                })
                .collect::<Vec<_>>()
                .join("\r\n"))
        })
    }

    fn gmail_account(&self) -> Option<String> {
        self.google.as_ref().and_then(|g| g.gmail_access()).map(|(a, _)| a)
    }
}

/// AgentMail, then the email rules (they read AgentMail's keys and move its old sender lists in),
/// then the `8792` listener the proxy asks before every send and inbound read.
pub fn register(
    reg: &mut Registry,
    app: &Arc<App>,
    agent: Arc<dyn AgentCalls>,
    codes: Codes,
    code_routes: Routes,
    on_credentials_changed: Arc<dyn Fn() -> cc_http::BoxFuture<()> + Send + Sync>,
    // The org Google account and the client its reads go through.
    google: Option<(Arc<GoogleFirewall>, Arc<dyn GoogleHttp>)>,
) -> (Option<Arc<AgentMailFirewall>>, Option<Arc<EmailRulesFirewall>>) {
    let api: Arc<dyn AgentMailCalls> = match LiveAgentMail::new() {
        Ok(a) => Arc::new(a),
        Err(_) => {
            tracing::error!("[agentmail] no HTTP client; AgentMail and email rules disabled");
            return (None, None);
        }
    };
    let rules_slot: Arc<OnceLock<Arc<EmailRulesFirewall>>> = Arc::default();
    // Gmail push: built with the Google account, judged by the email rules once they load (none:
    // nothing is woken for).
    if let Some((g, http)) = google.clone() {
        let r = rules_slot.clone();
        crate::channels::gmail_push::wire(
            g,
            http,
            agent.clone(),
            Arc::new(move |headers, labels| {
                let (ok, why, from) = r.get()?.gmail_inbound(headers, labels);
                Some((ok, why.map(str::to_string), from))
            }),
        );
    }
    let agentmail = {
        let (r1, r2) = (rules_slot.clone(), rules_slot.clone());
        AgentMailFirewall::new(AgentMailOptions {
            store_path: PathBuf::from(
                std::env::var("AGENTMAIL_STORE_PATH").unwrap_or_else(|_| "/opt/controlclaw/state/agentmail.enc".into()),
            ),
            box_key: app.box_key.clone(),
            org_id: app.config.org_id.clone(),
            box_id: app.config.box_id.clone(),
            agent,
            on_credentials_changed,
            api: api.clone(),
            // Who may write in comes from the email rules once they load; until then, the inbox's own list.
            allow_from: Arc::new(move |inbox| r1.get().map(|r| r.allow_from(inbox))),
            seed_senders: Arc::new(move |inbox, owner| {
                if let Some(r) = r2.get() {
                    r.seed_inbox(inbox, owner);
                }
            }),
        })
    };
    let agentmail = match agentmail {
        Ok(a) => {
            app.contracts.credentials.add(Arc::new(AgentMailCredentials(a.clone())));
            for action in [
                "signup", "claim", "check", "create", "import", "attach", "forget", "delete", "push", "read", "senders",
            ] {
                let a = a.clone();
                reg.commands.handle(&format!("agentmail.{action}"), move |p| {
                    let a = a.clone();
                    async move { a.command(action, p).await }
                });
            }
            // The account and its inboxes, unless the store could not be read (it holds no answer then).
            let s = a.clone();
            reg.commands.status(&["agentmail"], move || {
                let mut m = Map::new();
                if !cc_crypto::store_health::is_store_unreadable("agentmail") {
                    m.insert("agentmail".into(), s.summary());
                }
                m
            });
            let r = a.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    r.reconcile().await;
                }
            });
            crate::channels::contracts_fill::feature(app, "agentmail", || true);
            Some(a)
        }
        Err(_) => {
            tracing::error!("[agentmail] encrypted store unavailable; commands disabled");
            None
        }
    };

    let env = crate::core::core().map(|c| c.env.clone());
    let log_path = env
        .as_ref()
        .map(|e| e.traffic_log_path.clone())
        .filter(|p| !p.is_empty())
        .map(PathBuf::from);
    let (am_legacy, am_changed) = (agentmail.clone(), agentmail.clone());
    // EMAIL_RULES_STORE_PATH is the Rust build's alone (the conformance rig sets it); the counters go
    // next to the store, so the default is the TS build's two fixed paths.
    let store_path = std::env::var("EMAIL_RULES_STORE_PATH")
        .ok()
        .filter(|p| !p.is_empty())
        .map_or_else(
            || PathBuf::from("/opt/controlclaw/state/email-rules.enc"),
            PathBuf::from,
        );
    let rules = EmailRulesFirewall::new(EmailOptions {
        store_path: store_path.clone(),
        counters_path: store_path.with_file_name("email-counters.json"),
        log_path,
        box_key: app.box_key.clone(),
        org_id: app.config.org_id.clone(),
        box_id: app.config.box_id.clone(),
        codes,
        code_routes,
        lookups: Arc::new(Lookups {
            api,
            agentmail: agentmail.clone(),
            http: google.as_ref().map(|g| g.1.clone()),
            google: google.map(|g| g.0),
        }),
        // No grants store means no approval: every unlisted recipient is asked about.
        grant_active: Arc::new(|id| {
            crate::core::core().is_some_and(|c| c.grants.active(id, crate::core::grants::now_s()))
        }),
        revoke_grants: Some(Arc::new(|matches| {
            crate::core::core()
                .and_then(|c| c.bridge.get().cloned())
                .map(|b| b.revoke_email(matches))
                .unwrap_or_default()
        })),
        // `None` when the AgentMail store did not load: the move of its sender lists then waits.
        legacy_senders: Some(Arc::new(move || {
            am_legacy.as_ref().map(|a| a.legacy_senders()).transpose()
        })),
        on_changed: Some(Arc::new(move || -> cc_http::BoxFuture<()> {
            let a = am_changed.clone();
            Box::pin(async move {
                if let Some(a) = a {
                    a.refresh_senders().await;
                }
            })
        })),
        now: Arc::new(crate::channels::now_ms),
    });
    let rules = match rules {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("[email] rules store unavailable; email sends and AgentMail delivery refused: {e}");
            return (agentmail, None);
        }
    };
    let _ = rules_slot.set(rules.clone());
    crate::channels::contracts_fill::feature(app, "email_rules", || true);
    for action in ["read", "propose", "confirm", "cancel"] {
        let r = rules.clone();
        reg.commands.handle(&format!("email.{action}"), move |p| {
            let r = r.clone();
            async move { r.command(action, p).await }
        });
    }
    let router = Arc::new(rules::router(rules.clone()));
    tokio::spawn(async move {
        match tokio::net::TcpListener::bind(("127.0.0.1", cc_contracts::loopback::EMAIL_PORT)).await {
            Ok(l) => cc_http::serve(l, router).await,
            Err(_) => tracing::error!("[email] admission unavailable; email sends refused"),
        }
    });
    let r = rules.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            r.sweep();
        }
    });
    // Re-push the senders the channel accepts, now that they come from the rules.
    if let Some(a) = agentmail.clone() {
        tokio::spawn(async move { a.refresh_senders().await });
    }
    (agentmail, Some(rules))
}

#[cfg(test)]
mod tests;
