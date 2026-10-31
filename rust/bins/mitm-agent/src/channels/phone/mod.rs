//! H7: the phone on the firewall (`phone*.ts`): the Twilio account and number, one assignment to
//! an agent, the proxy entries, and the stream relay.

pub mod api;
pub mod firewall;
pub mod policy;
pub mod stream;
#[cfg(test)]
mod stream_tests;
pub mod twiml;

#[cfg(test)]
mod tests_forms;

#[cfg(test)]
mod tests;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{Map, Value};

use crate::app::{App, Registry};
use crate::channels::agent::AgentCalls;
use crate::channels::llm::Llm;
use crate::contracts::{CredentialContributor, CredentialOrder};
use firewall::{PhoneFirewall, PhoneOptions};

struct PhoneCredentials(Arc<PhoneFirewall>);

impl CredentialContributor for PhoneCredentials {
    fn order(&self) -> CredentialOrder {
        CredentialOrder::Phone
    }
    fn credentials(&self) -> Vec<Value> {
        self.0.credentials()
    }
}

/// The phone module (`index.ts` 1036-1082): `phone.*`, its proxy entries, the 10 s reconcile, the
/// beat's `phone` field and words, and its Twilio hook on the ingress.
pub fn register(
    reg: &mut Registry,
    app: &Arc<App>,
    agent: Arc<dyn AgentCalls>,
    code_routes: Arc<dyn Fn() -> Option<Vec<Value>> + Send + Sync>,
    llm: Arc<Llm>,
) {
    let api: Arc<dyn api::TwilioCalls> = match api::LiveTwilio::new() {
        Ok(a) => Arc::new(a),
        Err(_) => {
            tracing::error!("[phone] encrypted store or public origin unavailable; commands disabled");
            return;
        }
    };
    let hostname = app
        .keys
        .read("vm_hostname")
        .map(|h| h.trim().to_string())
        .unwrap_or_default();
    let me: Arc<std::sync::OnceLock<Arc<PhoneFirewall>>> = Arc::default();
    // Revocation must not wait for the console: only the phone's own entries are replaced in the
    // last config, at once.
    let changed = {
        let me = me.clone();
        Arc::new(move || -> cc_http::BoxFuture<()> {
            let me = me.get().cloned();
            Box::pin(async move {
                let (Some(core), Some(p)) = (crate::core::core(), me) else {
                    return;
                };
                let is_mine = |c: &Value| {
                    c.get("phone").is_some_and(crate::core::sync::js_truthy)
                        || c.get("phone_speech").is_some_and(crate::core::sync::js_truthy)
                };
                if let Err(e) = core.sync.replace_credentials(is_mine, move || p.credentials()).await {
                    tracing::error!("[phone] proxy config not rewritten: {e}");
                }
            })
        })
    };
    let ids = {
        let app = app.clone();
        Arc::new(move |vm: &str, host: &str| {
            app.contracts
                .identities
                .require()
                .ok()
                .and_then(|m| m.agent(vm))
                .is_some_and(|a| a.hostname.as_deref() == Some(host))
        })
    };
    let phone = PhoneFirewall::new(PhoneOptions {
        // `PHONE_STORE_PATH` for the conformance rig only (Rust only); the box uses the default.
        store_path: std::env::var("PHONE_STORE_PATH")
            .ok()
            .filter(|p| !p.is_empty())
            .map_or_else(
                || PathBuf::from("/opt/controlclaw/state/twilio-voice.enc"),
                PathBuf::from,
            ),
        box_key: app.box_key.clone(),
        org_id: app.config.org_id.clone(),
        box_id: app.config.box_id.clone(),
        public_origin: format!("https://{hostname}"),
        valid_target: ids,
        agent,
        codes: crate::channels::contracts_fill::codes_for(app, "phone", false),
        code_routes,
        on_credentials_changed: changed,
        speech_credential: Arc::new(move |s: &policy::SpeechPolicy| {
            llm.speech_credential(&s.provider, &s.credential_id)
        }),
        // No kill switch means no stream: an agent that cannot be checked is treated as locked.
        locked: Arc::new(|vm: &str| {
            crate::core::core()
                .and_then(|c| c.sync.hooks.kill.get().cloned())
                .is_none_or(|k| k.locked_vm_ids(&[vm.to_string()]).iter().any(|v| v == vm))
        }),
        api,
    });
    let phone = match phone {
        Ok(p) => p,
        Err(_) => {
            tracing::error!("[phone] encrypted store or public origin unavailable; commands disabled");
            return;
        }
    };
    let _ = me.set(phone.clone());
    app.contracts.credentials.add(Arc::new(PhoneCredentials(phone.clone())));
    for action in [
        "propose",
        "confirm",
        "cancel",
        "read",
        "push",
        "unassign",
        "forget",
        "disconnect",
    ] {
        let p = phone.clone();
        reg.commands.handle(&format!("phone.{action}"), move |payload| {
            let p = p.clone();
            async move { p.command(action, payload).await }
        });
    }
    let p = phone.clone();
    reg.commands.status(&["phone"], move || {
        let mut m = Map::new();
        m.insert("phone".into(), p.summary());
        m
    });
    crate::channels::contracts_fill::feature(app, "phone", || true);
    // The assigned number's speech, wake words and limits change in one save (`kind: voice`).
    crate::channels::contracts_fill::feature(app, "phone_voice_edit", || true);
    if let Some(core) = crate::core::core().filter(|c| Arc::ptr_eq(&c.app, app))
        && let Ok(mut extra) = core.extra_registrations.lock()
    {
        let p = phone.clone();
        extra.push(Arc::new(move || p.registrations()));
    }
    // The realtime stream and the proxy's admission of outbound calls (`phone-stream.ts`).
    let streams = {
        let (b, c) = (phone.clone(), phone.clone());
        let (keys, box_id) = (app.keys.clone(), app.config.box_id.clone());
        let log = crate::core::core()
            .map(|core| core.env.traffic_log_path.clone())
            .filter(|p| !p.is_empty())
            .map(PathBuf::from);
        stream::PhoneStreams::new(stream::PhoneStreamsOptions {
            binding: Arc::new(move || {
                b.stream_binding()
                    .and_then(|v| v.as_object().cloned())
                    .map(stream::Binding)
            }),
            // Bound like every other firewall token: this route, once.
            sign: Arc::new(move |vm, claims| {
                cc_auth::sign::agent_token(&keys, &box_id, vm, "phone", claims).map_err(|e| e.to_string())
            }),
            host_for: Arc::new(|vm| crate::core::core().and_then(|c| c.agents.host_for(vm))),
            media_dir: app.config.proxy_config_dir.clone(),
            control: Arc::new(move |sid, fields| {
                let c = c.clone();
                Box::pin(async move { c.control_call(&sid, fields).await })
            }),
            log_path: log,
            now: Arc::new(crate::channels::now_ms),
            agent_base: None,
        })
    };
    let _ = phone.streams.set(streams.clone());
    streams.start();
    {
        let router = Arc::new(stream::admission_router(streams.clone()));
        tokio::spawn(async move {
            match tokio::net::TcpListener::bind(("127.0.0.1", cc_contracts::loopback::PHONE_PORT)).await {
                Ok(l) => cc_http::serve(l, router).await,
                Err(_) => tracing::error!("[phone] admission unavailable; outbound calls refused"),
            }
        });
    }
    if let Some(up) = reg.ingress.upgrades_mut() {
        let s = streams.clone();
        up.route(
            crate::stages::INGRESS_UPGRADE,
            |_, path| path.starts_with("/phone-stream/"),
            move |req, _| {
                let s = s.clone();
                async move { s.upgrade(req) }
            },
        );
    }
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(10)).await;
            phone.reconcile().await;
        }
    });
}
