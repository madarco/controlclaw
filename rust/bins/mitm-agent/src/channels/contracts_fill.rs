//! What W4 provides to W3's C2 contracts: where codes can go (`code_route_source`, and W0's
//! `code_routes`), the Telegram approve buttons (`buttons`), and this group's feature words and
//! inventory sections on the beat.

use std::sync::Arc;

use serde_json::Value;

use crate::app::App;
use crate::channels::chan::ChannelsFirewall;
use crate::channels::chan::buttons::{self, CodeButtons, TapVerdict};
use crate::contracts::{self, ButtonOffer, CodeRoute, CodeRouteSource, CodeRoutes, CodeSender, Tap, TelegramRoute};

/// Marks the dev route in the JSON routes the channels build in code. Read only here, into
/// `CodeSender::Dev`; a route from anywhere else never carries it.
const DEV_MARK: &str = "__ccDevRoute";

/// Whether this firewall was built from the test repo (`provenance` → `devConsentAllowed`).
pub fn dev_build() -> bool {
    static DEV: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *DEV.get_or_init(|| {
        crate::core::provenance::dev_consent_allowed(std::path::Path::new(crate::core::provenance::PROVENANCE_PATH))
    })
}

/// The dev route as the channels list it, last.
pub fn dev_route_json() -> Value {
    serde_json::json!({"target": {"vmId": "dev", "hostname": "dev"}, "senders": [], "agentName": "this firewall", DEV_MARK: true})
}

/// Where nobody can be reached: what the routes are while they are not known.
fn unknown_route() -> CodeRoute {
    CodeRoute {
        vm_id: "unknown".into(),
        hostname: "unknown".into(),
        senders: vec![],
        telegram: None,
    }
}

/// A route the channels built: the dev route, or one person route.
fn route_of(v: &Value) -> Option<CodeRoute> {
    if v.get(DEV_MARK) == Some(&Value::Bool(true)) {
        return Some(CodeRoute {
            vm_id: "dev".into(),
            hostname: "dev".into(),
            senders: vec![CodeSender::Dev],
            telegram: None,
        });
    }
    typed_route(v)
}

/// `channels.codeRoutes()` as C2's typed routes, the dev route last on a firewall built from the
/// test repo. `ready()` is false when the channel store could not be read.
pub struct ChannelRoutes {
    pub channels: Arc<ChannelsFirewall>,
}

/// One route as `code_routes_of` writes it, typed. A route that does not read is left out.
pub fn typed_route(v: &Value) -> Option<CodeRoute> {
    let t = v.get("target")?;
    let s = |x: &Value, k: &str| x.get(k).and_then(Value::as_str).map(str::to_string);
    Some(CodeRoute {
        vm_id: s(t, "vmId")?,
        hostname: s(t, "hostname")?,
        senders: v
            .get("senders")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|x| {
                        Some(CodeSender::Person {
                            kind: s(x, "type")?,
                            id: s(x, "id")?,
                            label: s(x, "label"),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default(),
        telegram: v.get("telegram").and_then(|t| {
            Some(TelegramRoute {
                connection_id: s(t, "connectionId")?,
                bot_token: s(t, "botToken")?,
            })
        }),
    })
}

impl CodeRouteSource for ChannelRoutes {
    /// The routes. When they are not known (an approved person's agent has no address, or the store
    /// cannot be read) it is one route nobody can be reached on, never `[]`: a caller that checked
    /// `ready()` a moment before must not take an empty list for "nobody approved".
    fn routes(&self) -> Vec<CodeRoute> {
        match self.channels.code_routes_checked() {
            Some(r) => r.iter().filter_map(route_of).collect(),
            None => vec![unknown_route()],
        }
    }

    /// `channelsReady`: the channel store could be read (as the TS reads it).
    fn ready(&self) -> bool {
        self.channels.ready()
    }

    /// `codeRecipients().allowed?.length`, as the TS reads it whatever the store's state.
    fn agent_allowed_count(&self) -> Option<u32> {
        self.channels
            .code_recipients()
            .get("allowed")
            .and_then(Value::as_array)
            .map(|a| a.len() as u32)
    }
}

/// W0's untyped routes, for callers still on the first consent shapes. That shape has no way to
/// say "I cannot read my channel list", and its callers apply on first use when the list is empty;
/// so then it answers one route nobody can be reached on, and the code is refused (fail closed).
pub struct ChannelRoutesJson(pub Arc<ChannelsFirewall>);

impl CodeRoutes for ChannelRoutesJson {
    fn routes(&self) -> Vec<Value> {
        // The dev route stays: W3's adapter reads it as a route with nobody on it, so a dev build
        // refuses there rather than applying on first use.
        self.0.code_routes_checked().unwrap_or_else(|| {
            vec![serde_json::json!({"target": {"vmId": "unknown", "hostname": "unknown"}, "senders": []})]
        })
    }

    /// The routes are known: the channel store was read and every agent with approved people has
    /// an address. Without this the trait says false, and every change W5's modules send a code
    /// for (team chat, Doctor, website logins, integrations) was refused (found on the live round).
    /// Not just `channelsReady`: with an agent that has no address, `routes` stands in a route with
    /// nobody on it, which a caller counting senders reads as nobody to ask, and so first use.
    fn ready(&self) -> bool {
        self.0.code_routes_status().is_ok()
    }
}

/// The contract's tap owner, as the buttons module calls it.
struct Owner(Arc<dyn contracts::TapOwner>);

impl buttons::TapOwner for Owner {
    fn tap(&self, correct: bool) -> TapVerdict {
        match self.0.tap(correct) {
            Tap::Ok => TapVerdict::Ok,
            Tap::Wrong => TapVerdict::Wrong,
            Tap::Spent => TapVerdict::Spent,
            Tap::Gone => TapVerdict::Gone,
        }
    }
    fn cancel(&self) {
        self.0.cancel();
    }
}

/// The buttons module behind C2's `CodeButtons`.
pub struct Buttons {
    pub buttons: Arc<CodeButtons>,
    /// Whether the tap listener is up: without it a tap could never reach the firewall.
    pub listening: Arc<std::sync::atomic::AtomicBool>,
}

impl contracts::CodeButtons for Buttons {
    fn available(&self) -> bool {
        self.listening.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn offer(&self, o: ButtonOffer) -> cc_http::BoxFuture<Option<String>> {
        let b = self.buttons.clone();
        Box::pin(async move {
            b.offer(buttons::OfferInput {
                change_id: o.change_id,
                route: buttons::TelegramButtonsRoute {
                    connection_id: o.route.connection_id,
                    bot_token: o.route.bot_token,
                },
                sender_id: o.sender_id,
                text: o.text,
                render: o.render,
                code: o.code,
                expires_at: o.expires_at_ms as i64,
                owner: Arc::new(Owner(o.owner)),
            })
            .await
        })
    }

    fn settle(&self, nonce: Option<&str>, how: &str) {
        // Most codes went out without buttons; and off the runtime there is nothing to edit with.
        let (Some(nonce), Ok(rt)) = (nonce, tokio::runtime::Handle::try_current()) else {
            return;
        };
        let (b, nonce, how) = (self.buttons.clone(), nonce.to_string(), how.to_string());
        rt.spawn(async move { b.settle(Some(&nonce), &how, None).await });
    }
}

/// `ChannelWriter` (`channel-apply.ts`) for team chat (W5): one channel written to an agent with an
/// apply id, then asked how it ended when the answer did not come in time.
pub struct Writer(pub Arc<super::chan::apply::ChannelWriter>);

impl contracts::ChannelWriter for Writer {
    fn write(
        &self,
        vm_id: &str,
        hostname: &str,
        kind: &str,
        body: Value,
    ) -> cc_http::BoxFuture<Result<contracts::ApplyOutcome, String>> {
        let target = super::agent::Target::new(vm_id, hostname);
        let (w, kind) = (self.0.clone(), kind.to_string());
        Box::pin(async move {
            match w.write(&target, &kind, body, None).await? {
                super::chan::apply::ApplyOutcome::Applied => Ok(contracts::ApplyOutcome::Applied),
                super::chan::apply::ApplyOutcome::Unconfirmed => Ok(contracts::ApplyOutcome::Unconfirmed),
            }
        })
    }
}

/// Fill the slots this group provides.
pub fn fill(
    app: &Arc<App>,
    channels: Arc<ChannelsFirewall>,
    buttons: Arc<CodeButtons>,
    listening: Arc<std::sync::atomic::AtomicBool>,
) {
    app.contracts.code_route_source.set(Arc::new(ChannelRoutes {
        channels: channels.clone(),
    }));
    app.contracts.code_routes.set(Arc::new(ChannelRoutesJson(channels)));
    app.contracts.buttons.set(Arc::new(Buttons { buttons, listening }));
}

/// The core this app's register built (another app's, in a test that builds two, is left alone).
fn core_of(app: &Arc<App>) -> Option<Arc<crate::core::Core>> {
    crate::core::core().filter(|c| Arc::ptr_eq(&c.app, app))
}

/// A feature word on this app's beat.
pub fn feature(app: &Arc<App>, word: &'static str, on: impl Fn() -> bool + Send + Sync + 'static) {
    if let Some(core) = core_of(app) {
        core.beat.feature(word, on);
    }
}

/// An inventory section on this app's beat.
pub fn inventory(app: &Arc<App>, key: &'static str, f: impl Fn() -> Option<Vec<Value>> + Send + Sync + 'static) {
    if let Some(core) = core_of(app) {
        core.beat.inventory_section(key, f);
    }
}

/// One module's codes from C2's `code_service`, behind the first consent shapes this group's
/// modules were written against. The module is part of the key: a code sent for one module can
/// never confirm another's, whatever the scope. `no_buttons`: a code typed somewhere other than the
/// console's code dialog (secrets, email rules, meetings), as the TS's `buttons: false`.
pub struct ModuleConsent {
    codes: Arc<dyn contracts::ModuleCodes>,
    no_buttons: bool,
}

impl contracts::ConsentCodes for ModuleConsent {
    fn send(&self, req: contracts::CodeRequest) -> cc_http::BoxFuture<contracts::SendResult> {
        let ask = contracts::CodeAsk {
            scope: req.scope,
            change_id: req.change_id,
            proposal: req.proposal,
            agent_name: req.agent_name,
            summary: req.summary,
            routes: req.routes.iter().filter_map(route_of).collect(),
            no_buttons: self.no_buttons,
            ..Default::default()
        };
        let codes = self.codes.clone();
        Box::pin(async move {
            match codes.send(ask).await {
                contracts::CodeSent::Sent {
                    sent_via, expires_at, ..
                } => contracts::SendResult {
                    sent_via: Some(sent_via),
                    error: None,
                    delivery_failed: false,
                    expires_at_ms: crate::integrations::js::parse_iso(&expires_at).unwrap_or_else(|| {
                        // Codes live ten minutes: said, rather than reported as long expired.
                        tracing::error!("[codes] an expiry that does not read ({expires_at}); taking ten minutes");
                        crate::channels::now_ms() + 10 * 60_000
                    }),
                },
                contracts::CodeSent::Failed { message } => contracts::SendResult {
                    sent_via: None,
                    error: Some(message),
                    delivery_failed: true,
                    expires_at_ms: 0,
                },
            }
        })
    }

    fn verify(&self, scope: &str, change_id: &str, code: &str) -> contracts::Verify {
        match self.codes.verify(scope, change_id, code) {
            contracts::CodeCheck::Ok { proposal, .. } => contracts::Verify::Ok(proposal),
            contracts::CodeCheck::Wrong { tries_left } => contracts::Verify::Wrong { tries_left },
            contracts::CodeCheck::Expired => contracts::Verify::Expired,
        }
    }

    fn cancel(&self, scope: &str, change_id: Option<&str>) -> bool {
        self.codes.cancel(scope, change_id)
    }

    fn forget(&self, scope: &str) {
        self.codes.forget(scope)
    }
}

pub type Codes = Arc<dyn Fn() -> Option<Arc<dyn contracts::ConsentCodes>> + Send + Sync>;

/// `module`'s codes, once W3's code service is up; `None` (and so every coded change refused)
/// until then.
pub fn codes_for(app: &Arc<App>, module: &'static str, no_buttons: bool) -> Codes {
    let app = app.clone();
    let handle: Arc<std::sync::OnceLock<Arc<dyn contracts::ConsentCodes>>> = Arc::default();
    Arc::new(move || {
        if let Some(h) = handle.get() {
            return Some(h.clone());
        }
        let service = app.contracts.code_service.get()?;
        let h: Arc<dyn contracts::ConsentCodes> = Arc::new(ModuleConsent {
            codes: service.module(module),
            no_buttons,
        });
        Some(handle.get_or_init(|| h).clone())
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::sync::Mutex;

    use serde_json::json;

    use super::*;
    use crate::contracts::{CodeAsk, CodeCheck, CodeSent, ConsentCodes, ModuleCodes, Verify};

    #[derive(Default)]
    struct Fake {
        asks: Mutex<Vec<CodeAsk>>,
        answer: Mutex<Option<CodeSent>>,
    }

    impl ModuleCodes for Fake {
        fn send(&self, req: CodeAsk) -> cc_http::BoxFuture<CodeSent> {
            self.asks.lock().unwrap().push(req);
            let a = self.answer.lock().unwrap().clone().unwrap();
            Box::pin(async move { a })
        }
        fn verify(&self, _: &str, change_id: &str, _: &str) -> CodeCheck {
            match change_id {
                "ok" => CodeCheck::Ok {
                    proposal: json!({"x": 1}),
                    sent_via: "telegram".into(),
                },
                "wrong" => CodeCheck::Wrong { tries_left: 3 },
                _ => CodeCheck::Expired,
            }
        }
        fn cancel(&self, _: &str, _: Option<&str>) -> bool {
            true
        }
        fn forget(&self, _: &str) {}
    }

    fn route() -> Value {
        json!({"target": {"vmId": "vm1", "hostname": "a.example"}, "senders": [{"type": "telegram", "id": "42", "label": "Ana"}, {"type": "slack"}],
               "agentName": "a", "telegram": {"connectionId": "c1", "botToken": "1:x"}})
    }

    #[test]
    fn a_route_is_typed_and_a_sender_that_does_not_read_is_left_out() {
        let r = typed_route(&route()).unwrap();
        assert_eq!(r.vm_id, "vm1");
        assert_eq!(
            r.senders,
            vec![CodeSender::Person {
                kind: "telegram".into(),
                id: "42".into(),
                label: Some("Ana".into())
            }]
        );
        assert_eq!(r.telegram.unwrap().bot_token, "1:x");
        assert!(typed_route(&json!({"senders": []})).is_none());
    }

    #[tokio::test]
    async fn the_module_adapter_passes_buttons_off_and_maps_the_answers() {
        let fake = Arc::new(Fake::default());
        *fake.answer.lock().unwrap() = Some(CodeSent::Sent {
            sent_via: "telegram:Ana".into(),
            expires_at: "2026-10-28T10:00:00.000Z".into(),
            attempts_left: 5,
            recovery: None,
        });
        let c = ModuleConsent {
            codes: fake.clone(),
            no_buttons: true,
        };
        let sent = c
            .send(contracts::CodeRequest {
                scope: "email".into(),
                change_id: "c".into(),
                proposal: json!({}),
                agent_name: "your email rules".into(),
                summary: "s".into(),
                routes: vec![route(), json!({"bad": true})],
            })
            .await;
        assert_eq!(sent.sent_via.as_deref(), Some("telegram:Ana"));
        assert_eq!(
            cc_crypto::store_health::iso_from_millis(sent.expires_at_ms),
            "2026-10-28T10:00:00.000Z"
        );
        let ask = fake.asks.lock().unwrap()[0].clone();
        assert!(ask.no_buttons);
        assert_eq!(ask.routes.len(), 1);
        *fake.answer.lock().unwrap() = Some(CodeSent::Failed {
            message: "nobody".into(),
        });
        let failed = c
            .send(contracts::CodeRequest {
                scope: "email".into(),
                change_id: "c".into(),
                proposal: json!({}),
                agent_name: String::new(),
                summary: String::new(),
                routes: vec![],
            })
            .await;
        assert_eq!((failed.sent_via, failed.error.as_deref()), (None, Some("nobody")));
        assert_eq!(c.verify("s", "ok", "1"), Verify::Ok(json!({"x": 1})));
        assert_eq!(c.verify("s", "wrong", "1"), Verify::Wrong { tries_left: 3 });
        assert_eq!(c.verify("s", "gone", "1"), Verify::Expired);
    }

    #[test]
    fn only_the_channels_dev_route_is_dev() {
        assert_eq!(route_of(&dev_route_json()).unwrap().senders, vec![CodeSender::Dev]);
        // A sender that calls itself dev is a person, and one with nothing to read is dropped.
        let r = route_of(&json!({"target": {"vmId": "a", "hostname": "h"}, "senders": [{"type": "dev", "id": "dev"}]}))
            .unwrap();
        assert!(matches!(r.senders[0], CodeSender::Person { .. }));
        let marked = json!({"target": {"vmId": "a", "hostname": "h"}, "senders": [], "__ccDevRoute": "yes"});
        assert!(route_of(&marked).unwrap().senders.is_empty());
    }
}
