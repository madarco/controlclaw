//! Doctor on the firewall: repairing an agent (or this firewall) with a coding agent after a code,
//! its transcripts, the model bridge, the runner, the key the agents trust, and the pages a person
//! uses (the chat, the terminal, the start page).

pub mod capture;
pub mod chat;
pub mod credentials;
pub mod firewall;
pub mod fw_tools;
pub mod gateway;
pub mod key;
pub mod loopback;
#[cfg(test)]
pub mod pages_test;
pub mod repair;
pub mod reserve;
pub mod runner;
pub mod start;
pub mod store;
pub mod stream;
pub mod terminal;
pub mod tplcheck;
pub mod transcript;

use std::sync::Arc;

use serde::Serialize;

/// `Date.now`, or the tests' clock.
pub type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;

/// An agent Doctor can repair (`DoctorTarget`), as the runner is handed it.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Target {
    pub vm_id: String,
    pub name: String,
    pub hostname: String,
    pub private_ip: String,
    pub ssh_host_key: String,
    pub key_ready: bool,
    /// `agent` or `firewall`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
}

use std::path::PathBuf;
use std::time::Duration;

use serde_json::{Value, json};

use crate::app::{App, Registry};
use crate::integrations::Env;
use crate::integrations::js;

pub const ACTIONS: &[&str] = &["propose", "confirm", "stop"];

/// The agents Doctor knows: the identity map's agents with a name, and what the key store learned.
fn targets(app: &Arc<App>, keys: &Arc<key::DoctorKeyStore>) -> Vec<Target> {
    app.contracts
        .identities
        .require()
        .ok()
        .map(|i| i.agents())
        .unwrap_or_default()
        .into_iter()
        .filter_map(|a| {
            let host = a.hostname.clone().filter(|h| !h.is_empty())?;
            Some(Target {
                name: a.name.clone().filter(|n| !n.is_empty()).unwrap_or_else(|| host.clone()),
                key_ready: keys.ready(&a.vm_id),
                ssh_host_key: keys.host_key(&a.vm_id).unwrap_or_default(),
                vm_id: a.vm_id,
                hostname: host,
                private_ip: a.private_ip,
                kind: None,
            })
        })
        .collect()
}

/// `new URL(path, FIREWALL_URL)`: a console route next to the firewall's own.
fn console_route(app: &App, path: &str) -> Option<String> {
    url::Url::parse(&app.config.firewall_url)
        .ok()?
        .join(path)
        .ok()
        .map(|u| u.to_string())
}

/// `makeDoctorUploader`: the session's metadata to the console.
fn uploader(app: &Arc<App>) -> firewall::UploadFn {
    let app = app.clone();
    Arc::new(move |body: firewall::Upload| {
        let app = app.clone();
        Box::pin(async move {
            let Some(url) = console_route(&app, "doctor") else {
                return Err(firewall::SendError::Failed);
            };
            let send = |with_kind: bool| {
                let mut v = crate::integrations::as_map(json!({"sessionId": body.session_id}));
                if with_kind {
                    v.insert("kind".into(), json!(body.kind));
                }
                v.insert("state".into(), json!(body.state));
                if let Some(r) = &body.end_reason {
                    v.insert("endReason".into(), json!(r));
                }
                if let Some(c) = &body.created {
                    v.insert("created".into(), c.clone());
                }
                let (app, url) = (app.clone(), url.clone());
                async move {
                    app.console
                        .post_json(&url, &Value::Object(v), Duration::from_secs(15))
                        .await
                }
            };
            let mut r = send(true).await.map_err(|_| firewall::SendError::Failed)?;
            // A console older than `kind` refuses a field it does not name (400).
            if r.status == 400 && body.kind.starts_with("repair-") {
                r = send(false).await.map_err(|_| firewall::SendError::Failed)?;
            }
            if r.status == 403 && r.body.get("refused") == Some(&Value::Bool(true)) {
                return Err(firewall::SendError::RefusedRepair);
            }
            if (200..300).contains(&r.status) {
                Ok(())
            } else {
                Err(firewall::SendError::Failed)
            }
        })
    })
}

/// `makeProposalSender`: a repair's files or a capture's draft, only when a person pressed Send.
fn sender(app: &Arc<App>, path: &'static str) -> firewall::SendFn {
    let app = app.clone();
    Arc::new(move |body: Value| {
        let app = app.clone();
        Box::pin(async move {
            let Some(url) = console_route(&app, path) else {
                return Err(firewall::SendError::Failed);
            };
            let r = app
                .console
                .post_json(&url, &body, Duration::from_secs(30))
                .await
                .map_err(|_| firewall::SendError::Failed)?;
            if (200..300).contains(&r.status) {
                return Ok(());
            }
            if (400..500).contains(&r.status)
                && let Some(m) = r.body.get("message").and_then(Value::as_str)
            {
                let replace = r.body.get("replace") == Some(&Value::Bool(true));
                return Err(firewall::SendError::Refused {
                    message: crate::integrations::connectors::firewall::js_slice(m, 300),
                    replace,
                });
            }
            Err(firewall::SendError::Failed)
        })
    })
}

/// `makeRedactor(firewallSecrets())`: what a coding agent reads, masked with what this firewall
/// keeps secret now (read fresh each time, as the stores fill as they load).
fn masked(app: &Arc<App>) -> Arc<dyn Fn(&str) -> String + Send + Sync> {
    let app = app.clone();
    Arc::new(move |text| {
        let secrets = app
            .contracts
            .firewall_secrets
            .get()
            .map(|s| s.values())
            .unwrap_or_default();
        cc_redact::make_redactor(secrets)(text)
    })
}

/// Firewall Doctor's tools: W3's Logs reader and self-update, the root helper, and every answer
/// masked with what this firewall keeps secret now.
fn fw_tools_maker(app: &Arc<App>, helper: String) -> firewall::MakeTools {
    let (a1, a2, a3) = (app.clone(), app.clone(), app.clone());
    let opts = Arc::new(fw_tools::Options {
        logs: Arc::new(move |range, service| {
            let a = a1.clone();
            Box::pin(async move {
                match a.contracts.fw_logs.get() {
                    Some(l) => l.read(range, &service).await,
                    None => Err("This firewall cannot read its logs.".into()),
                }
            })
        }),
        repair: fw_tools::local_repair(helper),
        update: Arc::new(move || {
            let Some(u) = a2.contracts.self_update.get().filter(|u| u.supported()) else {
                return "This firewall was created before in-place updates; it has to be rebuilt instead (Firewall page, then Rebuild).".into();
            };
            if ["resolving", "installing", "running"].contains(&u.phase().as_str()) {
                return "An update is already running. Read it with cc-fwdoctor update-log; it may restart the firewall software and end this session.".into();
            }
            u.apply_for_doctor();
            "The update started. It takes a few minutes. If it restarts the firewall software, this repair session ends; follow it on the Firewall page.".into()
        }),
        redact: masked(&a3),
    });
    Arc::new(move |active| {
        Arc::new(loopback::Listener(fw_tools::listener(opts.clone(), active))) as Arc<dyn firewall::SessionTools>
    })
}

/// A Final check after a template was applied (`tplcheck`): Doctor's runner with read-only tools.
/// Its consent and reports are this firewall's own, and not in its backups.
/// True when Final checks are on.
fn template_checks(
    reg: &mut Registry,
    app: &Arc<App>,
    env: &Env,
    doctor: &Arc<firewall::DoctorFirewall>,
    now: Clock,
) -> bool {
    let path = PathBuf::from(env.get("TPLCHECK_STORE_PATH", tplcheck::TPLCHECK_STORE_PATH));
    let aad = format!("{}:{}:template-checks", app.config.org_id, app.config.box_id);
    let loaded = match cc_crypto::enc_file::load_encrypted_json(&path, &app.box_key, &aad) {
        Ok(None) => None,
        Ok(Some(v)) => match serde_json::from_value::<tplcheck::CheckStore>(v) {
            Ok(s) => Some(s),
            Err(_) => {
                tracing::error!("[tplcheck] Final checks could not start. Check the encrypted store.");
                return false;
            }
        },
        Err(_) => {
            tracing::error!("[tplcheck] Final checks could not start. Check the encrypted store.");
            return false;
        }
    };
    let (a1, a2, a3, a4, a5) = (app.clone(), app.clone(), app.clone(), app.clone(), app.clone());
    let (d1, d2) = (doctor.clone(), doctor.clone());
    let box_key = app.box_key.clone();
    let unavailable = || crate::contracts::AgentError {
        message: "The firewall cannot reach its agents.".into(),
        timed_out: false,
    };
    let checks = tplcheck::TemplateCheck::new(
        app,
        tplcheck::Options {
            agent_of: Arc::new(move |vm| {
                let a = a1.contracts.identities.require().ok()?.agent(vm)?;
                let host = a.hostname.filter(|h| !h.is_empty())?;
                Some((host, a.name))
            }),
            facts: Arc::new(move |vm| {
                let a = a2.clone();
                Box::pin(async move {
                    match a.contracts.agents.get() {
                        Some(c) => c.get(&vm, "/templates/check/facts").await,
                        None => Err(unavailable()),
                    }
                })
            }),
            probe: Arc::new(move |vm, body| {
                let a = a3.clone();
                Box::pin(async move {
                    match a.contracts.agents.get() {
                        Some(c) => c.post(&vm, "/templates/check/probe", body).await,
                        None => Err(unavailable()),
                    }
                })
            }),
            credential_for: Arc::new(move |id| {
                let a = a4.clone();
                Box::pin(async move {
                    match a.contracts.doctor_credential.get() {
                        Some(c) => c.credential(&id).await,
                        None => None,
                    }
                })
            }),
            check: Arc::new(move |input| {
                let d = d1.clone();
                Box::pin(async move { d.check(input).await })
            }),
            annotate: Arc::new(move |id, text| d2.annotate(id, text)),
            redact: masked(&a5),
            save: Arc::new(move |store| {
                let v = serde_json::to_value(store).map_err(|_| "unsaved".to_string())?;
                cc_crypto::enc_file::save_encrypted_json(&path, &v, &box_key, &aad).map_err(|_| "unsaved".to_string())
            }),
            now,
            make_id: None,
            retry_ms: None,
        },
        loaded,
    );
    for action in ["propose", "confirm", "cancel"] {
        let c = checks.clone();
        reg.commands.handle(&format!("tplcheck.{action}"), move |p| {
            let c = c.clone();
            async move { c.handle(action, p).await }
        });
    }
    reg.commands.status(&["template_checks"], move || {
        crate::integrations::as_map(json!({"template_checks": checks.status()}))
    });
    true
}

/// The beat's feature words for Doctor (`index.ts` `features`), on W3's list. The pages' words need
/// the access module ready, as the TS's `access?.ready()`: a page with no way in is not offered.
fn features(app: &Arc<App>, checks: bool, firewall: bool, terminal: bool) {
    let Some(core) = crate::core::core() else { return };
    let page = |app: &Arc<App>| {
        let app = app.clone();
        move || app.contracts.page_access.get().is_some_and(|a| a.origin().is_some())
    };
    if checks {
        core.beat.feature("template_check_v1", || true);
    }
    core.beat.feature("doctor_v1", || true);
    core.beat.feature("template_repair", page(app));
    core.beat.feature("template_capture", page(app));
    core.beat.feature("doctor_chat", page(app));
    core.beat.feature("doctor_start", page(app));
    if firewall {
        core.beat.feature("doctor_firewall_v1", || true);
    }
    if terminal {
        core.beat.feature("doctor_terminal", page(app));
    }
}

struct PublicKey(Arc<key::DoctorKeyStore>);

impl crate::contracts::DoctorPublicKey for PublicKey {
    fn public_key(&self) -> Value {
        self.0.public_key()
    }
}

/// Doctor: the key store always (agents keep the key while the helpers are missing), the sessions
/// where `cc-doctor-run` is installed, and the pages a person uses.
pub fn register(reg: &mut Registry, app: &Arc<App>, env: &Env) {
    let keys_dir = app.keys.clone();
    let keys = match key::DoctorKeyStore::open(
        PathBuf::from(env.get("DOCTOR_KEY_PATH", "/opt/controlclaw/state/doctor.enc")),
        &app.box_key,
        &app.config.org_id,
        &app.config.box_id,
        Arc::new(move |m| key::sign_detached(&keys_dir, m)),
        Arc::new(key::generate_with_ssh_keygen),
    ) {
        Ok(k) => Arc::new(k),
        Err(_) => {
            tracing::error!("[doctor] Doctor could not start. Check its encrypted store and installed helpers.");
            return;
        }
    };
    app.contracts.doctor_public_key.set(Arc::new(PublicKey(keys.clone())));
    // The key goes to every agent of the identity map, and each one's host key comes back.
    let (a, k) = (app.clone(), keys.clone());
    tokio::spawn(async move {
        loop {
            if let Some(client) = a.contracts.agents.get() {
                let ids: Vec<String> = targets(&a, &k).into_iter().map(|t| t.vm_id).collect();
                k.reconcile(&ids, &client).await;
            }
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    });
    let run_helper = env.get("DOCTOR_RUN_HELPER", "/usr/local/bin/cc-doctor-run");
    if !std::path::Path::new(&run_helper).exists() {
        return;
    }
    let now: Clock = Arc::new(js::now_ms);
    let store = match store::DoctorStore::new(
        PathBuf::from(env.get("DOCTOR_TRANSCRIPTS_DIR", "/opt/controlclaw/state/doctor-transcripts")),
        app.box_key.clone(),
        app.config.org_id.clone(),
        app.config.box_id.clone(),
        now.clone(),
    ) {
        Ok(s) => s,
        Err(_) => {
            tracing::error!("[doctor] Doctor could not start. Check its encrypted store and installed helpers.");
            return;
        }
    };
    // Firewall Doctor (doctor-rescue.md, Phase 2): only where the role installed the repair helper
    // and its client.
    let repair_helper = env.get("FW_REPAIR_HELPER", fw_tools::FW_REPAIR_HELPER);
    let reserve = Arc::new(reserve::Reserve::new(
        PathBuf::from(env.get("DOCTOR_RESERVE_PATH", "/opt/controlclaw/state/doctor-reserve")),
        reserve::DOCTOR_RESERVE_BYTES,
    ));
    let fw_client = env.get("FW_DOCTOR_CLIENT", fw_tools::FW_DOCTOR_CLIENT);
    let (h, c) = (repair_helper.clone(), fw_client.clone());
    let fw_installed = move || std::path::Path::new(&h).exists() && std::path::Path::new(&c).exists();
    let firewall_target = fw_installed().then(|| firewall::FirewallTarget {
        vm_id: app.config.box_id.clone(),
        name: "the firewall".into(),
        tools: fw_tools_maker(app, repair_helper.clone()),
        reserve: Some(reserve.clone()),
    });
    let (a2, k2, k3) = (app.clone(), keys.clone(), keys.clone());
    let agents: Arc<dyn Fn() -> Vec<Target> + Send + Sync> = Arc::new(move || targets(&a2, &k2));
    let doctor = firewall::DoctorFirewall::new(
        app,
        firewall::Options {
            store,
            runner: Arc::new(runner::LocalRunner),
            agents: agents.clone(),
            private_key: Arc::new(move || k3.private_key()),
            firewall: firewall_target.clone(),
            upload: uploader(app),
            propose: Some(sender(app, "template-proposal")),
            send_draft: Some(sender(app, "template-capture-draft")),
            now: now.clone(),
            window_ms: None,
            idle_ms: None,
            check_sockets_dir: firewall::CHECK_SOCKETS_DIR.into(),
            gateway_base: None,
        },
    );
    // A restart during a firewall repair forgot that session: give the disk reserve back.
    if std::path::Path::new(&repair_helper).exists() {
        reserve.restore();
    }
    // A daemon restart revokes in-memory consent and its old session units together. The TS awaits
    // this before it takes a command; here every command waits for it.
    let reset: Arc<tokio::sync::OnceCell<()>> = Arc::default();
    let r = reset.clone();
    tokio::spawn(async move {
        r.get_or_init(|| async {
            let _ = runner::LocalRunner.reset().await;
        })
        .await;
    });
    for action in ACTIONS {
        let (d, r) = (doctor.clone(), reset.clone());
        reg.commands.handle(&format!("doctor.{action}"), move |p| {
            let (d, r) = (d.clone(), r.clone());
            async move {
                r.get_or_init(|| async {
                    let _ = runner::LocalRunner.reset().await;
                })
                .await;
                d.handle(action, p).await
            }
        });
    }
    let k4 = keys.clone();
    reg.commands.status(&["doctor_keys"], move || {
        crate::integrations::as_map(json!({"doctor_keys": k4.ready_ids()}))
    });
    let d = doctor.clone();
    tokio::spawn(async move {
        let mut n = 0u64;
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            d.tick().await;
            n += 1;
            if n.is_multiple_of(2) {
                d.flush().await;
            }
        }
    });
    let checks = std::path::Path::new(&env.get("TPLCHECK_CLIENT", tplcheck::TPLCHECK_CLIENT)).exists()
        && template_checks(reg, app, env, &doctor, now.clone());
    let attach = std::path::Path::new(&env.get("DOCTOR_ATTACH_HELPER", "/usr/local/bin/cc-doctor-attach")).exists();
    features(app, checks, firewall_target.is_some(), attach);
    let chat = chat::DoctorChat::new(app, doctor.clone(), now.clone());
    // In every firewall page's sidebar (the TS's `fwShellPages({doctor: !!doctorStart})`), while the
    // console is told `doctor_start`: otherwise the link would end on a notice.
    {
        let app = app.clone();
        crate::core::fw_shell::set_page(crate::core::fw_shell::FwPage::Doctor, move || {
            app.contracts.page_access.get().is_some_and(|a| a.origin().is_some())
        });
    }
    let start = start::DoctorStart::new(
        app,
        doctor.clone(),
        chat.clone(),
        agents,
        {
            // `firewall: () => existsSync(...)`: the helpers are looked for on every request.
            let (box_id, fw_installed) = (app.config.box_id.clone(), fw_installed.clone());
            Arc::new(move || fw_installed().then(|| (box_id.clone(), "the firewall".to_string())))
        },
        // The same `dist-ui/` the pages' stylesheet comes from (next to the binary on a box).
        crate::core::fw_shell::ui_dir().display().to_string(),
        now.clone(),
    );
    reg.ingress.route(
        crate::stages::INGRESS_PAGES,
        |_, p| start::owns(p),
        move |req, _| {
            let s = start.clone();
            async move { s.handle(req).await }
        },
    );
    let c = chat.clone();
    reg.ingress.route(
        crate::stages::INGRESS_PAGES,
        |_, p| p == chat::ROOT || p.starts_with("/__cc/doctor/chat/"),
        move |req, _| {
            let c = c.clone();
            async move { c.handle(req).await }
        },
    );
    if attach {
        let t = terminal::DoctorTerminal::new(app, doctor.clone(), None, now);
        let t2 = t.clone();
        reg.ingress.route(
            crate::stages::INGRESS_PAGES,
            |_, p| terminal::owns(p),
            move |req, _| {
                let t = t.clone();
                async move { t.handle(req).await }
            },
        );
        if let Some(up) = reg.ingress.upgrades_mut() {
            up.route(
                crate::stages::INGRESS_UPGRADE,
                |_, p| p == "/__cc/doctor/ws",
                move |req, _| {
                    let t = t2.clone();
                    async move { t.upgrade(req).await }
                },
            );
        }
    }
}
