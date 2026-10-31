//! The firewall's own pages and its Open flow on the ingress (`index.ts`, the access, Logs page and
//! shell parts): the shared assets first, then the Logs page, then `/__cc/open` and
//! `/__cc/enroll/confirm`; the `access.*` commands; the `access` beat field and the Open features.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use super::Core;
use super::access::{AccessFirewall, AccessOptions, access_request, owns_access_path};
use super::access_store::AccessStoreFile;
use super::fw_logs::{FW_LOGS_HELPER, FwLogsPage, FwLogsReader, owns_fw_logs_path, page_request, page_response};
use super::fw_shell::{FwPage, FwShellState, fw_ui_response, owns_fw_ui_path, pages_now, set_fw_shell, set_page};
use crate::app::Registry;
use crate::stages;

static ACCESS: OnceLock<Arc<AccessFirewall>> = OnceLock::new();

/// The Open module, once `register` built it (W5's Doctor, team chat and logins pages use it).
pub fn access() -> Option<Arc<AccessFirewall>> {
    ACCESS.get().cloned()
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn helper_present() -> bool {
    std::path::Path::new(FW_LOGS_HELPER).exists()
}

/// `firewallSecrets`: every secret value this firewall holds, collected fresh on each read.
pub(super) fn firewall_secrets(core: &Core) -> Vec<String> {
    use cc_crypto::enc_file::{encrypted_secret_values, remember_encrypted_secrets};
    use serde_json::Value;
    let keys = &core.app.config.keys_dir;
    remember_encrypted_secrets(&Value::String(core.app.box_key.clone()), true);
    static WANTED: std::sync::LazyLock<regex::Regex> =
        std::sync::LazyLock::new(|| regex::Regex::new(r"private|secret|token|password|box_key|\.key$").expect("regex"));
    let wanted = &*WANTED;
    let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(keys)
        .map(|d| {
            d.filter_map(|e| e.ok())
                .filter(|e| wanted.is_match(&e.file_name().to_string_lossy()))
                .map(|e| e.path())
                .collect()
        })
        .unwrap_or_default();
    files.push("/opt/controlclaw/mitm/ca/mitmproxy-ca.pem".into());
    files.push(keys.join("recovery_key.pem"));
    files.push(keys.join("vm_private_key.pem"));
    for path in files {
        // A file this daemon cannot read is not in anything it shows either.
        if let Ok(m) = std::fs::metadata(&path)
            && m.is_file()
            && m.len() <= 65_536
            && let Ok(text) = std::fs::read_to_string(&path)
        {
            remember_encrypted_secrets(&Value::String(text), true);
        }
    }
    if let Some(last) = core.sync.last()
        && let Some(c) = last.get("credentials")
    {
        remember_encrypted_secrets(c, false);
    }
    encrypted_secret_values()
}

pub fn register(reg: &mut Registry, core: &Arc<Core>) {
    let app = core.app.clone();
    reg.ingress.route(
        stages::INGRESS_SHELL,
        |_, p| owns_fw_ui_path(p),
        |req, _| async move { fw_ui_response(req.method().as_str(), &cc_http::pathname(req.uri().path())) },
    );
    // The access module runs where the control channel does (`FIREWALL_URL && getToken`), and on
    // a standalone firewall, whose Open links it signs itself (`local_intent`).
    let standalone = app.config.mode.standalone();
    if !standalone && (app.config.firewall_url.is_empty() || !core.uses_http) {
        return;
    }
    let intent_key = if standalone {
        super::local_intent::PUBLIC_FILE
    } else {
        "saas_public_key.pem"
    };
    let path = std::env::var("ACCESS_STORE_PATH").unwrap_or_else(|_| "/opt/controlclaw/state/access.enc".into());
    let keys = app.keys.clone();
    let nonempty = |s: Option<String>| s.filter(|v| !v.is_empty());
    let (k1, k2, k3) = (keys.clone(), keys.clone(), keys.clone());
    let (c1, c2, c3, c4) = (app.clone(), app.clone(), core.clone(), core.clone());
    let access = AccessFirewall::new(AccessOptions {
        store: AccessStoreFile::new(
            std::path::Path::new(&path),
            &app.box_key,
            &app.config.org_id,
            &app.config.box_id,
        ),
        org_id: app.config.org_id.clone(),
        box_id: app.config.box_id.clone(),
        agent: core.agent.clone(),
        consent: crate::contracts::CodeService::module(
            &super::consent::ConsentView(core.consent.clone()),
            super::access::MODULE,
        ),
        code_routes: Arc::new(move || {
            c1.contracts
                .code_route_source
                .get()
                .map(|r| r.routes())
                .unwrap_or_default()
        }),
        channels_ready: Arc::new(move || c2.contracts.code_route_source.get().is_some_and(|r| r.ready())),
        identities: Arc::new(move || c3.agents.browser_boxes()),
        stopped: Arc::new(move |vm: &str| {
            c4.sync
                .hooks
                .kill
                .get()
                .is_some_and(|k| k.locked_vm_ids(&[vm.to_string()]).iter().any(|v| v == vm))
        }),
        hostname: Arc::new(move || nonempty(k1.read("vm_hostname"))),
        saas_public_key: Arc::new(move || nonempty(k2.read(intent_key))),
        signing_key: Arc::new(move || nonempty(k3.read("vm_private_key.pem"))),
        now: Arc::new(now_ms),
    });
    let _ = ACCESS.set(access.clone());
    app.contracts
        .page_access
        .set(Arc::new(super::slots::Pages(access.clone())));
    let a = access.clone();
    core.agents.set_pinned(Arc::new(move |vm: &str| a.pinned_host(vm)));
    let a = access.clone();
    core.agents.on_identities(Arc::new(move |_, _| a.note_pins()));

    let a = access.clone();
    reg.commands.handle("access.revoke", move |p| {
        let a = a.clone();
        async move { a.revoke(p).await }
    });
    let a = access.clone();
    reg.commands.handle("access.revoke_all", move |_| {
        let a = a.clone();
        async move { a.revoke_all().await }
    });
    let a = access.clone();
    reg.commands.status(&["access"], move || {
        let mut m = serde_json::Map::new();
        m.insert("access".into(), a.status());
        m
    });
    for word in ["open_v1", "open_logs", "open_whatsapp", "open_phone"] {
        let a = access.clone();
        core.beat.feature(word, move || a.ready());
    }

    // This firewall's own Logs page.
    let c = core.clone();
    let reader = Arc::new(FwLogsReader::new(
        app.runner.clone(),
        Arc::new(move || firewall_secrets(&c)),
        Arc::new({
            let k = keys.clone();
            move || nonempty(k.read("vm_hostname"))
        }),
    ));
    app.contracts.fw_logs.set(Arc::new(super::slots::Logs(reader.clone())));
    let firewall_url = app.config.firewall_url.clone();
    let console = {
        let u = firewall_url.clone();
        Arc::new(move || {
            u.starts_with("http")
                .then(|| {
                    url::Url::parse(&u)
                        .ok()?
                        .join("/dashboard/firewall")
                        .ok()
                        .map(|x| x.to_string())
                })
                .flatten()
        })
    };
    let page = Arc::new(FwLogsPage::new(
        access.clone(),
        reader,
        console,
        super::fw_shell::ui_asset("app.js"),
        Arc::new(now_ms),
    ));
    let a = access.clone();
    core.beat.feature("open_fw_logs", move || a.ready() && helper_present());
    set_page(FwPage::Logs, helper_present);
    let (k, box_id) = (keys.clone(), app.config.box_id.clone());
    set_fw_shell(Arc::new(move || FwShellState {
        hostname: nonempty(k.read("vm_hostname")),
        console_origin: firewall_url
            .starts_with("http")
            .then(|| {
                url::Url::parse(&firewall_url)
                    .ok()
                    .map(|u| u.origin().ascii_serialization())
            })
            .flatten(),
        firewall_id: box_id.clone(),
        pages: pages_now(),
    }));
    let p = page.clone();
    reg.ingress.route(
        stages::INGRESS_PAGES,
        |_, path| owns_fw_logs_path(path),
        move |req, _| {
            let p = p.clone();
            async move { page_response(p.handle(&page_request(req).await).await) }
        },
    );

    if standalone {
        let (a, cfg) = (access.clone(), app.config.clone());
        reg.ingress.route(
            stages::INGRESS_ACCESS,
            |_, path| super::local_open::owns(path),
            move |req, _| super::local_open::handle(a.clone(), cfg.clone(), req),
        );
    }
    let a = access.clone();
    reg.ingress.route(
        stages::INGRESS_ACCESS,
        |_, path| owns_access_path(path),
        move |req, _| {
            let a = a.clone();
            async move {
                let path = cc_http::pathname(req.uri().path());
                a.handle(&path, access_request(req).await).await.into_response()
            }
        },
    );
}

/// After the first sync: the access tick at once, then every `ACCESS_TICK_MS`.
pub fn start(core: &Arc<Core>) {
    let Some(a) = access() else { return };
    let _ = core;
    let every_ms: u64 = std::env::var("ACCESS_TICK_MS")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(60_000);
    let first = a.clone();
    tokio::spawn(async move { first.tick().await });
    super::every(Duration::from_millis(every_ms), move || {
        let a = a.clone();
        async move { a.tick().await }
    });
}
