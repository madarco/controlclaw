//! Wiring for the org Google account and Drive folders: the stores, the commands, the proxy
//! credentials, the heartbeat reports and the token timers (`index.ts` 929-945, 1085-1110,
//! 2354-2374).

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use serde_json::Value;

use crate::app::{App, Registry};
use crate::channels::agent::AgentCalls;
use crate::channels::drive::{DriveFirewall, DriveOptions};
use crate::channels::google::http::{GoogleHttp, LiveHttp};
use crate::channels::google::{Changed, GoogleFirewall, GoogleOptions, Routes};
use crate::contracts::{CredentialContributor, CredentialOrder};

struct GoogleCredentials(Arc<GoogleFirewall>);

impl CredentialContributor for GoogleCredentials {
    fn order(&self) -> CredentialOrder {
        CredentialOrder::Google
    }
    fn credentials(&self) -> Vec<Value> {
        self.0.credentials()
    }
}

struct DriveCredentials(Arc<DriveFirewall>);

impl CredentialContributor for DriveCredentials {
    fn order(&self) -> CredentialOrder {
        CredentialOrder::Drive
    }
    fn credentials(&self) -> Vec<Value> {
        self.0.credentials()
    }
}

fn env_path(name: &str, default: &str) -> PathBuf {
    PathBuf::from(crate::channels::env_or(name, default))
}

fn env_ms(name: &str, default: u64) -> Duration {
    Duration::from_millis(crate::channels::env_ms(name, default).max(1))
}

/// Builds both; Google and its HTTP client are returned for the email rules' and Gmail push's own
/// reads.
pub fn register(
    reg: &mut Registry,
    app: &Arc<App>,
    agent: Arc<dyn AgentCalls>,
    code_routes: Routes,
    sync: Changed,
) -> (Option<Arc<GoogleFirewall>>, Option<Arc<dyn GoogleHttp>>) {
    let http: Arc<dyn GoogleHttp> = match LiveHttp::new() {
        Ok(h) => Arc::new(h),
        Err(_) => {
            tracing::error!("[google] no HTTP client; Google and Drive disabled");
            return (None, None);
        }
    };
    let google_slot: Arc<OnceLock<Arc<GoogleFirewall>>> = Arc::default();
    let drive_slot: Arc<OnceLock<Arc<DriveFirewall>>> = Arc::default();

    // Drive first, as `index.ts` builds it; it borrows the Google account through a late binding.
    let g = google_slot.clone();
    let drive = DriveFirewall::new(DriveOptions {
        store_path: env_path("DRIVE_STORE_PATH", "/opt/controlclaw/state/drive.enc"),
        box_key: app.box_key.clone(),
        org_id: app.config.org_id.clone(),
        box_id: app.config.box_id.clone(),
        agent: agent.clone(),
        codes: crate::channels::contracts_fill::codes_for(app, "drive", false),
        code_routes: code_routes.clone(),
        google_account: Arc::new(move || g.get().and_then(|g| g.drive_access())),
        on_credentials_changed: Some(sync.clone()),
        http: http.clone(),
        now: Arc::new(crate::channels::now_ms),
        write_check: Default::default(),
    });
    let drive = match drive {
        Ok(d) => {
            let _ = drive_slot.set(d.clone());
            crate::channels::contracts_fill::feature(app, "drive_folders", || true);
            app.contracts.credentials.add(Arc::new(DriveCredentials(d.clone())));
            for action in ["propose", "confirm", "cancel", "push", "read"] {
                let d = d.clone();
                reg.commands.handle(&format!("drive.{action}"), move |p| {
                    let d = d.clone();
                    async move { d.command(action, p).await }
                });
            }
            Some(d)
        }
        Err(e) => {
            tracing::error!("[mitm-agent] drive module would not start, drive commands disabled: {e}");
            None
        }
    };

    // Re-syncing the proxy is not enough for Drive: a borrowed folder has a `connected` flag on its
    // boxes. `on_google_account_changed` compares a fingerprint first, so the hourly refresh that
    // also lands here re-pushes nothing.
    let changed: Changed = {
        let (sync, d) = (sync.clone(), drive_slot.clone());
        Arc::new(move || {
            let (sync, d) = (sync.clone(), d.get().cloned());
            Box::pin(async move {
                sync().await;
                if let Some(d) = d {
                    d.on_google_account_changed().await;
                }
            })
        })
    };
    let google = GoogleFirewall::new(GoogleOptions {
        store_path: env_path("GOOGLE_STORE_PATH", "/opt/controlclaw/state/google.enc"),
        box_key: app.box_key.clone(),
        org_id: app.config.org_id.clone(),
        box_id: app.config.box_id.clone(),
        agent,
        codes: crate::channels::contracts_fill::codes_for(app, "google", false),
        code_routes,
        on_credentials_changed: Some(changed),
        http: http.clone(),
        now: Arc::new(crate::channels::now_ms),
    });
    let google = match google {
        Ok(g) => {
            let _ = google_slot.set(g.clone());
            crate::channels::contracts_fill::feature(app, "google_account", || true);
            app.contracts.credentials.add(Arc::new(GoogleCredentials(g.clone())));
            for action in ["propose", "callback", "confirm", "cancel", "push", "forget", "read"] {
                let g = g.clone();
                reg.commands.handle(&format!("google.{action}"), move |p| {
                    let g = g.clone();
                    async move { g.command(action, p).await }
                });
            }
            Some(g)
        }
        Err(e) => {
            tracing::error!("[mitm-agent] google module would not start, google commands disabled: {e}");
            None
        }
    };

    let (d, g) = (drive.clone(), google.clone());
    reg.commands.reports(move || {
        let mut r = d.as_ref().map(|d| d.drain_reports()).unwrap_or_default();
        r.extend(g.as_ref().map(|g| g.drain_reports()).unwrap_or_default());
        r
    });

    // Two jobs on Drive's timer: its own mints, and a borrowed account that moved with nothing
    // written in between. The first run is at once, as `void tick()` is.
    if let Some(d) = drive {
        let every = env_ms("DRIVE_TOKEN_POLL_MS", 60_000);
        tokio::spawn(async move {
            loop {
                d.refresh_due().await;
                d.on_google_account_changed().await;
                tokio::time::sleep(every).await;
            }
        });
    }
    if let Some(g) = google.clone() {
        let every = env_ms("GOOGLE_TOKEN_POLL_MS", 60_000);
        tokio::spawn(async move {
            loop {
                g.refresh_due().await;
                tokio::time::sleep(every).await;
            }
        });
    }
    (google, Some(http))
}
