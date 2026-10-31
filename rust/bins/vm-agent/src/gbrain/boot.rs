//! The brain box's first boot (`gbrain.ts`, after `server.listen`): the steps an agent has, in the
//! same order and for the same reasons, and nothing about OpenClaw (there is none here). Unlike the
//! TS (and, for now, the agent's bootstrap), a failed step is tried again (`secure`). Every
//! step runs while egress is still open, and reporting ready is what makes the control plane lock
//! the box's egress to the firewall. So the CA has to be trusted and the redirect on before that,
//! or the brain would be sealed with no way out.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Map, json};

use crate::app::App;
use crate::contracts::BoxSetup;

/// How long the first boot waits before trying a failed step again: doubling up to `RETRY_MAX`.
const RETRY: Duration = Duration::from_secs(60);
const RETRY_MAX: Duration = Duration::from_secs(30 * 60);

/// One CA install at a time: the first boot's and the console's `/mitm-ca/refresh` both write the
/// CA file and run `cc-install-ca`.
pub(crate) static CA: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Keypair, its registration, the firewall's CA, the egress redirect, then ready.
pub async fn run(app: Arc<App>) {
    if cc_auth::keys::ensure_vm_keypair(&app.config.keys_dir).is_none() {
        tracing::warn!("[keys] could not make or read the vm keypair");
    }
    crate::platform::keys::register_public_key(&app).await;
    // W7's box-side steps, set by the brain's router (`register_box_routes`). Without them there
    // is no CA and no redirect, so no ready report either: the box stays initializing.
    let Some(steps) = app.contracts.box_setup.get() else {
        tracing::error!("[bootstrap] no box setup — skipping ready report (box stays initializing)");
        return;
    };
    let keys = app.keys.clone();
    let marker = move || keys.read("mitm_box_private_ip").is_some_and(|v| !v.is_empty());
    let behind_firewall = secure(steps.as_ref(), &marker, RETRY).await;
    // Said out loud, because the control plane locks a brain's egress to the firewall only on this
    // word. Only with the firewall marker: without it the redirect step succeeds having done nothing
    // (a brain built before its Ansible wired the redirect), and locking that one would cut it off.
    let mut extra = Map::new();
    if behind_firewall {
        extra.insert("egress".into(), json!(true));
    }
    let a = app.clone();
    crate::platform::report_ready(&app, extra, move || crate::platform::box_software(&a, None)).await;
}

/// The firewall's CA, then the egress redirect, each tried again until it works, the pause
/// doubling from `pause` to `RETRY_MAX`. Rust only: the TS gave up after one failure and left the
/// brain initializing until its service restarted (a firewall that came up late, one failed
/// `cc-enable-egress`). The answer is whether the box is behind the firewall, read just before the
/// egress step that worked: a marker Ansible writes after that read means no lock this time (the
/// box stays reachable), never a lock with no redirect behind it.
pub(crate) async fn secure(steps: &dyn BoxSetup, marker: &(dyn Fn() -> bool + Sync), pause: Duration) -> bool {
    let mut wait = pause;
    loop {
        let installed = {
            let _one = CA.lock().await;
            steps.install_ca().await
        };
        if installed {
            break;
        }
        tracing::error!(
            "[bootstrap] mitm CA not installed — trying again in {}s (box stays initializing)",
            wait.as_secs()
        );
        tokio::time::sleep(wait).await;
        wait = (wait * 2).min(RETRY_MAX);
    }
    let mut wait = pause;
    loop {
        let behind = marker();
        if steps.enable_egress().await {
            return behind;
        }
        tracing::error!(
            "[bootstrap] transparent egress not active — trying again in {}s (box stays initializing)",
            wait.as_secs()
        );
        tokio::time::sleep(wait).await;
        wait = (wait * 2).min(RETRY_MAX);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use cc_http::BoxFuture;

    use super::*;

    /// Fails the CA `ca` times and the redirect `egress` times, counting every call.
    #[derive(Default)]
    struct Flaky {
        ca: AtomicUsize,
        egress: AtomicUsize,
        calls: std::sync::Mutex<Vec<&'static str>>,
    }

    impl BoxSetup for Flaky {
        fn report_handle_certificate(&self) {}
        fn install_ca(&self) -> BoxFuture<bool> {
            self.calls.lock().expect("calls").push("ca");
            let ok = self.ca.fetch_sub(1, Ordering::SeqCst) == 0;
            if ok {
                self.ca.store(0, Ordering::SeqCst);
            }
            Box::pin(async move { ok })
        }
        fn trust_ca_in_process(&self) -> bool {
            true
        }
        fn enable_egress(&self) -> BoxFuture<bool> {
            self.calls.lock().expect("calls").push("egress");
            let ok = self.egress.fetch_sub(1, Ordering::SeqCst) == 0;
            if ok {
                self.egress.store(0, Ordering::SeqCst);
            }
            Box::pin(async move { ok })
        }
        fn own_certificate(&self, _: String, _: Duration) -> BoxFuture<bool> {
            Box::pin(async { true })
        }
        fn ssh_reading(&self) -> Option<serde_json::Value> {
            None
        }
        fn drive_summary(&self) -> Option<serde_json::Value> {
            None
        }
    }

    #[tokio::test]
    async fn a_failed_step_is_tried_again_and_the_ca_comes_first() {
        let f = Flaky::default();
        f.ca.store(2, Ordering::SeqCst);
        f.egress.store(1, Ordering::SeqCst);
        // The marker appears between the two egress tries: the one read before the try that worked
        // is the answer.
        let reads = AtomicUsize::new(0);
        let marker = || reads.fetch_add(1, Ordering::SeqCst) >= 1;
        assert!(secure(&f, &marker, Duration::ZERO).await);
        assert_eq!(*f.calls.lock().expect("calls"), ["ca", "ca", "ca", "egress", "egress"]);
        let f = Flaky::default();
        assert!(!secure(&f, &|| false, Duration::ZERO).await);
    }
}
