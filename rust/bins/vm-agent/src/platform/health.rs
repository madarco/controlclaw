//! `GET /health` (`packages/vm-agent/src/routes/health.ts`): the services the box runs and how long
//! the agent has been up. No process list: it named every command line on the box.

use std::sync::Arc;

use cc_http::{Router, json};
use cc_proc::{Cmd, Runner};
use hyper::Method;
use serde_json::{Map, Value};

use crate::app::App;
use crate::stages;

const SERVICES: &[&str] = &["docker", "tailscaled", "browser-stream", "openclaw"];

/// `getServiceStatus`: `running` when `systemctl is-active` says `active`; else `stopped` when the
/// unit file exists, `not-installed` when it does not.
pub async fn service_status(runner: &dyn Runner, service: &str) -> &'static str {
    let t = std::time::Duration::from_secs(5);
    match runner
        .run(Cmd::new("systemctl").args(["is-active", service]).timeout(t))
        .await
    {
        Ok(out) if out.success() => {
            if out.stdout_str().trim() == "active" {
                "running"
            } else {
                "stopped"
            }
        }
        _ => match runner
            .run(Cmd::new("systemctl").args(["cat", service]).timeout(t))
            .await
        {
            Ok(out) if out.success() => "stopped",
            _ => "not-installed",
        },
    }
}

pub fn register(router: &mut Router, app: &Arc<App>) {
    let app = app.clone();
    router.exact(stages::CONSOLE, Method::GET, "/health", move |_, _| {
        let app = app.clone();
        async move {
            // At once rather than one after another: each check can take its 5 s timeout twice.
            let checks = SERVICES.iter().map(|s| service_status(app.runner.as_ref(), s));
            let states = futures_util::future::join_all(checks).await;
            let mut services = Map::new();
            for (s, state) in SERVICES.iter().zip(states) {
                services.insert((*s).to_string(), Value::from(state));
            }
            json(
                200,
                &serde_json::json!({
                    "status": "ok",
                    "uptime": app.started.elapsed().as_secs_f64(),
                    "services": services,
                }),
            )
        }
    });
}
