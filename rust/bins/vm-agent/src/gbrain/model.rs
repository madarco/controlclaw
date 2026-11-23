//! The brain's model (T-217, apps/saas/docs/features/brain.md): the model GBrain uses for its own
//! calls, the nightly run and query expansion, picked by the owner on the Brain page.
//!
//! `POST /brain/model {model}` behind the console's token. A setting of cost, not of access: the
//! firewall's allow-list for the brain already takes both models, and the key stays the firewall's.
//! The vm-agent cannot run GBrain's CLI (its env file is GBrain's account's), so a root helper,
//! `cc-gbrain-model` (gbrain.yml), takes the name as its only argument, sets GBrain's tiers, keeps
//! the choice for the role's next run and restarts GBrain when it changed.

use std::sync::Arc;
use std::time::Duration;

use cc_http::{BodyBinding, Router, send_json};
use cc_proc::Runner;
use hyper::Method;
use serde_json::{Map, Value, json};

use super::run_helper;
use crate::app::App;
use crate::stages;

/// The models the owner can pick, the first being the default (`gbrain_models` in the role, and
/// `BRAIN_CHAT_MODELS` in the console).
pub const MODELS: &[&str] = &["gpt-5.6-luna", "gpt-5.6-terra"];
const HELPER: &str = "/usr/local/bin/cc-gbrain-model";
/// Five `gbrain config set` and a restart.
const HELPER_TIMEOUT: Duration = Duration::from_secs(90);

/// The model asked for, or the 400's message.
pub fn parse(body: Option<&Map<String, Value>>) -> Result<&'static str, &'static str> {
    let asked = body.and_then(|b| b.get("model")).and_then(Value::as_str);
    MODELS
        .iter()
        .copied()
        .find(|m| Some(*m) == asked)
        .ok_or("model must be gpt-5.6-luna or gpt-5.6-terra")
}

/// Hand the model to the helper; whether it changed.
pub async fn apply(model: &str, runner: &dyn Runner) -> Result<bool, String> {
    let cmd = super::helper(HELPER).arg(model).timeout(HELPER_TIMEOUT);
    run_helper(runner, cmd)
        .await
        .map(|out| out.trim() == "changed")
        .map_err(|e| format!("could not set the brain's model: {e}"))
}

pub fn register(router: &mut Router, app: &Arc<App>) {
    let app = app.clone();
    router.exact(stages::CONSOLE, Method::POST, "/brain/model", move |req, _| {
        let app = app.clone();
        async move {
            let (_, body) = req.into_parts();
            let body = cc_http::read_json_body(body, 1024, &BodyBinding::not_firewall()).await;
            let model = match parse(body.as_ref()) {
                Ok(m) => m,
                Err(e) => return send_json(400, &json!({"ok": false, "error": e})),
            };
            match apply(model, app.runner.as_ref()).await {
                Ok(changed) => {
                    tracing::info!("[gbrain] model {model}{}", if changed { "" } else { " (unchanged)" });
                    send_json(200, &json!({"ok": true, "model": model, "changed": changed}))
                }
                Err(e) => {
                    tracing::error!("[gbrain] {e}");
                    send_json(500, &json!({"ok": false, "error": "The brain did not take the model. It may be starting; try again in a minute."}))
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use cc_proc::RecordingRunner;

    use super::*;

    #[test]
    fn only_the_two_models() {
        let b = |v: Value| v.as_object().cloned();
        assert_eq!(
            parse(b(json!({"model": "gpt-5.6-terra"})).as_ref()),
            Ok("gpt-5.6-terra")
        );
        assert_eq!(parse(b(json!({"model": "gpt-5.6-luna"})).as_ref()), Ok("gpt-5.6-luna"));
        for m in [
            json!("gpt-6.1-sol"),
            json!("gpt-5.6-luna; rm -rf /"),
            json!(1),
            json!(null),
        ] {
            assert!(parse(b(json!({"model": m})).as_ref()).is_err());
        }
        assert!(parse(None).is_err());
    }

    #[tokio::test]
    async fn the_helper_gets_the_name_as_its_only_argument() {
        let runner = RecordingRunner::new();
        runner.answer(&["sudo"], cc_proc::ok("changed\n"));
        assert_eq!(apply("gpt-5.6-terra", &runner).await, Ok(true));
        let calls = runner.calls();
        assert_eq!(calls[0].program, "sudo");
        assert_eq!(calls[0].args, vec![HELPER.to_string(), "gpt-5.6-terra".to_string()]);
    }
}
