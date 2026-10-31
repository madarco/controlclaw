//! `sudo /usr/local/bin/cc-teamchat …` (`teamchat-helper.ts`): the root helper Ansible installs
//! next to ClickClack. Everything privileged about Team chat goes through it: starting and stopping
//! the unit, and the ClickClack admin CLI, which has to run as the `clickclack` account against its
//! own data directory. It answers one line of JSON.

use std::sync::Arc;
use std::time::Duration;

use cc_http::BoxFuture;
use cc_proc::{Cmd, Runner};
use serde_json::{Map, Value};

pub const TEAMCHAT_HELPER: &str = "/usr/local/bin/cc-teamchat";

pub trait TeamChatHelper: Send + Sync {
    /// Whether the helper is installed at all (a firewall built before Team chat has none).
    fn installed(&self) -> bool;
    fn start(&self, hostname: String, home_url: String) -> BoxFuture<Result<(), String>>;
    fn stop(&self) -> BoxFuture<Result<(), String>>;
    fn status(&self) -> BoxFuture<Result<String, String>>;
    /// Create the system owner, the workspace and #general once, and mint a single-use magic link
    /// for that owner: `(owner, token)`.
    fn bootstrap(&self) -> BoxFuture<Result<(String, String), String>>;
    /// Make sure the person is a workspace member and mint a single-use magic link: `(user, token)`.
    fn login(&self, workspace_id: String, email: String, name: String) -> BoxFuture<Result<(String, String), String>>;
}

#[derive(Clone)]
pub struct SudoHelper {
    pub path: String,
    pub runner: Arc<dyn Runner>,
}

impl SudoHelper {
    /// `execFile("sudo", ["-n", path, ...args])`, the last line of stdout read as JSON. An answer
    /// with `ok: true` is a success whatever the exit code, as in the TS.
    async fn run(&self, args: Vec<String>, timeout: Duration) -> Result<Map<String, Value>, String> {
        let what = args.first().cloned().unwrap_or_default();
        let line = std::iter::once("sudo -n".to_string())
            .chain(std::iter::once(self.path.clone()))
            .chain(args.iter().cloned())
            .collect::<Vec<_>>()
            .join(" ");
        let out = self.runner.run(Cmd::sudo(&self.path).args(args).timeout(timeout)).await;
        let (stdout, failed) = match &out {
            Ok(o) => (
                o.stdout_str(),
                (!o.success()).then(|| format!("Command failed: {line}")),
            ),
            Err(_) => (String::new(), Some("spawn sudo ENOENT".to_string())),
        };
        let last = stdout.trim().split('\n').next_back().unwrap_or("").to_string();
        let parsed = serde_json::from_str::<Value>(if last.is_empty() { "null" } else { &last })
            .ok()
            .and_then(|v| v.as_object().cloned());
        if let Some(p) = &parsed
            && p.get("ok") == Some(&Value::Bool(true))
        {
            return Ok(p.clone());
        }
        let why = parsed
            .as_ref()
            .and_then(|p| p.get("error").and_then(Value::as_str).map(String::from))
            .or(failed)
            .unwrap_or_else(|| "no answer".into());
        Err(format!("cc-teamchat {what}: {why}"))
    }
}

const LONG: Duration = Duration::from_secs(90);

fn text(o: &Map<String, Value>, k: &str) -> Option<String> {
    o.get(k).and_then(Value::as_str).map(String::from)
}

impl TeamChatHelper for SudoHelper {
    fn installed(&self) -> bool {
        std::path::Path::new(&self.path).exists()
    }

    fn start(&self, hostname: String, home_url: String) -> BoxFuture<Result<(), String>> {
        let me = self.clone();
        Box::pin(async move { me.run(vec!["start".into(), hostname, home_url], LONG).await.map(|_| ()) })
    }

    fn stop(&self) -> BoxFuture<Result<(), String>> {
        let me = self.clone();
        Box::pin(async move { me.run(vec!["stop".into()], LONG).await.map(|_| ()) })
    }

    fn status(&self) -> BoxFuture<Result<String, String>> {
        let me = self.clone();
        Box::pin(async move {
            let o = me.run(vec!["status".into()], Duration::from_secs(20)).await?;
            // `String(state ?? "unknown")`.
            Ok(match o.get("state") {
                None | Some(Value::Null) => "unknown".into(),
                Some(Value::String(s)) => s.clone(),
                Some(v) => crate::integrations::js::stringify(v),
            })
        })
    }

    fn bootstrap(&self) -> BoxFuture<Result<(String, String), String>> {
        let me = self.clone();
        Box::pin(async move {
            let o = me.run(vec!["bootstrap".into()], LONG).await?;
            match (text(&o, "owner"), text(&o, "token")) {
                (Some(owner), Some(token)) => Ok((owner, token)),
                _ => Err("cc-teamchat bootstrap: no owner".into()),
            }
        })
    }

    fn login(&self, workspace_id: String, email: String, name: String) -> BoxFuture<Result<(String, String), String>> {
        let me = self.clone();
        Box::pin(async move {
            let o = me.run(vec!["login".into(), workspace_id, email, name], LONG).await?;
            match (text(&o, "user"), text(&o, "token")) {
                (Some(user), Some(token)) => Ok((user, token)),
                _ => Err("cc-teamchat login: no token".into()),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cc_proc::{RecordingRunner, exit, ok};

    #[tokio::test]
    async fn the_helper_runs_under_sudo_and_reads_its_last_line() {
        let r = RecordingRunner::new();
        r.answer(
            &["sudo", "-n", "/h", "status"],
            ok("starting\n{\"ok\":true,\"state\":\"active\"}\n"),
        );
        r.answer(
            &["sudo", "-n", "/h", "bootstrap"],
            exit(1, "{\"ok\":false,\"error\":\"no workspace\"}"),
        );
        r.answer(&["sudo", "-n", "/h", "stop"], exit(1, ""));
        let h = SudoHelper {
            path: "/h".into(),
            runner: Arc::new(r.clone()),
        };
        assert_eq!(h.status().await, Ok("active".into()));
        assert_eq!(h.bootstrap().await, Err("cc-teamchat bootstrap: no workspace".into()));
        assert_eq!(
            h.stop().await,
            Err("cc-teamchat stop: Command failed: sudo -n /h stop".into())
        );
        assert_eq!(
            h.login("w".into(), "e".into(), "n".into()).await,
            Err("cc-teamchat login: spawn sudo ENOENT".into())
        );
        assert_eq!(r.calls()[0].args, ["-n", "/h", "status"]);
    }
}
