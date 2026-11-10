//! Credential writes with OpenClaw's gateway stopped ([`crate::platform::common::OfflineRun`]),
//! the way it runs here. A container's CLI is reached through `docker exec`, which a stopped
//! container does not take: the write runs in a container of its own instead, with the stopped
//! one's image, mounts, user, work dir and environment, and no network.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use cc_proc::{Cmd, Runner};
use serde_json::Value;

use super::discover::Runs;
use super::{Unmanaged, after_act, supervisor};
use crate::app::App;
use crate::platform::common::{CliWrite, Deps, Offline, exec_failure_line, spawn_message};

const INSPECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Stop, write, start, in one unit action. Refused before anything is stopped when the gateway
/// could not be started again (one started by hand), or when a container's writes would not last.
pub async fn offline_writes(
    app: &Arc<App>,
    um: &Arc<Unmanaged>,
    deps: &Deps,
    bin: &str,
    writes: Vec<CliWrite>,
) -> Result<Offline, String> {
    let install = um.install();
    let runner = app.runner.as_ref();
    supervisor::action_cmd(&install, "start").map_err(|e| {
        format!("OpenClaw saves this only with its gateway stopped, and it could not be started again: {e}")
    })?;
    let like = match &install.runs {
        Runs::Docker { container } => Some((
            container.clone(),
            like(runner, container, install.container_state_dir.as_deref()).await?,
        )),
        _ => None,
    };
    let outcome = {
        let _one = crate::platform::UNIT_ACTIONS.lock().await;
        match supervisor::act(runner, &install, "stop").await {
            Err(e) => {
                // It may be stopping still: it is started again either way.
                let _ = supervisor::act(runner, &install, "start").await;
                Err(format!("OpenClaw did not stop to save it: {e}"))
            }
            Ok(()) => {
                let mut results = Vec::new();
                for w in &writes {
                    results.push(match &like {
                        Some((container, like)) => docker_write(runner, &um.state_dir, container, like, w).await,
                        None => {
                            let args: Vec<&str> = w.args.iter().map(String::as_str).collect();
                            deps.exec(bin, &args, w.timeout, w.stdin.clone(), &[]).await
                        }
                    });
                }
                let started = supervisor::act(runner, &install, "start").await;
                Ok(Offline { results, started })
            }
        }
    };
    after_act(app, um, "start");
    outcome
}

/// What a container like `container` needs, read before it is stopped. Refused when OpenClaw's
/// state is not on a mount: a write in another container would be lost with it.
async fn like(runner: &dyn Runner, container: &str, state_dir: Option<&str>) -> Result<Like, String> {
    let inspect = Cmd::new("docker")
        .args(["inspect", "--format", "{{json .}}", "--", container])
        .timeout(INSPECT_TIMEOUT);
    let seen = match runner.run(inspect).await {
        Ok(o) if o.success() => serde_json::from_str::<Value>(o.stdout_str().trim()).ok(),
        _ => None,
    };
    let like = seen
        .as_ref()
        .and_then(Like::of)
        .ok_or_else(|| format!("Could not read the container {container}"))?;
    match state_dir {
        Some(dir) if like.mounted(dir) => Ok(like),
        _ => Err(format!(
            "OpenClaw saves this only with its gateway stopped, and its state in the container {container} is not on a volume, so it could not be written from outside"
        )),
    }
}

/// One write in a container of its own, like the stopped `container`.
async fn docker_write(
    runner: &dyn Runner,
    state_dir: &Path,
    container: &str,
    like: &Like,
    w: &CliWrite,
) -> Result<String, String> {
    // The environment through a file of this agent's own: it may hold the gateway's token.
    let env_file = state_dir.join(".offline-write.env");
    cc_store::write_atomic(
        &env_file,
        like.env_file().as_bytes(),
        0o600,
        cc_store::TmpName::HiddenPrefix,
    )
    .map_err(|e| format!("Could not write the container's environment: {e}"))?;
    let cmd = Cmd::new("docker")
        .args(like.run_args(container, &env_file, &w.args))
        .timeout(w.timeout)
        .stdin(w.stdin.clone().unwrap_or_default());
    let result = runner.run(cmd).await;
    let _ = std::fs::remove_file(&env_file);
    match result {
        Ok(o) if o.success() => Ok(o.stdout_str()),
        Ok(o) => Err(exec_failure_line(
            &o.stderr_str(),
            &o.stdout_str(),
            "Command failed: docker run",
        )),
        Err(e) => Err(spawn_message("docker", &e)),
    }
}

/// What a container like another needs: `docker inspect`'s image id and config.
#[derive(Debug, PartialEq)]
struct Like {
    image: String,
    user: String,
    work_dir: String,
    env: Vec<String>,
    /// Where its mounts are, inside it.
    mounts: Vec<String>,
}

impl Like {
    fn of(v: &Value) -> Option<Self> {
        let config = v.get("Config")?;
        let s = |x: Option<&Value>| x.and_then(Value::as_str).unwrap_or_default().to_string();
        let image = s(v.get("Image"));
        if image.is_empty() {
            return None;
        }
        Some(Self {
            image,
            user: s(config.get("User")),
            work_dir: s(config.get("WorkingDir")),
            env: config
                .get("Env")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                // An env file holds one line a variable.
                .filter(|e| !e.contains('\n') && e.contains('='))
                .map(str::to_string)
                .collect(),
            mounts: v
                .get("Mounts")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|m| m.get("Destination").and_then(Value::as_str))
                .map(str::to_string)
                .collect(),
        })
    }

    /// Whether `dir` is on one of its mounts.
    fn mounted(&self, dir: &str) -> bool {
        let dir = Path::new(dir);
        self.mounts.iter().any(|m| dir.starts_with(m))
    }

    fn env_file(&self) -> String {
        self.env.iter().map(|e| format!("{e}\n")).collect()
    }

    /// `docker run` for the image's documented entry (`node dist/index.js`, as the wrapper).
    fn run_args(&self, container: &str, env_file: &Path, args: &[String]) -> Vec<String> {
        let mut a: Vec<String> = ["run", "--rm", "-i", "--network", "none", "--volumes-from", container]
            .map(String::from)
            .to_vec();
        a.extend(["--env-file".into(), env_file.to_string_lossy().into_owned()]);
        if !self.user.is_empty() {
            a.extend(["--user".into(), self.user.clone()]);
        }
        if !self.work_dir.is_empty() {
            a.extend(["--workdir".into(), self.work_dir.clone()]);
        }
        a.extend([
            "--entrypoint".into(),
            "node".into(),
            "--".into(),
            self.image.clone(),
            "dist/index.js".into(),
        ]);
        a.extend(args.iter().cloned());
        a
    }
}

#[cfg(test)]
mod tests {
    use cc_proc::{RecordingRunner, ok};
    use serde_json::json;

    use super::*;

    fn write() -> CliWrite {
        CliWrite {
            args: [
                "models",
                "auth",
                "paste-api-key",
                "--provider",
                "openai",
                "--profile-id",
                "openai:controlclaw",
            ]
            .map(String::from)
            .to_vec(),
            stdin: Some("sk-cc-1\n".into()),
            timeout: Duration::from_secs(45),
        }
    }

    #[tokio::test]
    async fn a_write_runs_like_the_stopped_container_with_no_network_and_the_key_on_stdin() {
        let dir = tempfile::tempdir().expect("dir");
        let r = RecordingRunner::new();
        r.answer_with(|c| {
            Some(if c.args.first().map(String::as_str) == Some("inspect") {
                ok(&json!({"Image": "sha256:abc", "Mounts": [{"Destination": "/home/node/.openclaw"}], "Config": {"User": "node", "WorkingDir": "/app", "Env": ["HOME=/home/node", "OPENCLAW_GATEWAY_TOKEN=t0k", "BAD=a\nb"]}}).to_string())
            } else {
                ok("Auth profile: openai:controlclaw (openai/api_key)\n")
            })
        });
        let like = like(&r, "oc", Some("/home/node/.openclaw/state"))
            .await
            .expect("on a volume");
        let out = docker_write(&r, dir.path(), "oc", &like, &write())
            .await
            .expect("written");
        assert!(out.contains("openai:controlclaw"));
        let calls = r.calls();
        let run = &calls[1];
        let env_file = dir.path().join(".offline-write.env").to_string_lossy().into_owned();
        assert_eq!(
            run.args,
            [
                "run",
                "--rm",
                "-i",
                "--network",
                "none",
                "--volumes-from",
                "oc",
                "--env-file",
                &env_file,
                "--user",
                "node",
                "--workdir",
                "/app",
                "--entrypoint",
                "node",
                "--",
                "sha256:abc",
                "dist/index.js",
                "models",
                "auth",
                "paste-api-key",
                "--provider",
                "openai",
                "--profile-id",
                "openai:controlclaw",
            ]
        );
        assert_eq!(run.stdin.as_deref(), Some(b"sk-cc-1\n".as_slice()));
        assert!(
            !run.args.iter().any(|a| a.contains("t0k")),
            "the token is not on the command line"
        );
        assert!(!Path::new(&env_file).exists(), "the env file is removed");
    }

    #[tokio::test]
    async fn a_container_whose_state_is_not_on_a_volume_is_refused_before_anything_is_stopped() {
        let r = RecordingRunner::new();
        r.answer_with(|_| {
            Some(ok(
                &json!({"Image": "i", "Mounts": [{"Destination": "/data"}], "Config": {}}).to_string(),
            ))
        });
        let e = like(&r, "oc", Some("/home/node/.openclaw")).await.expect_err("refused");
        assert!(e.contains("not on a volume"), "{e}");
        assert!(like(&r, "oc", None).await.is_err(), "unknown state folder: refused too");
        assert!(like(&r, "oc", Some("/data/.openclaw")).await.is_ok());
    }

    #[test]
    fn the_env_file_keeps_one_line_variables_only() {
        let like = Like::of(&json!({"Image": "i", "Config": {"Env": ["A=1", "B=x\ny", "C"]}})).expect("like");
        assert_eq!(like.env_file(), "A=1\n");
        assert!(Like::of(&json!({"Config": {}})).is_none(), "no image: nothing to run");
    }
}
