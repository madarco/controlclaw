//! 1Password as a source of website logins (`logins-1password.ts`). An owner gives the firewall a
//! 1Password service account token, scoped in 1Password to the vaults it was given. The firewall
//! runs the official `op` CLI with it (installed by Ansible) to list those vaults' logins and read
//! them. The token goes in the child's environment only, never on its command line.

use std::sync::{Arc, LazyLock};
use std::time::Duration;

use regex::Regex;
use serde_json::Value;

use cc_proc::{Cmd, Runner};

const OP_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, PartialEq)]
pub struct OpVault {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpItem {
    pub item_id: String,
    pub vault_id: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpLogin {
    pub item_id: String,
    pub vault_id: String,
    pub title: String,
    pub urls: Vec<String>,
    pub username: String,
    pub password: String,
    /// The OTP field's `otpauth://` link, when the item has one.
    pub totp: Option<String>,
}

/// What `op` said, cut to something that can be shown: never the token, never a long dump.
pub fn op_failure(stderr: &str) -> String {
    static PREFIX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\[ERROR\] \S+ \S+ ").expect("pattern"));
    static TOKEN: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?i)DecodeSACredentials|illegal base64|seed length|Unauthorized|invalid.*token|401")
            .expect("pattern")
    });
    static RATE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)rate limit|429").expect("pattern"));
    static VAULT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)isn't a vault|not found|403").expect("pattern"));
    let line = stderr
        .split('\n')
        .map(|l| PREFIX.replace(l, "").trim().to_string())
        .find(|l| !l.is_empty() && !l.starts_with("Using configuration"))
        .unwrap_or_default();
    if TOKEN.is_match(&line) {
        return "1Password did not accept that token. Paste a service account token (it starts with ops_).".into();
    }
    if RATE.is_match(&line) {
        return "1Password is limiting how often this token can be used. Try again in a few minutes.".into();
    }
    if VAULT.is_match(&line) {
        return "The token cannot open that vault. Give the service account access to it in 1Password.".into();
    }
    "1Password did not answer. Try again in a minute.".into()
}

const UNREADABLE: &str = "1Password answered something this firewall could not read.";

fn parse(text: &str) -> Result<Value, String> {
    serde_json::from_str(text).map_err(|_| UNREADABLE.to_string())
}

/// A list `op` printed. Anything else is a failed read (the TS's `.filter` throws on it), never an
/// empty vault: a sync that read nothing would take every login of that vault away.
fn list(text: &str) -> Result<Vec<Value>, String> {
    match parse(text)? {
        Value::Array(a) => Ok(a),
        _ => Err(UNREADABLE.to_string()),
    }
}

#[derive(Clone)]
pub struct OnePassword {
    runner: Arc<dyn Runner>,
    bin: String,
    config_dir: String,
}

impl OnePassword {
    pub fn new(runner: Arc<dyn Runner>) -> Self {
        Self {
            runner,
            bin: std::env::var("OP_BIN").unwrap_or_else(|_| "/usr/local/bin/op".into()),
            config_dir: std::env::var("OP_CONFIG_DIR").unwrap_or_else(|_| "/opt/controlclaw/state/op".into()),
        }
    }

    /// `op <args>` with the token in its environment; stdout, or a sentence.
    async fn run(&self, args: &[&str], token: &str) -> Result<String, String> {
        {
            use std::os::unix::fs::DirBuilderExt;
            let _ = std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&self.config_dir);
        }
        // Only what op needs: the token, a config directory of its own, no cache on disk.
        let mut cmd = Cmd::new(&self.bin)
            .args(args.iter().copied())
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .env("HOME", &self.config_dir)
            .env("OP_CONFIG_DIR", &self.config_dir)
            .env("OP_CACHE", "false")
            .env("OP_SERVICE_ACCOUNT_TOKEN", token)
            .timeout(OP_TIMEOUT);
        cmd.clear_env = true;
        let out = self.runner.run(cmd).await.map_err(|_| op_failure(""))?;
        if !out.success() {
            return Err(op_failure(&out.stderr_str()));
        }
        Ok(out.stdout_str())
    }

    pub async fn vaults(&self, token: &str) -> Result<Vec<OpVault>, String> {
        let v = list(&self.run(&["vault", "list", "--format", "json"], token).await?)?;
        Ok(v.iter()
            .filter_map(|x| {
                Some(OpVault {
                    id: x.get("id")?.as_str()?.into(),
                    name: x.get("name")?.as_str()?.into(),
                })
            })
            .collect())
    }

    /// The login items in a vault: ids and when each last changed. One call, no secrets.
    pub async fn list(&self, token: &str, vault_id: &str) -> Result<Vec<OpItem>, String> {
        let v = list(
            &self
                .run(
                    &[
                        "item",
                        "list",
                        "--vault",
                        vault_id,
                        "--categories",
                        "Login",
                        "--format",
                        "json",
                    ],
                    token,
                )
                .await?,
        )?;
        Ok(v.iter()
            .filter_map(|x| {
                Some(OpItem {
                    item_id: x.get("id")?.as_str()?.into(),
                    vault_id: vault_id.into(),
                    updated_at: x.get("updated_at").and_then(Value::as_str).unwrap_or("").into(),
                })
            })
            .collect())
    }

    /// One login item with its secrets.
    pub async fn get(&self, token: &str, vault_id: &str, item_id: &str) -> Result<OpLogin, String> {
        let item = parse(
            &self
                .run(
                    &[
                        "item", "get", item_id, "--vault", vault_id, "--format", "json", "--reveal",
                    ],
                    token,
                )
                .await?,
        )?;
        // Only an item is an item: `null` or a list would read as a login with no password and no
        // address, and the sync would take the real one away. (The TS's `null.fields` throws, so
        // its `null` fails too; a list it reads as an empty login.)
        if !item.is_object() {
            return Err(UNREADABLE.to_string());
        }
        let fields: Vec<Value> = item
            .get("fields")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let field = |k: &str, v: &str| {
            fields
                .iter()
                .find(|f| f.get(k).and_then(Value::as_str) == Some(v))
                .and_then(|f| f.get("value").and_then(Value::as_str))
                .map(str::to_string)
        };
        let mut urls: Vec<(bool, String)> = item
            .get("urls")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .map(|u| {
                (
                    u.get("primary").and_then(Value::as_bool).unwrap_or(false),
                    u.get("href").and_then(Value::as_str).unwrap_or("").to_string(),
                )
            })
            .collect();
        // The primary first, the others as they were (a stable sort).
        urls.sort_by_key(|(p, _)| !p);
        let title = crate::integrations::connectors::firewall::js_slice(
            item.get("title").and_then(Value::as_str).unwrap_or(""),
            64,
        );
        Ok(OpLogin {
            item_id: item.get("id").and_then(Value::as_str).unwrap_or(item_id).into(),
            vault_id: vault_id.into(),
            title: if title.is_empty() {
                "1Password login".into()
            } else {
                title
            },
            urls: urls.into_iter().map(|(_, h)| h).filter(|h| !h.is_empty()).collect(),
            username: field("purpose", "USERNAME").unwrap_or_default(),
            password: field("purpose", "PASSWORD").unwrap_or_default(),
            totp: fields
                .iter()
                .find(|f| {
                    f.get("type").and_then(Value::as_str) == Some("OTP")
                        && f.get("value").and_then(Value::as_str).is_some_and(|v| !v.is_empty())
                })
                .and_then(|f| f.get("value").and_then(Value::as_str).map(str::to_string)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cc_proc::{RecordingRunner, exit, ok};

    #[tokio::test]
    async fn op_runs_with_the_token_in_its_environment_only_and_reads_items() {
        let r = RecordingRunner::new();
        r.answer(
            &["op", "vault", "list"],
            ok(r#"[{"id":"v1abcdefghij","name":"Shared"},{"id":3}]"#),
        );
        r.answer(&["op", "item", "get"], ok(r#"{"id":"it1","title":"GitHub","urls":[{"href":"https://x.example"},{"href":"https://github.com/login","primary":true}],
            "fields":[{"purpose":"USERNAME","value":"ana"},{"purpose":"PASSWORD","value":"pw"},{"type":"OTP","value":"otpauth://totp/x?secret=JBSWY3DPEHPK3PXP"}]}"#));
        let mut op = OnePassword::new(Arc::new(r.clone()));
        op.bin = "op".into();
        op.config_dir = tempfile::tempdir().expect("dir").path().display().to_string();
        let v = op.vaults("ops_secret").await.expect("vaults");
        assert_eq!(
            v,
            vec![OpVault {
                id: "v1abcdefghij".into(),
                name: "Shared".into()
            }]
        );
        let call = &r.calls()[0];
        assert_eq!(call.args, ["vault", "list", "--format", "json"]);
        assert!(call.clear_env);
        assert_eq!(
            call.env.get("OP_SERVICE_ACCOUNT_TOKEN").map(String::as_str),
            Some("ops_secret")
        );
        assert!(
            !call.args.iter().any(|a| a.contains("ops_")),
            "never on the command line"
        );
        let item = op.get("ops_secret", "v1abcdefghij", "it1").await.expect("item");
        assert_eq!(item.urls, ["https://github.com/login", "https://x.example"]);
        assert_eq!((item.username.as_str(), item.password.as_str()), ("ana", "pw"));
        assert!(item.totp.is_some());
        r.answer(&["op", "item", "list", "--vault", "v1"], exit(1, ""));
        assert!(op.list("ops_secret", "v1").await.is_err());
        // Not a list: a failed read, never an empty vault.
        r.answer(&["op", "item", "list", "--vault", "v2"], ok("null"));
        assert!(op.list("ops_secret", "v2").await.is_err());
        // Not an item: a failed read, never a login with nothing in it.
        for answer in ["null", "[]", "\"x\""] {
            let r = RecordingRunner::new();
            r.answer(&["op", "item", "get"], ok(answer));
            let mut op = OnePassword::new(Arc::new(r));
            op.bin = "op".into();
            op.config_dir = tempfile::tempdir().expect("dir").path().display().to_string();
            assert_eq!(
                op.get("ops_secret", "v1abcdefghij", "it9").await.err().as_deref(),
                Some(UNREADABLE),
                "{answer}"
            );
        }
    }

    #[test]
    fn failures_are_sentences_never_stderr() {
        assert_eq!(
            op_failure("[ERROR] 2026/10/28 10:00:00 Unauthorized: token ops_abc"),
            "1Password did not accept that token. Paste a service account token (it starts with ops_)."
        );
        assert_eq!(
            op_failure("Using configuration at x\n[ERROR] a b rate limit exceeded"),
            "1Password is limiting how often this token can be used. Try again in a few minutes."
        );
        assert_eq!(
            op_failure("\"v\" isn't a vault in this account"),
            "The token cannot open that vault. Give the service account access to it in 1Password."
        );
        assert_eq!(op_failure(""), "1Password did not answer. Try again in a minute.");
    }
}
