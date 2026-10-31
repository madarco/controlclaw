//! Control-plane cases: the other side of the contract. Instead of an agent answering a fake
//! console, a control plane answers what a firewall sends it (docs/standalone/control-plane-contract.md).
//! The `saas` target is `apps/saas/scripts/conformance-cp.ts`, the real route modules behind a small
//! server; the `local` target is the standalone firewall's own control plane (`cc-local-contract`).
//!
//! A case seeds an organization with its boxes through the target's `/__conformance/seed` hook, then
//! sends requests signed as one of those boxes, and removes the organization at the end. Values come
//! back into later steps as `${name.path}`: `${org_id}`, `${bootstrap.<vm id>}`, and what a step
//! kept with `save: <name>`.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use cc_testkit::Pair;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use tokio::io::{AsyncBufReadExt, BufReader};

use crate::matcher::diff;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpTarget {
    Saas,
    Local,
}

impl CpTarget {
    pub fn name(self) -> &'static str {
        match self {
            CpTarget::Saas => "saas",
            CpTarget::Local => "local",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Scope {
    /// Every control plane answers it.
    Both,
    /// Only the SaaS: the local control plane does not serve it.
    SaasOnly,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CpCase {
    pub name: String,
    /// Always `control-plane`; what tells these cases from the agent ones.
    #[allow(dead_code)]
    pub agent: String,
    /// The endpoint the case is about, as the spec names it.
    pub endpoint: String,
    pub scope: Scope,
    #[serde(default)]
    pub seed: Seed,
    pub steps: Vec<CpStep>,
    #[serde(default)]
    pub skip: BTreeMap<String, String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct Seed {
    /// Each box gets a fresh key pair; its public half is seeded unless `bootstrap` is set.
    #[serde(default)]
    pub vms: Vec<Map<String, Value>>,
    /// Passed to the hook as they are (`egress_rules`, `store`).
    #[serde(flatten)]
    pub rest: Map<String, Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CpStep {
    #[serde(default)]
    pub name: Option<String>,
    /// `saas-only`: a step about what only the SaaS has (the command queue); the local target
    /// skips it.
    #[serde(default)]
    pub scope: Option<Scope>,
    pub request: CpRequest,
    #[serde(default)]
    pub expect: CpExpect,
    /// Keep the answer's JSON under this name for later steps.
    #[serde(default)]
    pub save: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CpRequest {
    pub method: String,
    pub path: String,
    /// Sign as this seeded box: `{vmId}`, 30 s, its own key (the box token every call carries).
    #[serde(default, rename = "as")]
    pub as_vm: Option<String>,
    /// A token that must fail: signed for `as` with a key the control plane does not know, or
    /// already expired.
    #[serde(default)]
    pub broken: Option<Broken>,
    /// A raw `Authorization` header instead (`Bearer <bootstrap token>`).
    #[serde(default)]
    pub authorization: Option<String>,
    #[serde(default)]
    pub json: Option<Value>,
    /// A raw body, sent as it is.
    #[serde(default)]
    pub body: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Broken {
    WrongKey,
    Expired,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CpExpect {
    pub status: Option<u16>,
    pub json: Option<Value>,
    pub json_subset: Option<Value>,
}

pub fn load(path: &Path) -> Result<CpCase> {
    let raw = std::fs::read_to_string(path)?;
    serde_yaml::from_str(&raw).with_context(|| format!("{}", path.display()))
}

/// Whether a case file is a control-plane case, without parsing the rest.
pub fn is_cp(path: &Path) -> bool {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|raw| serde_yaml::from_str::<Value>(&raw).ok())
        .is_some_and(|v| v.get("agent").and_then(Value::as_str) == Some("control-plane"))
}

/// A running control plane: its address, and the process when the runner started it.
pub struct Server {
    base: String,
    child: Option<tokio::process::Child>,
    http: reqwest::Client,
}

impl Server {
    /// `conformance-cp.ts` under tsx, on a free port; ready when it prints `listening <port>`.
    pub async fn start_saas(repo: &Path) -> Result<Self> {
        let app = repo.join("apps/saas");
        let tsx = app.join("node_modules/.bin/tsx");
        if !tsx.exists() {
            bail!("{} is missing: run pnpm install", tsx.display());
        }
        let mut cmd = tokio::process::Command::new(tsx);
        cmd.args(["-r", "./scripts/server-only-shim.cjs", "scripts/conformance-cp.ts"])
            .current_dir(&app);
        Self::spawn(cmd, "conformance-cp.ts").await
    }

    /// `cc-local-contract`, the standalone firewall's control plane with the same hooks.
    pub async fn start_local(rust_bin_dir: &Path) -> Result<Self> {
        let bin = rust_bin_dir.join("cc-local-contract");
        if !bin.exists() {
            bail!(
                "{} is missing: cargo build -p cc-local --features contract",
                bin.display()
            );
        }
        Self::spawn(tokio::process::Command::new(bin), "cc-local-contract").await
    }

    async fn spawn(mut cmd: tokio::process::Command, what: &str) -> Result<Self> {
        let mut child = cmd
            .env("PORT", "0")
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            // tsx runs node as its own child: a group of their own, so `stop` ends both.
            .process_group(0)
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("start {what}"))?;
        let stdout = child.stdout.take().context("stdout")?;
        let mut lines = BufReader::new(stdout).lines();
        let port = tokio::time::timeout(Duration::from_secs(60), async {
            while let Some(line) = lines.next_line().await? {
                if let Some(p) = line.strip_prefix("listening ") {
                    return Ok::<u16, anyhow::Error>(p.trim().parse()?);
                }
            }
            bail!("{what} exited before listening")
        })
        .await
        .with_context(|| format!("{what} did not listen within 60 s"))??;
        // The server logs what it is asked; drained so it never blocks on a full pipe.
        tokio::spawn(async move { while let Ok(Some(_)) = lines.next_line().await {} });
        Ok(Self {
            base: format!("http://127.0.0.1:{port}"),
            child: Some(child),
            http: reqwest::Client::new(),
        })
    }

    /// Ends the harness (also on drop, so an early return cannot leave it running).
    pub fn stop(self) {}

    async fn hook(&self, name: &str, body: &Value) -> Result<Value> {
        let r = self
            .http
            .post(format!("{}/__conformance/{name}", self.base))
            .json(body)
            .send()
            .await?;
        let status = r.status();
        let v: Value = r.json().await.unwrap_or(Value::Null);
        if !status.is_success() || v.get("error").is_some() {
            bail!("hook {name}: {status} {v}");
        }
        Ok(v)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        if let Some(pid) = self.child.as_ref().and_then(tokio::process::Child::id) {
            let _ = std::process::Command::new("kill")
                .args(["-KILL", "--", &format!("-{pid}")])
                .status();
        }
    }
}

pub enum Outcome {
    Pass,
    Skip(String),
}

pub async fn run(case: &CpCase, target: CpTarget, server: Option<&Server>) -> Result<Outcome> {
    if let Some(why) = case.skip.get(target.name()) {
        return Ok(Outcome::Skip(why.clone()));
    }
    if target == CpTarget::Local && case.scope == Scope::SaasOnly {
        return Ok(Outcome::Skip("SaaS only".into()));
    }
    let Some(server) = server else {
        return Ok(Outcome::Skip(format!("no {} control plane yet", target.name())));
    };
    let mut keys: HashMap<String, Pair> = HashMap::new();
    let mut vms = Vec::new();
    for v in &case.seed.vms {
        let id = v
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("a seeded vm has no id"))?;
        let pair = Pair::generate();
        let mut v = v.clone();
        if !v.get("bootstrap").and_then(Value::as_bool).unwrap_or(false) {
            v.insert("public_key".into(), json!(pair.public_pem));
        }
        keys.insert(id.to_string(), pair);
        vms.push(Value::Object(v));
    }
    let mut seed = case.seed.rest.clone();
    seed.insert("vms".into(), Value::Array(vms));
    let seeded = server.hook("seed", &Value::Object(seed)).await?;
    let org_id = seeded["org_id"].as_str().unwrap_or_default().to_string();
    let mut vars: Map<String, Value> = Map::new();
    vars.insert("org_id".into(), json!(org_id));
    vars.insert("bootstrap".into(), seeded["bootstrap"].clone());
    let result = steps(case, target, server, &keys, &mut vars).await;
    let cleaned = server.hook("reset", &json!({"org_id": org_id})).await;
    result?;
    cleaned?;
    Ok(Outcome::Pass)
}

async fn steps(
    case: &CpCase,
    target: CpTarget,
    server: &Server,
    keys: &HashMap<String, Pair>,
    vars: &mut Map<String, Value>,
) -> Result<()> {
    for (i, step) in case.steps.iter().enumerate() {
        if target == CpTarget::Local && step.scope == Some(Scope::SaasOnly) {
            continue;
        }
        let label = step.name.clone().unwrap_or_else(|| format!("step {}", i + 1));
        let r = &step.request;
        let path = interpolate(&json!(r.path), vars)?;
        let url = format!("{}{}", server.base, path.as_str().unwrap_or_default());
        let method = reqwest::Method::from_bytes(r.method.as_bytes())?;
        let mut req = server.http.request(method, url);
        if let Some(vm) = &r.as_vm {
            let pair = keys.get(vm).ok_or_else(|| anyhow!("{label}: {vm} is not seeded"))?;
            req = req.bearer_auth(box_token(vm, pair, r.broken)?);
        }
        if let Some(a) = &r.authorization {
            req = req.header(
                "authorization",
                interpolate(&json!(a), vars)?.as_str().unwrap_or_default(),
            );
        }
        if let Some(j) = &r.json {
            req = req.json(&interpolate(j, vars)?);
        } else if let Some(b) = &r.body {
            req = req.header("content-type", "application/json").body(b.clone());
        }
        let started = Instant::now();
        let resp = req.send().await.with_context(|| format!("{label}: send"))?;
        let status = resp.status().as_u16();
        let text = resp.text().await.unwrap_or_default();
        let got: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        let e = &step.expect;
        if let Some(want) = e.status
            && want != status
        {
            bail!("{label}: status {status}, want {want}; body {text}");
        }
        if let Some(w) = &e.json
            && let Some(d) = diff(&interpolate(w, vars)?, &got, false, "$")
        {
            bail!("{label}: {d}; body {text}");
        }
        if let Some(w) = &e.json_subset
            && let Some(d) = diff(&interpolate(w, vars)?, &got, true, "$")
        {
            bail!("{label}: {d}; body {text}");
        }
        if started.elapsed() > Duration::from_secs(30) {
            bail!("{label}: took {:?}", started.elapsed());
        }
        if let Some(name) = &step.save {
            vars.insert(name.clone(), got);
        }
    }
    Ok(())
}

/// `{vmId}` signed with the box's key, for as long as `cc_auth::sign::box_token`'s tokens live.
fn box_token(vm: &str, pair: &Pair, broken: Option<Broken>) -> Result<String> {
    let mut claims = Map::new();
    claims.insert("vmId".into(), json!(vm));
    let key = match broken {
        Some(Broken::WrongKey) => Pair::generate().sign_key(),
        _ => pair.sign_key(),
    };
    let iat = (broken == Some(Broken::Expired)).then(|| cc_auth::jwt::now_s() - 120);
    Ok(cc_auth::jwt::sign(
        claims,
        &key,
        Some(cc_auth::sign::BOX_TOKEN_LIFETIME_S),
        iat,
    )?)
}

/// `${a.b.c}` in strings: a string that is only the reference takes the value as it is (any JSON
/// type); inside other text it is put in as text.
fn interpolate(v: &Value, vars: &Map<String, Value>) -> Result<Value> {
    Ok(match v {
        Value::String(s) => {
            if let Some(name) = s.strip_prefix("${").and_then(|r| r.strip_suffix('}'))
                && !name.contains("${")
            {
                lookup(name, vars)?
            } else {
                let mut out = String::new();
                let mut rest = s.as_str();
                while let Some(start) = rest.find("${") {
                    out.push_str(&rest[..start]);
                    let end = rest[start..].find('}').ok_or_else(|| anyhow!("unclosed ${{ in {s}"))?;
                    let found = lookup(&rest[start + 2..start + end], vars)?;
                    out.push_str(&found.as_str().map_or_else(|| found.to_string(), str::to_string));
                    rest = &rest[start + end + 1..];
                }
                out.push_str(rest);
                Value::String(out)
            }
        }
        Value::Array(a) => Value::Array(a.iter().map(|x| interpolate(x, vars)).collect::<Result<_>>()?),
        Value::Object(m) => Value::Object(
            m.iter()
                .map(|(k, x)| Ok((k.clone(), interpolate(x, vars)?)))
                .collect::<Result<_>>()?,
        ),
        other => other.clone(),
    })
}

fn lookup(name: &str, vars: &Map<String, Value>) -> Result<Value> {
    let mut parts = name.split('.');
    let first = parts.next().unwrap_or_default();
    let mut v = vars.get(first).ok_or_else(|| anyhow!("no value ${{{name}}}"))?;
    for p in parts {
        v = match v {
            Value::Array(a) => p.parse::<usize>().ok().and_then(|i| a.get(i)),
            other => other.get(p),
        }
        .ok_or_else(|| anyhow!("no value ${{{name}}}"))?;
    }
    Ok(v.clone())
}

/// The case files under `paths` that are control-plane cases.
pub fn files(all: &[PathBuf]) -> (Vec<PathBuf>, Vec<PathBuf>) {
    all.iter().cloned().partition(|p| is_cp(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interpolates_whole_values_and_text() {
        let mut vars = Map::new();
        vars.insert("org_id".into(), json!("cf_1"));
        vars.insert("cmd".into(), json!({"id": "c1", "n": 3, "list": [{"x": "y"}]}));
        let v = interpolate(
            &json!({"a": "${cmd.n}", "b": "id=${cmd.id}/${org_id}", "c": ["${cmd.list.0.x}"]}),
            &vars,
        )
        .expect("interpolate");
        assert_eq!(v, json!({"a": 3, "b": "id=c1/cf_1", "c": ["y"]}));
        assert!(interpolate(&json!("${nope}"), &vars).is_err());
    }
}
