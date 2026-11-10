//! The emergency stop, web search and the exit proxy (the user's own), as the SaaS's
//! `killSwitch.*`, `webSearch.*` and `exit.*` do them, with no code for the signed-in admin. The
//! stop's and the exit's state come from the firewall's beat fields (`kill`, `residential`); the
//! search key is kept here like a model key (a hint, the placeholder), since the firewall has no
//! read of it.

use http::Method;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use super::{CommandAnswer, Ctx, Reply, Result, Route, agent_refs, checked, new_id};
use crate::db::Db;

const TAG: &str = "controls";
const SEARCH_KEY: &str = "web_search";
/// OpenClaw's own search, used when no key is set (the SaaS's `DEFAULT_SEARCH_PROVIDER`).
const DEFAULT_SEARCH_PROVIDER: &str = "parallel-free";

pub fn routes() -> Vec<Route> {
    vec![
        Route::get::<(), KillView, _, _>("/api/kill", TAG, "Whether the agents are stopped", |c| async move {
            Ok(Reply::ok(&KillView {
                kill: (c.hooks.status)().remove("kill").unwrap_or(Value::Null),
            }))
        }),
        Route::write::<Engage, CommandAnswer, _, _>(
            Method::POST,
            "/api/kill/engage",
            TAG,
            "Stop every agent, or one (`vmId`): their traffic is refused until released. Type STOP.",
            |c, b| async move {
                if b.confirm != "STOP" {
                    return Err(Reply::bad("Type STOP to confirm."));
                }
                let p = checked("kill.engage", kill_payload(&c, b.vm_id.as_deref(), true)?)?;
                Ok(c.command("kill.engage", Value::Object(p)).await?.reply())
            },
        ),
        Route::write::<Release, CommandAnswer, _, _>(
            Method::POST,
            "/api/kill/release",
            TAG,
            "Let every agent, or one, go again",
            |c, b| async move {
                if b.vm_id.is_some() {
                    return Ok(release(&c, b.vm_id.as_deref()).await?.reply());
                }
                // Every stop: the firewall's org-wide release leaves an agent stopped on its own
                // stopped (the SaaS lifts those one by one), so each of them is released here too,
                // after the org stop, under which an agent's release starts nothing.
                let kill = (c.hooks.status)().remove("kill").unwrap_or(Value::Null);
                let own: Vec<String> = kill["agents"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|a| a["vmId"].as_str().map(str::to_string))
                    .collect();
                // Each one tried; the answer is the first that was not applied, else the last.
                let mut scopes: Vec<Option<String>> = Vec::new();
                if !kill["org"].is_null() || own.is_empty() {
                    scopes.push(None);
                }
                scopes.extend(own.into_iter().map(Some));
                let mut answers = Vec::new();
                for vm in &scopes {
                    answers.push(release(&c, vm.as_deref()).await?);
                }
                let first_not_applied = answers.iter().position(|a| a.status != "applied");
                let answer = match first_not_applied {
                    Some(i) => answers.swap_remove(i),
                    None => answers.pop().expect("one release at least"),
                };
                Ok(answer.reply())
            },
        ),
        Route::get::<(), SearchView, _, _>(
            "/api/search",
            TAG,
            "The web search key, and the providers",
            |c| async move { Ok(Reply::ok(&search_view(&c.db))) },
        ),
        Route::write::<SearchKey, SearchChange, _, _>(
            Method::PUT,
            "/api/search/key",
            TAG,
            "Set the web search key for every agent (Tavily or Brave), replacing one there is",
            |c, b| async move { put_search(&c, b).await },
        ),
        Route::write::<super::NoBody, SearchChange, _, _>(
            Method::DELETE,
            "/api/search/key",
            TAG,
            "Remove the web search key; agents go back to the free search",
            |c, _| async move { remove_search(&c).await },
        ),
        Route::get::<(), ExitView, _, _>(
            "/api/exit",
            TAG,
            "The exit proxy, and what it carried",
            |c| async move {
                Ok(Reply::ok(&ExitView {
                    residential: residential(&c),
                }))
            },
        ),
        Route::write::<ExitAccount, CommandAnswer, _, _>(
            Method::PUT,
            "/api/exit",
            TAG,
            "Set the exit proxy (your own account with a proxy provider), or replace it",
            |c, b| async move { put_exit(&c, b).await },
        ),
        Route::write::<ExitSettings, CommandAnswer, _, _>(
            Method::PATCH,
            "/api/exit",
            TAG,
            "Change the exit's settings: one IP per agent, a byte cap, the country",
            |c, b| async move { exit_settings(&c, b).await },
        ),
        Route::write::<super::NoBody, CommandAnswer, _, _>(
            Method::DELETE,
            "/api/exit",
            TAG,
            "Remove the exit proxy: no traffic leaves through it",
            |c, _| async move {
                let mut p = Map::new();
                p.insert("kind".into(), json!("remove"));
                exit(&c, p).await
            },
        ),
        Route::write::<super::NoBody, CommandAnswer, _, _>(
            Method::POST,
            "/api/exit/check",
            TAG,
            "Check the exit proxy now: one request through it",
            |c, _| async move { Ok(c.command("exit.check", json!({})).await?.reply()) },
        ),
    ]
}

// ---- the stop ----

#[derive(Debug, Serialize, JsonSchema)]
pub struct KillView {
    /// The firewall's own account: `{org, agents: [{vmId, ...}]}`; null when it has none.
    pub kill: Value,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Engage {
    /// One agent; every agent when left out.
    #[serde(default)]
    pub vm_id: Option<String>,
    /// `STOP`.
    pub confirm: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Release {
    #[serde(default)]
    pub vm_id: Option<String>,
}

/// `kill.release` for one agent, or the org-wide stop, confirmed at once.
async fn release(c: &Ctx, vm: Option<&str>) -> Result<CommandAnswer> {
    let p = checked("kill.release", kill_payload(c, vm, false)?)?;
    let mut with = Map::new();
    with.insert("scope".into(), p["scope"].clone());
    if let Some(v) = vm {
        with.insert("vmId".into(), json!(v));
    }
    c.apply_as("kill.release", "kill.confirm", p, with).await
}

/// `known`: the agent must be in the list now (a stop); a release also takes one removed since.
fn kill_payload(c: &Ctx, vm: Option<&str>, known: bool) -> Result<Value> {
    let agents = agent_refs(&c.db)?;
    if let Some(v) = vm
        && known
        && !agents.iter().any(|a| a["vmId"] == v)
    {
        return Err(Reply::not_found("Agent"));
    }
    let mut p =
        json!({"changeId": new_id("chg"), "scope": if vm.is_some() { "agent" } else { "org" }, "agents": agents});
    if let Some(v) = vm {
        p["vmId"] = json!(v);
    }
    Ok(p)
}

// ---- web search ----

struct SearchProvider {
    id: &'static str,
    name: &'static str,
    package: &'static str,
    base_url: &'static str,
    config: Option<(&'static str, &'static str)>,
    match_domain: &'static str,
    location: &'static str,
    key_prefix: &'static str,
    placeholder_prefix: &'static str,
}

const SEARCH_PROVIDERS: &[SearchProvider] = &[
    SearchProvider {
        id: "tavily",
        name: "Tavily",
        package: "@openclaw/tavily-plugin",
        base_url: "https://api.tavily.com",
        config: None,
        match_domain: "api.tavily.com",
        location: "header:authorization",
        key_prefix: "tvly-",
        placeholder_prefix: "tvly-cc-",
    },
    SearchProvider {
        id: "brave",
        name: "Brave Search",
        package: "@openclaw/brave-plugin",
        base_url: "https://api.search.brave.com",
        config: Some(("mode", "web")),
        match_domain: "api.search.brave.com",
        location: "header:x-subscription-token",
        key_prefix: "BSA",
        placeholder_prefix: "BSAcc",
    },
];

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SearchKeyInfo {
    pub credential_id: String,
    /// `tavily` or `brave`.
    pub provider: String,
    pub hint: String,
    #[serde(skip_serializing)]
    #[schemars(skip)]
    #[serde(default)]
    pub placeholder: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct SearchView {
    /// The key set, or null: agents use the free search.
    pub key: Option<SearchKeyInfo>,
    pub providers: Vec<SearchProviderOption>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct SearchProviderOption {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SearchKey {
    /// `tavily` or `brave`.
    pub provider: String,
    pub key: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct SearchChange {
    pub result: CommandAnswer,
    pub key: Option<SearchKeyInfo>,
}

fn search_key(db: &Db) -> Option<SearchKeyInfo> {
    // The placeholder is kept with it, so read the stored JSON as it is.
    let raw: Value = serde_json::from_str(&db.setting(SEARCH_KEY)?).ok()?;
    Some(SearchKeyInfo {
        credential_id: raw.get("credentialId")?.as_str()?.into(),
        provider: raw.get("provider")?.as_str()?.into(),
        hint: raw.get("hint")?.as_str()?.into(),
        placeholder: raw.get("placeholder")?.as_str()?.into(),
    })
}

fn search_view(db: &Db) -> SearchView {
    SearchView {
        key: search_key(db),
        providers: SEARCH_PROVIDERS
            .iter()
            .map(|p| SearchProviderOption {
                id: p.id.into(),
                name: p.name.into(),
            })
            .collect(),
    }
}

/// The `search.propose` payload, as the SaaS's `proposalPayload` makes it.
fn search_payload(
    c: &Ctx,
    p: &SearchProvider,
    kind: &str,
    id: &str,
    placeholder: &str,
    hint: &str,
) -> Result<Map<String, Value>> {
    let mut v = json!({
        "changeId": new_id("chg"),
        "kind": kind,
        "credentialId": id,
        "provider": p.id,
        "providerName": p.name,
        "placeholder": placeholder,
        "hint": hint,
        "plugin": {"id": p.id, "package": p.package},
        "baseUrl": p.base_url,
        "swap": {"matchDomain": p.match_domain, "locations": [p.location]},
        "defaultProvider": DEFAULT_SEARCH_PROVIDER,
        "agents": agent_refs(&c.db)?,
    });
    if let Some((k, val)) = p.config {
        v["config"] = json!({ k: val });
    }
    Ok(v.as_object().cloned().unwrap_or_default())
}

/// One search key change at a time (as the model keys).
static SEARCH_CHANGES: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn put_search(c: &Ctx, b: SearchKey) -> Result {
    let _one = SEARCH_CHANGES.lock().await;
    let Some(p) = SEARCH_PROVIDERS.iter().find(|p| p.id == b.provider) else {
        return Err(Reply::bad("provider: tavily or brave"));
    };
    let key = b.key.trim();
    let ok = key
        .strip_prefix(p.key_prefix)
        .is_some_and(|t| t.len() >= 8 && t.bytes().all(|x| x.is_ascii_alphanumeric() || x == b'_' || x == b'-'));
    if !ok {
        return Err(Reply::bad(format!("That does not look like a {} key.", p.name)));
    }
    let had = search_key(&c.db);
    let id = had
        .as_ref()
        .map_or_else(|| new_id("search"), |k| k.credential_id.clone());
    let placeholder = super::llm::mint_placeholder(p.placeholder_prefix);
    let tail: Vec<char> = key.chars().rev().take(4).collect();
    let hint = format!("…{}", tail.into_iter().rev().collect::<String>());
    let mut payload = search_payload(
        c,
        p,
        if had.is_some() { "replace" } else { "add" },
        &id,
        &placeholder,
        &hint,
    )?;
    if let Some(h) = &had
        && h.provider != p.id
    {
        // A name, for the summary the code message and the activity show.
        let name = SEARCH_PROVIDERS
            .iter()
            .find(|x| x.id == h.provider)
            .map_or(h.provider.as_str(), |x| x.name);
        payload.insert("replaces".into(), json!(name));
    }
    payload.insert("secret".into(), json!({"apiKey": key}));
    let result = c
        .apply("search", checked("search.propose", Value::Object(payload))?)
        .await?;
    // Only once the firewall holds it: a change still waiting for a code is not a key yet.
    if result.ok && result.status == "applied" {
        let info = json!({"credentialId": id, "provider": p.id, "hint": hint, "placeholder": placeholder});
        c.db.set_setting(SEARCH_KEY, &info.to_string())?;
    }
    Ok(search_reply(c, result))
}

async fn remove_search(c: &Ctx) -> Result {
    let _one = SEARCH_CHANGES.lock().await;
    let Some(k) = search_key(&c.db) else {
        return Err(Reply::not_found("Web search key"));
    };
    let Some(p) = SEARCH_PROVIDERS.iter().find(|p| p.id == k.provider) else {
        return Err(Reply::not_found("Web search provider"));
    };
    let payload = search_payload(c, p, "remove", &k.credential_id, &k.placeholder, &k.hint)?;
    let result = c
        .apply("search", checked("search.propose", Value::Object(payload))?)
        .await?;
    if result.ok && result.status == "applied" {
        c.db.delete_setting(SEARCH_KEY)?;
    }
    Ok(search_reply(c, result))
}

fn search_reply(c: &Ctx, result: CommandAnswer) -> Reply {
    Reply {
        status: if result.ok { 200 } else { 409 },
        body: serde_json::to_value(SearchChange {
            result,
            key: search_key(&c.db),
        })
        .unwrap_or(Value::Null),
    }
}

// ---- the exit proxy ----

#[derive(Debug, Serialize, JsonSchema)]
pub struct ExitView {
    /// The firewall's own account: provider, host, sticky, cap, country, bytes used, last check;
    /// `{configured: false}` when there is none.
    pub residential: Value,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExitAccount {
    /// A preset id (`brightdata`, `oxylabs`, `decodo`, `iproyal`, `apify`) or `custom`.
    pub provider: String,
    /// The name shown in the summary; the provider id when left out.
    #[serde(default)]
    pub provider_name: Option<String>,
    /// `http`, `https` or `socks5`.
    pub scheme: String,
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub username: String,
    pub password: String,
    /// How the proxy's user name is written, with `{username}`, `{session}`, `{country}`.
    pub username_template: String,
    pub password_template: String,
    /// One IP per agent.
    #[serde(default)]
    pub sticky: bool,
    #[serde(default)]
    pub cap_bytes: Option<u64>,
    /// Two letters; any country when left out.
    #[serde(default)]
    pub country: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExitSettings {
    /// Left out: unchanged.
    #[serde(default)]
    pub sticky: Option<bool>,
    /// Left out: unchanged; `null`: no cap.
    #[serde(default, deserialize_with = "some")]
    pub cap_bytes: Option<Option<u64>>,
    /// Left out: unchanged; `null`: any country.
    #[serde(default, deserialize_with = "some")]
    pub country: Option<Option<String>>,
}

fn some<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> std::result::Result<Option<Option<T>>, D::Error> {
    Option::<T>::deserialize(d).map(Some)
}

/// Two letters, upper case; anything else is a 400.
fn country(c: Option<&str>) -> Result<Option<String>> {
    match c.map(str::trim).filter(|c| !c.is_empty()) {
        None => Ok(None),
        Some(c) if c.len() == 2 && c.bytes().all(|x| x.is_ascii_alphabetic()) => Ok(Some(c.to_ascii_uppercase())),
        Some(_) => Err(Reply::bad("country: two letters")),
    }
}

/// The exit as the firewall reports it (`residential` on its beat).
fn residential(c: &Ctx) -> Value {
    (c.hooks.status)().remove("residential").unwrap_or(Value::Null)
}

/// A settings change carries one IP per agent always (the module writes what it gets), so a
/// request that leaves it out keeps the current one.
async fn exit_settings(c: &Ctx, b: ExitSettings) -> Result {
    let cur = residential(c);
    let mut p = Map::new();
    p.insert("kind".into(), json!("settings"));
    let sticky = b
        .sticky
        .unwrap_or_else(|| cur.get("sticky").and_then(Value::as_bool).unwrap_or(false));
    p.insert("sticky".into(), json!(sticky));
    if let Some(cap) = b.cap_bytes {
        p.insert("capBytes".into(), json!(cap));
    }
    if let Some(cn) = b.country {
        p.insert("country".into(), json!(country(cn.as_deref())?));
    }
    exit(c, p).await
}

async fn put_exit(c: &Ctx, b: ExitAccount) -> Result {
    if b.host.trim().is_empty() || b.password.is_empty() {
        return Err(Reply::bad("host and password are needed"));
    }
    let cn = country(b.country.as_deref())?;
    let configured = residential(c)
        .get("configured")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let hint: String = match b.username.chars().count() {
        0 => String::new(),
        n if n <= 4 => "…".into(),
        _ => format!("{}…", b.username.chars().take(4).collect::<String>()),
    };
    let mut p = Map::new();
    p.insert("kind".into(), json!(if configured { "replace" } else { "add" }));
    p.insert(
        "providerName".into(),
        json!(b.provider_name.clone().unwrap_or_else(|| b.provider.clone())),
    );
    p.insert("provider".into(), json!(b.provider));
    p.insert("scheme".into(), json!(b.scheme));
    p.insert("host".into(), json!(b.host.trim()));
    p.insert("port".into(), json!(b.port));
    p.insert("username".into(), json!(b.username));
    p.insert("password".into(), json!(b.password));
    p.insert("usernameTemplate".into(), json!(b.username_template));
    p.insert("passwordTemplate".into(), json!(b.password_template));
    p.insert("usernameHint".into(), json!(hint));
    p.insert("sticky".into(), json!(b.sticky));
    p.insert("capBytes".into(), json!(b.cap_bytes));
    p.insert("country".into(), json!(cn));
    exit(c, p).await
}

async fn exit(c: &Ctx, mut p: Map<String, Value>) -> Result {
    p.insert("changeId".into(), json!(new_id("chg")));
    let p = checked("exit.propose", Value::Object(p))?;
    // The module rewrites the proxy's exit file itself once a change applies.
    Ok(c.apply("exit", p).await?.reply())
}
