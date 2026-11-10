//! Internet access: the egress rules one by one and the AI review settings, as the SaaS's
//! `egress.*` procedures do them (`apps/saas/app/(mitm)/lib/egress.rpc.ts`), with the same checks.
//! The firewall reads both on its next sync (`/egress-rules`), which a change here starts at once.

use http::Method;
use rusqlite::{OptionalExtension, Row, params};
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Value, json};

use super::{CommandAnswer, Ctx, Reply, Result, Route, new_id};
use crate::db::{BLOCK_ALL_ID, BLOCK_ALL_NAME, BLOCK_ALL_PRIORITY, Db, now_s};
use crate::plane::iso;

const TAG: &str = "egress";
/// The AI settings as the panel edits them; `ai_settings` holds what the firewall reads.
const AI_KEY: &str = "egress_ai";
const INSTRUCTIONS_MAX: usize = 2000;

pub fn routes() -> Vec<Route> {
    vec![
        Route::get::<(), Vec<EgressRule>, _, _>(
            "/api/egress/rules",
            TAG,
            "The egress rules, in order",
            |c| async move { Ok(Reply::ok(&list(&c.db)?)) },
        ),
        Route::write::<NewEgressRule, EgressRule, _, _>(
            Method::POST,
            "/api/egress/rules",
            TAG,
            "Add an egress rule",
            |c, b| async move { create(&c, b) },
        ),
        Route::write::<EgressRulePatch, EgressRule, _, _>(
            Method::PATCH,
            "/api/egress/rules/:id",
            TAG,
            "Change an egress rule",
            |c, b| async move { update(&c, b) },
        ),
        Route::write::<super::NoBody, EgressRule, _, _>(
            Method::POST,
            "/api/egress/rules/:id/cycle",
            TAG,
            "Move a rule to its next effect: allow, ask, block, allow",
            |c, _| async move { cycle(&c) },
        ),
        Route::write::<super::NoBody, Deleted, _, _>(
            Method::DELETE,
            "/api/egress/rules/:id",
            TAG,
            "Delete an egress rule",
            |c, _| async move {
                locked(c.param("id"))?;
                let n =
                    c.db.lock()
                        .execute("DELETE FROM egress_rules WHERE id = ?1", [c.param("id")])?;
                if n == 0 {
                    return Err(Reply::not_found("Egress rule"));
                }
                (c.hooks.rules_changed)();
                Ok(Reply::ok(&Deleted {
                    id: c.param("id").into(),
                }))
            },
        ),
        Route::get::<(), EveryOtherSite, _, _>(
            "/api/egress/default",
            TAG,
            "What happens to a site no rule names: allow (and logged), or block",
            |c| async move { Ok(Reply::ok(&every_other_site(&c.db)?)) },
        ),
        Route::write::<EveryOtherSite, EveryOtherSite, _, _>(
            Method::PUT,
            "/api/egress/default",
            TAG,
            "Allow or block every site no rule names. The rules added for model keys and bots still let those through",
            |c, b| async move { put_every_other_site(&c, b) },
        ),
        Route::get::<(), AiView, _, _>("/api/egress/ai", TAG, "The AI review settings", |c| async move {
            Ok(Reply::ok(&ai_view(&c.db)?))
        }),
        Route::write::<AiSettingsInput, AiView, _, _>(
            Method::PUT,
            "/api/egress/ai",
            TAG,
            "Change the AI review settings",
            |c, b| async move { put_ai(&c, b) },
        ),
        Route::write::<super::NoBody, CommandAnswer, _, _>(
            Method::POST,
            "/api/egress/scan",
            TAG,
            "Run the AI log review's scan now",
            |c, _| async move { Ok(c.command("ai.scan", json!({})).await?.reply()) },
        ),
    ]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    Allow,
    Block,
    RequirePermission,
    Tunnel,
}

impl Effect {
    fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Block => "block",
            Self::RequirePermission => "require_permission",
            Self::Tunnel => "tunnel",
        }
    }

    fn parse(s: &str) -> Self {
        match s {
            "block" => Self::Block,
            "require_permission" => Self::RequirePermission,
            "tunnel" => Self::Tunnel,
            _ => Self::Allow,
        }
    }

    /// AI review only on rules that let traffic out.
    fn reviewable(self) -> bool {
        matches!(self, Self::Allow | Self::RequirePermission)
    }

    /// A residential exit only on the effects that already let traffic out.
    fn relayable(self) -> bool {
        matches!(self, Self::Allow | Self::Tunnel)
    }
}

/// Where a rule's traffic leaves from. `residential` goes through the exit proxy (Settings).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Exit {
    #[default]
    Firewall,
    Residential,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[allow(clippy::upper_case_acronyms)]
pub enum HttpMethod {
    GET,
    POST,
    PUT,
    PATCH,
    DELETE,
    HEAD,
    OPTIONS,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct EgressRule {
    pub id: String,
    pub name: String,
    pub match_domain: String,
    pub match_path: Option<String>,
    pub match_method: Option<String>,
    pub match_port: Option<i64>,
    pub effect: Effect,
    pub exit: Exit,
    pub exit_country: Option<String>,
    pub priority: i64,
    pub enabled: bool,
    pub vm_id: Option<String>,
    pub ai_review: bool,
    pub ai_policy: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    /// Set on a rule this firewall added by itself for a model key (`anthropic`, `openai`, …) or a
    /// bot (`telegram`, `slack`): it cannot be changed, and goes when the key or the bot does.
    pub managed: Option<String>,
}

/// "Every other site": what happens to a request no rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DefaultEffect {
    /// Let through, and logged (and read by the AI log review when it is on).
    Allow,
    Block,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EveryOtherSite {
    pub effect: DefaultEffect,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NewEgressRule {
    /// 1 to 120 characters.
    pub name: String,
    /// 1 to 253 characters; `*.example.com` matches the subdomains.
    pub match_domain: String,
    #[serde(default)]
    pub match_path: Option<String>,
    #[serde(default)]
    pub match_method: Option<HttpMethod>,
    /// Only on a `tunnel` rule.
    #[serde(default)]
    pub match_port: Option<i64>,
    #[serde(default = "allow")]
    pub effect: Effect,
    #[serde(default)]
    pub exit: Exit,
    /// Two letters, for a residential exit.
    #[serde(default)]
    pub exit_country: Option<String>,
    /// 0 to 1,000,000; lower runs first. 1000 when left out.
    #[serde(default = "default_priority")]
    pub priority: i64,
    #[serde(default = "yes")]
    pub enabled: bool,
    /// One agent's rule; every agent's when left out.
    #[serde(default)]
    pub vm_id: Option<String>,
    #[serde(default)]
    pub ai_review: bool,
    /// At most 1000 characters: instructions on an allow rule, the approval policy on an ask rule.
    #[serde(default)]
    pub ai_policy: Option<String>,
}

fn allow() -> Effect {
    Effect::Allow
}
fn default_priority() -> i64 {
    1000
}
fn yes() -> bool {
    true
}

/// Left out: unchanged. `null`: cleared.
fn some<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> std::result::Result<Option<Option<T>>, D::Error> {
    Option::<T>::deserialize(d).map(Some)
}

/// Each field left out stays as it is; `null` clears one that may be empty.
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EgressRulePatch {
    pub name: Option<String>,
    pub match_domain: Option<String>,
    #[serde(default, deserialize_with = "some")]
    pub match_path: Option<Option<String>>,
    #[serde(default, deserialize_with = "some")]
    pub match_method: Option<Option<HttpMethod>>,
    #[serde(default, deserialize_with = "some")]
    pub match_port: Option<Option<i64>>,
    pub effect: Option<Effect>,
    pub exit: Option<Exit>,
    #[serde(default, deserialize_with = "some")]
    pub exit_country: Option<Option<String>>,
    pub priority: Option<i64>,
    pub enabled: Option<bool>,
    #[serde(default, deserialize_with = "some")]
    pub vm_id: Option<Option<String>>,
    pub ai_review: Option<bool>,
    #[serde(default, deserialize_with = "some")]
    pub ai_policy: Option<Option<String>>,
}

#[derive(Serialize, JsonSchema)]
pub struct Deleted {
    pub id: String,
}

const COLUMNS: &str = "id, name, match_domain, match_path, match_method, match_port, effect, exit, exit_country,
                       priority, enabled, vm_id, ai_review, ai_policy, created_at, updated_at";

fn row(r: &Row) -> rusqlite::Result<EgressRule> {
    let created: i64 = r.get(14)?;
    Ok(EgressRule {
        id: r.get(0)?,
        name: r.get(1)?,
        match_domain: r.get(2)?,
        match_path: r.get(3)?,
        match_method: r.get(4)?,
        match_port: r.get(5)?,
        effect: Effect::parse(&r.get::<_, String>(6)?),
        exit: if r.get::<_, Option<String>>(7)?.as_deref() == Some("residential") {
            Exit::Residential
        } else {
            Exit::Firewall
        },
        exit_country: r.get(8)?,
        priority: r.get(9)?,
        enabled: r.get(10)?,
        vm_id: r.get(11)?,
        ai_review: r.get(12)?,
        ai_policy: r.get(13)?,
        created_at: iso(created),
        updated_at: iso(r.get::<_, Option<i64>>(15)?.unwrap_or(created)),
        managed: None,
    })
}

/// A managed rule (`plane::managed_rules`) as the list shows it.
fn managed_row(r: &Value) -> EgressRule {
    let s = |k: &str| r.get(k).and_then(Value::as_str).map(str::to_string);
    EgressRule {
        id: s("id").unwrap_or_default(),
        name: s("name").unwrap_or_default(),
        match_domain: s("match_domain").unwrap_or_default(),
        match_path: s("match_path"),
        match_method: None,
        match_port: None,
        effect: Effect::Allow,
        exit: Exit::Firewall,
        exit_country: None,
        priority: r.get("priority").and_then(Value::as_i64).unwrap_or_default(),
        enabled: true,
        vm_id: s("vm_id"),
        ai_review: false,
        ai_policy: None,
        created_at: iso(0),
        updated_at: iso(0),
        managed: s(cc_contracts::managed::FIELD),
    }
}

/// The rules in order: the managed ones first, then the admin's. "Every other site" is not one of
/// them (`/api/egress/default`).
pub fn list(db: &Db) -> rusqlite::Result<Vec<EgressRule>> {
    let c = db.lock();
    let mut out: Vec<EgressRule> = crate::plane::managed_rules(&c)?.iter().map(managed_row).collect();
    let mut q = c.prepare(&format!(
        "SELECT {COLUMNS} FROM egress_rules WHERE id <> ?1 ORDER BY priority, created_at, rowid"
    ))?;
    for r in q.query_map([BLOCK_ALL_ID], row)? {
        out.push(r?);
    }
    Ok(out)
}

/// A rule the firewall keeps by itself, refused here as the SaaS refuses the brain's.
fn locked(id: &str) -> Result<()> {
    if id.starts_with(cc_contracts::managed::ID_PREFIX) {
        return Err(Reply::error(
            403,
            "This rule was added for a model key or a bot, and goes when they do. It can't be changed or deleted.",
        ));
    }
    if id == BLOCK_ALL_ID {
        return Err(Reply::bad(
            "This is \"Every other site\": change it with PUT /api/egress/default.",
        ));
    }
    Ok(())
}

pub fn every_other_site(db: &Db) -> rusqlite::Result<EveryOtherSite> {
    let block = db
        .lock()
        .query_row("SELECT 1 FROM egress_rules WHERE id = ?1", [BLOCK_ALL_ID], |_| Ok(()))
        .optional()?
        .is_some();
    Ok(EveryOtherSite {
        effect: if block {
            DefaultEffect::Block
        } else {
            DefaultEffect::Allow
        },
    })
}

/// Block: the one rule after every other, `*` blocked. Allow: no such rule.
fn put_every_other_site(c: &Ctx, b: EveryOtherSite) -> Result {
    {
        let db = c.db.lock();
        match b.effect {
            DefaultEffect::Block => db.execute(
                "INSERT OR REPLACE INTO egress_rules (id, name, match_domain, effect, priority, enabled, created_at, updated_at)
                 VALUES (?1, ?2, '*', 'block', ?3, 1, ?4, ?4)",
                params![BLOCK_ALL_ID, BLOCK_ALL_NAME, BLOCK_ALL_PRIORITY, now_s()],
            )?,
            DefaultEffect::Allow => db.execute("DELETE FROM egress_rules WHERE id = ?1", [BLOCK_ALL_ID])?,
        };
    }
    (c.hooks.rules_changed)();
    Ok(Reply::ok(&every_other_site(&c.db)?))
}

fn get(db: &Db, id: &str) -> rusqlite::Result<Option<EgressRule>> {
    db.lock()
        .query_row(&format!("SELECT {COLUMNS} FROM egress_rules WHERE id = ?1"), [id], row)
        .optional()
}

fn text(name: &str, v: &str, min: usize, max: usize) -> Result<()> {
    let n = v.chars().count();
    if n < min || n > max {
        return Err(Reply::bad(if min > 0 {
            format!("{name}: {min} to {max} characters")
        } else {
            format!("{name}: at most {max} characters")
        }));
    }
    Ok(())
}

fn country(v: Option<&str>) -> Result<Option<String>> {
    let Some(v) = v.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    if v.len() != 2 || !v.bytes().all(|b| b.is_ascii_alphabetic()) {
        return Err(Reply::bad(
            "exitCountry: a two-letter country code, or empty for any country",
        ));
    }
    Ok(Some(v.to_ascii_uppercase()))
}

/// `*`, `host` or `*.parent` covers `host`.
fn covers(rule: &str, host: &str) -> bool {
    let rule = rule.to_ascii_lowercase();
    rule == "*"
        || rule == host
        || rule
            .strip_prefix("*.")
            .is_some_and(|p| host.ends_with(&format!(".{p}")) || host == p)
}

/// A residential exit asked for: only on an allow or tunnel rule, and not over a host where the
/// firewall puts in a key it holds.
fn check_residential(db: &Db, effect: Effect, domain: &str) -> Result<()> {
    if !effect.relayable() {
        return Err(Reply::bad("A residential exit is only for allow and tunnel rules."));
    }
    if let Some(h) = super::llm::swap_hosts(db)?.into_iter().find(|h| covers(domain, h)) {
        return Err(Reply::bad(format!(
            "{h} gets a model key from this firewall; it cannot leave through the residential exit, which the firewall cannot read."
        )));
    }
    Ok(())
}

fn check_vm(db: &Db, vm: Option<&str>) -> Result<()> {
    let Some(vm) = vm else { return Ok(()) };
    let known = db
        .lock()
        .query_row(
            "SELECT 1 FROM agents WHERE vm_id = ?1 AND role IN ('openclaw', 'gbrain')",
            [vm],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if known { Ok(()) } else { Err(Reply::not_found("Agent")) }
}

/// What a rule becomes once the SaaS's invariants are applied: a port only on a tunnel rule, a
/// residential exit only where traffic goes out, AI review only on a rule the firewall inspects,
/// and the AI note only under review.
struct Settled {
    match_port: Option<i64>,
    exit: Exit,
    ai_review: bool,
    ai_policy: Option<String>,
}

fn settle(effect: Effect, port: Option<i64>, exit: Exit, ai_review: bool, ai_policy: Option<String>) -> Settled {
    let exit = if exit == Exit::Residential && effect.relayable() {
        Exit::Residential
    } else {
        Exit::Firewall
    };
    let ai_review = ai_review && effect.reviewable() && exit == Exit::Firewall;
    Settled {
        match_port: if effect == Effect::Tunnel { port } else { None },
        exit,
        ai_review,
        ai_policy: ai_policy
            .filter(|_| ai_review)
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty()),
    }
}

fn check_fields(
    name: Option<&str>,
    domain: Option<&str>,
    path: Option<&str>,
    port: Option<i64>,
    priority: Option<i64>,
    policy: Option<&str>,
) -> Result<()> {
    if let Some(v) = name {
        text("name", v, 1, 120)?;
    }
    if let Some(v) = domain {
        text("matchDomain", v, 1, 253)?;
    }
    if let Some(v) = path {
        text("matchPath", v, 0, 512)?;
    }
    if port.is_some_and(|p| !(1..=65535).contains(&p)) {
        return Err(Reply::bad("matchPort: 1 to 65535"));
    }
    if priority.is_some_and(|p| !(0..=1_000_000).contains(&p)) {
        return Err(Reply::bad("priority: 0 to 1000000"));
    }
    if let Some(v) = policy {
        text("aiPolicy", v.trim(), 0, 1000)?;
    }
    Ok(())
}

/// A rule in the whole-list form (`PUT /api/egress-rules`, snake_case) with the checks and the
/// settling a rule added one at a time gets; the reason when it does not pass.
pub fn settle_legacy(db: &Db, r: &Value) -> std::result::Result<Value, String> {
    let s = |k: &str| r.get(k).and_then(Value::as_str).filter(|v| !v.is_empty());
    let err = |e: Reply| e.body["error"].as_str().unwrap_or("not valid").to_string();
    let domain = s("match_domain").ok_or("match_domain is required")?;
    let effect: Effect = match s("effect") {
        None => Effect::Allow,
        Some(e) => {
            serde_json::from_value(json!(e)).map_err(|_| "effect is allow, block, require_permission or tunnel")?
        }
    };
    if let Some(m) = s("match_method") {
        serde_json::from_value::<HttpMethod>(json!(m))
            .map_err(|_| "match_method: GET, POST, PUT, PATCH, DELETE, HEAD or OPTIONS")?;
    }
    let port = r.get("match_port").and_then(Value::as_i64);
    let priority = r.get("priority").and_then(Value::as_i64);
    check_fields(
        Some(s("name").unwrap_or(domain)),
        Some(domain),
        s("match_path"),
        port,
        priority,
        s("ai_policy"),
    )
    .map_err(err)?;
    check_vm(db, s("vm_id")).map_err(err)?;
    let exit = if s("exit") == Some("residential") {
        Exit::Residential
    } else {
        Exit::Firewall
    };
    if exit == Exit::Residential {
        check_residential(db, effect, domain).map_err(err)?;
    }
    let st = settle(
        effect,
        port,
        exit,
        r.get("ai_review").and_then(Value::as_bool).unwrap_or(false),
        s("ai_policy").map(str::to_string),
    );
    let mut out = r.clone();
    out["match_port"] = json!(st.match_port);
    out["ai_review"] = json!(st.ai_review);
    out["ai_policy"] = json!(st.ai_policy);
    out["exit"] = json!(if st.exit == Exit::Residential {
        "residential"
    } else {
        "firewall"
    });
    out["exit_country"] = json!(country(s("exit_country")).map_err(err)?);
    Ok(out)
}

fn method_str(m: Option<HttpMethod>) -> Option<String> {
    m.and_then(|m| serde_json::to_value(m).ok()?.as_str().map(str::to_string))
}

fn create(c: &Ctx, b: NewEgressRule) -> Result {
    check_fields(
        Some(&b.name),
        Some(&b.match_domain),
        b.match_path.as_deref(),
        b.match_port,
        Some(b.priority),
        b.ai_policy.as_deref(),
    )?;
    let exit_country = country(b.exit_country.as_deref())?;
    check_vm(&c.db, b.vm_id.as_deref())?;
    if b.exit == Exit::Residential {
        check_residential(&c.db, b.effect, &b.match_domain)?;
    }
    let s = settle(b.effect, b.match_port, b.exit, b.ai_review, b.ai_policy);
    let id = new_id("r");
    let now = now_s();
    c.db.lock().execute(
        "INSERT INTO egress_rules (id, name, match_domain, match_path, match_method, match_port, vm_id, effect, exit,
                                   exit_country, priority, enabled, ai_review, ai_policy, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?15)",
        params![
            id,
            b.name,
            b.match_domain,
            b.match_path.filter(|p| !p.is_empty()),
            method_str(b.match_method),
            s.match_port,
            b.vm_id,
            b.effect.as_str(),
            (s.exit == Exit::Residential).then_some("residential"),
            exit_country,
            b.priority,
            b.enabled,
            s.ai_review,
            s.ai_policy,
            now
        ],
    )?;
    (c.hooks.rules_changed)();
    Ok(Reply::ok(&get(&c.db, &id)?))
}

fn update(c: &Ctx, p: EgressRulePatch) -> Result {
    locked(c.param("id"))?;
    let Some(cur) = get(&c.db, c.param("id"))? else {
        return Err(Reply::not_found("Egress rule"));
    };
    check_fields(
        p.name.as_deref(),
        p.match_domain.as_deref(),
        p.match_path.as_ref().and_then(Option::as_deref),
        p.match_port.flatten(),
        p.priority,
        p.ai_policy.as_ref().and_then(Option::as_deref),
    )?;
    let exit_country = match &p.exit_country {
        Some(v) => country(v.as_deref())?,
        None => cur.exit_country.clone(),
    };
    let vm_id = p.vm_id.clone().unwrap_or(cur.vm_id.clone());
    if p.vm_id.is_some() {
        check_vm(&c.db, vm_id.as_deref())?;
    }
    let effect = p.effect.unwrap_or(cur.effect);
    let exit = p.exit.unwrap_or(cur.exit);
    // Judged on what the rule becomes, when the exit or the domain is what changes; a new effect
    // that cannot relay puts the rule back on the firewall, as the SaaS does.
    if exit == Exit::Residential && (p.exit.is_some() || p.match_domain.is_some()) {
        check_residential(&c.db, effect, p.match_domain.as_deref().unwrap_or(&cur.match_domain))?;
    }
    let review = p.ai_review.unwrap_or(cur.ai_review);
    // A note written for one effect is never carried to another unless a new one comes with it.
    let policy = match &p.ai_policy {
        Some(v) => v.clone(),
        None if effect != cur.effect => None,
        None => cur.ai_policy.clone(),
    };
    let s = settle(effect, p.match_port.unwrap_or(cur.match_port), exit, review, policy);
    let method = match p.match_method {
        Some(m) => method_str(m),
        None => cur.match_method.clone(),
    };
    let path = match p.match_path {
        Some(v) => v.filter(|v| !v.is_empty()),
        None => cur.match_path.clone(),
    };
    c.db.lock().execute(
        "UPDATE egress_rules SET name = ?2, match_domain = ?3, match_path = ?4, match_method = ?5, match_port = ?6,
                vm_id = ?7, effect = ?8, exit = ?9, exit_country = ?10, priority = ?11, enabled = ?12,
                ai_review = ?13, ai_policy = ?14, updated_at = ?15
         WHERE id = ?1",
        params![
            cur.id,
            p.name.unwrap_or(cur.name.clone()),
            p.match_domain.unwrap_or(cur.match_domain.clone()),
            path,
            method,
            s.match_port,
            vm_id,
            effect.as_str(),
            (s.exit == Exit::Residential).then_some("residential"),
            exit_country,
            p.priority.unwrap_or(cur.priority),
            p.enabled.unwrap_or(cur.enabled),
            s.ai_review,
            s.ai_policy,
            now_s()
        ],
    )?;
    (c.hooks.rules_changed)();
    Ok(Reply::ok(&get(&c.db, &cur.id)?))
}

/// allow → ask → block → allow; a tunnel rule goes back to allow. Never into `tunnel`.
fn cycle(c: &Ctx) -> Result {
    locked(c.param("id"))?;
    let Some(cur) = get(&c.db, c.param("id"))? else {
        return Err(Reply::not_found("Egress rule"));
    };
    let next = match cur.effect {
        Effect::Allow => Effect::RequirePermission,
        Effect::RequirePermission => Effect::Block,
        Effect::Block | Effect::Tunnel => Effect::Allow,
    };
    let s = settle(next, None, cur.exit, cur.ai_review, None);
    c.db.lock().execute(
        "UPDATE egress_rules SET effect = ?2, exit = ?3, match_port = NULL, ai_review = ?4, ai_policy = NULL, updated_at = ?5
         WHERE id = ?1",
        params![
            cur.id,
            next.as_str(),
            (s.exit == Exit::Residential).then_some("residential"),
            s.ai_review,
            now_s()
        ],
    )?;
    (c.hooks.rules_changed)();
    Ok(Reply::ok(&get(&c.db, &cur.id)?))
}

// ---- AI review ----

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AiSettings {
    /// The AI firewall: the check on each request, AI approval, and the content rules' AI.
    pub enabled: bool,
    /// AI log review: the review every minute and the scan.
    pub log_review_enabled: bool,
    /// The model key it uses (`GET /api/llm/keys`).
    pub credential_id: Option<String>,
    pub model: String,
    pub daily_call_cap: i64,
    pub scan_interval_hours: i64,
    pub auto_approve_per_hour: i64,
    pub request_instructions: Option<String>,
    pub review_instructions: Option<String>,
}

impl Default for AiSettings {
    /// The SaaS's column defaults.
    fn default() -> Self {
        Self {
            enabled: false,
            log_review_enabled: true,
            credential_id: None,
            model: "typesafe-ai/jev".into(),
            daily_call_cap: 5000,
            scan_interval_hours: 6,
            auto_approve_per_hour: 30,
            request_instructions: None,
            review_instructions: None,
        }
    }
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AiView {
    pub settings: AiSettings,
    /// The model keys the review can use.
    pub credentials: Vec<AiCredential>,
    /// The firewall has the settings: on, with a key it holds.
    pub active: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AiCredential {
    pub id: String,
    pub provider: String,
    pub name: String,
    pub hint: String,
    pub default_model: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AiSettingsInput {
    pub enabled: bool,
    /// Left out: unchanged.
    #[serde(default)]
    pub log_review_enabled: Option<bool>,
    pub credential_id: Option<String>,
    /// 1 to 100 characters.
    pub model: String,
    /// 100 to 100000.
    pub daily_call_cap: i64,
    /// 1 to 168.
    pub scan_interval_hours: i64,
    /// 0 to 1000.
    pub auto_approve_per_hour: i64,
    /// Left out: unchanged; `null` or empty: none. At most 2000 characters.
    #[serde(default, deserialize_with = "some")]
    pub request_instructions: Option<Option<String>>,
    #[serde(default, deserialize_with = "some")]
    pub review_instructions: Option<Option<String>>,
}

fn ai_settings(db: &Db) -> AiSettings {
    db.setting(AI_KEY)
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn credentials(db: &Db) -> rusqlite::Result<Vec<AiCredential>> {
    Ok(super::llm::list(db)?
        .keys
        .into_iter()
        .filter(|k| k.state == "active")
        .filter_map(|k| {
            let p = super::llm::provider(&k.provider)?;
            Some(AiCredential {
                id: k.id,
                provider: k.provider,
                name: p.name.into(),
                hint: k.hint,
                default_model: p.review_model?.into(),
            })
        })
        .collect())
}

fn ai_view(db: &Db) -> rusqlite::Result<AiView> {
    let active = db
        .lock()
        .query_row("SELECT settings FROM ai_settings WHERE id = 1", [], |r| {
            r.get::<_, String>(0)
        })
        .optional()?
        .is_some_and(|s| s != "null");
    Ok(AiView {
        settings: ai_settings(db),
        credentials: credentials(db)?,
        active,
    })
}

/// The AI review's check on each request is on (the content rules' AI needs it).
pub fn ai_checks_on(db: &Db) -> bool {
    let s = ai_settings(db);
    s.enabled && credentials(db).is_ok_and(|k| k.iter().any(|k| Some(&k.id) == s.credential_id.as_ref()))
}

/// What the firewall reads as `ai` from `/egress-rules`, as the SaaS's `firewallAiSettings`:
/// nothing unless a part is on and its key is one the firewall holds.
pub fn sync_ai(db: &Db) -> rusqlite::Result<()> {
    let s = ai_settings(db);
    let key = credentials(db)?
        .into_iter()
        .find(|k| Some(&k.id) == s.credential_id.as_ref());
    let ai = match key {
        Some(k) if s.enabled || s.log_review_enabled => json!({
            "credential_id": k.id,
            "provider": k.provider,
            "model": s.model,
            "checks": s.enabled,
            "log_review": s.log_review_enabled,
            "daily_call_cap": s.daily_call_cap,
            "scan_interval_hours": s.scan_interval_hours,
            "auto_approve_per_hour": s.auto_approve_per_hour,
            "request_instructions": s.request_instructions,
            "review_instructions": s.review_instructions,
        }),
        _ => Value::Null,
    };
    db.lock().execute(
        "INSERT INTO ai_settings (id, settings) VALUES (1, ?1) ON CONFLICT (id) DO UPDATE SET settings = excluded.settings",
        [ai.to_string()],
    )?;
    Ok(())
}

fn instructions(v: Option<Option<String>>, cur: Option<String>) -> Result<Option<String>> {
    match v {
        None => Ok(cur),
        Some(v) => {
            let v = v.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
            if v.as_ref().is_some_and(|s| s.chars().count() > INSTRUCTIONS_MAX) {
                return Err(Reply::bad(format!(
                    "instructions: at most {INSTRUCTIONS_MAX} characters"
                )));
            }
            Ok(v)
        }
    }
}

fn put_ai(c: &Ctx, b: AiSettingsInput) -> Result {
    let cur = ai_settings(&c.db);
    let model = b.model.trim().to_string();
    text("model", &model, 1, 100)?;
    if !(100..=100_000).contains(&b.daily_call_cap) {
        return Err(Reply::bad("dailyCallCap: 100 to 100000"));
    }
    if !(1..=168).contains(&b.scan_interval_hours) {
        return Err(Reply::bad("scanIntervalHours: 1 to 168"));
    }
    if !(0..=1000).contains(&b.auto_approve_per_hour) {
        return Err(Reply::bad("autoApprovePerHour: 0 to 1000"));
    }
    let log_review = b.log_review_enabled.unwrap_or(cur.log_review_enabled);
    if let Some(id) = &b.credential_id
        && !credentials(&c.db)?.iter().any(|k| &k.id == id)
    {
        return Err(Reply::bad(
            "credentialId: a model key the AI review can use (GET /api/llm/keys)",
        ));
    }
    if b.enabled && b.credential_id.is_none() {
        return Err(Reply::bad("Add a model key and pick it first."));
    }
    let next = AiSettings {
        enabled: b.enabled,
        log_review_enabled: log_review,
        credential_id: b.credential_id,
        model,
        daily_call_cap: b.daily_call_cap,
        scan_interval_hours: b.scan_interval_hours,
        auto_approve_per_hour: b.auto_approve_per_hour,
        request_instructions: instructions(b.request_instructions, cur.request_instructions)?,
        review_instructions: instructions(b.review_instructions, cur.review_instructions)?,
    };
    c.db.set_setting(AI_KEY, &serde_json::to_string(&next).unwrap_or_default())?;
    sync_ai(&c.db)?;
    (c.hooks.rules_changed)();
    Ok(Reply::ok(&ai_view(&c.db)?))
}
