//! Integrations rules, called Apps rules before T-179 (`apps-rules-schema.ts`): what an agent may
//! do through the organization's app connections and in any remote MCP server. One ordered list
//! per organization, held on the firewall and read by the connector gate on every call. The first
//! enabled rule that matches decides; when none does, the call is allowed and recorded.
//!
//! The TS checks shapes with zod (`appRule`, `appRulesChange`); [`parse_rule`] and
//! [`parse_change`] refuse the same things.

use std::sync::LazyLock;

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const APP_RULES_MAX: usize = 100;
pub const APP_RULE_ACTIONS_MAX: usize = 50;
pub const APP_RULE_AGENTS_MAX: usize = 50;
pub const APP_RULE_TOOLS_MAX: usize = 50;
/// The rule as one sentence, judged by the AI against the call.
pub const RULE_SENTENCE_MAX: usize = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AppEffect {
    Block,
    Ask,
    Allow,
}

impl AppEffect {
    /// Strictest to loosest.
    fn rank(self) -> u8 {
        match self {
            AppEffect::Block => 0,
            AppEffect::Ask => 1,
            AppEffect::Allow => 2,
        }
    }

    fn words(self) -> &'static str {
        match self {
            AppEffect::Allow => "allows",
            AppEffect::Ask => "asks a person before",
            AppEffect::Block => "blocks",
        }
    }
}

/// OpenConnector's own word for what an action does to the provider (`operationType`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AppOperation {
    Read,
    Write,
    Destructive,
}

impl AppOperation {
    pub fn parse(v: &str) -> Option<Self> {
        match v {
            "read" => Some(Self::Read),
            "write" => Some(Self::Write),
            "destructive" => Some(Self::Destructive),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Destructive => "destructive",
        }
    }

    fn words(self) -> &'static str {
        match self {
            Self::Read => "reading",
            Self::Write => "changing",
            Self::Destructive => "deleting",
        }
    }
}

pub const PROXY_METHODS: &[&str] = &["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"];

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum AppMatch {
    Any,
    Actions {
        actions: Vec<String>,
    },
    Operation {
        operations: Vec<AppOperation>,
    },
    Proxy {
        method: Option<String>,
        path: Option<String>,
    },
    /// MCP tools by name.
    Tools {
        tools: Vec<String>,
    },
}

/// One rule, its fields in the order the TS writes them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppRule {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    /// Empty: every agent.
    pub agents: Vec<String>,
    /// None: any app.
    pub service: Option<String>,
    /// OpenConnector's connection id, of `service`. None: any connection of it.
    pub connection_id: Option<String>,
    #[serde(rename = "match")]
    pub match_: AppMatch,
    pub then: AppEffect,
    /// Optional: the AI judges whether the call fits it, and the rule acts only when it does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sentence: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AppRulesChange {
    /// A new rule (at `at`, else last), or a rule replaced in place.
    Put {
        rule: AppRule,
        at: Option<usize>,
    },
    Delete {
        id: String,
    },
    Move {
        id: String,
        to: usize,
    },
}

/// The seeded rule's name before T-179; a firewall that finds it unchanged renames it.
pub const SEEDED_APP_RULE_OLD_NAME: &str = "Ask before destructive app actions";

/// Every organization starts with this one (owner decision, 2026-10-25). It only narrows.
pub fn seeded_app_rule() -> AppRule {
    AppRule {
        id: "ask-destructive".into(),
        name: "Ask before destructive integration actions".into(),
        enabled: true,
        agents: vec![],
        service: None,
        connection_id: None,
        match_: AppMatch::Operation {
            operations: vec![AppOperation::Destructive],
        },
        then: AppEffect::Ask,
        sentence: None,
    }
}

/// One call as the gate read it.
#[derive(Debug, Clone, PartialEq)]
pub struct AppCall {
    pub vm_id: String,
    pub service: String,
    /// None when the call names no connection the gate could pin down; see [`decide_app`].
    pub connection_id: Option<String>,
    /// Execute calls.
    pub action_id: Option<String>,
    pub operation: Option<AppOperation>,
    /// Proxy calls: the method and the path without its query.
    pub proxy: Option<ProxyCall>,
    /// MCP calls (`service` is `mcp:<host>`): the tool.
    pub tool: Option<String>,
    /// The call's input or arguments: only for judging a rule's sentence, never matched on.
    pub input: Value,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProxyCall {
    pub method: String,
    pub path: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Judged {
    Fits,
    Unavailable,
}

/// `judged`: the rule had a sentence, and how the AI answered (or that it could not).
#[derive(Debug, Clone, PartialEq)]
pub struct AppDecision {
    pub then: AppEffect,
    pub rule: Option<AppRule>,
    pub judged: Option<Judged>,
}

impl AppDecision {
    fn allow() -> Self {
        Self {
            then: AppEffect::Allow,
            rule: None,
            judged: None,
        }
    }
}

/// What the AI says about a rule's sentence for a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fit {
    Fits,
    No,
    Unavailable,
}

/// Whether a call fits a rule's sentence (`SentenceJudge`). Only asked for a rule whose fields match.
pub type SentenceJudge<'a> = &'a (dyn Fn(&AppRule, &AppCall) -> cc_http::BoxFuture<Fit> + Send + Sync);

fn re(s: &str) -> Regex {
    Regex::new(s).expect("a fixed pattern")
}

static PLAIN_LINE: LazyLock<Regex> = LazyLock::new(|| re(r"^[^\p{Cc}\p{Cf}\p{Co}\p{Cn}\p{Zl}\p{Zp}]+$"));
static RULE_ID: LazyLock<Regex> = LazyLock::new(|| re(r"^[a-z0-9][a-z0-9-]{0,63}$"));
/// OpenConnector's service ids (`connectors.ts` `SERVICE_RE`).
pub static CONNECTOR_SERVICE: LazyLock<Regex> = LazyLock::new(|| re(r"^[a-z0-9][a-z0-9_]{0,60}$"));
/// An MCP server, by host: `mcp:mcp.deepwiki.com`.
pub static MCP_SERVICE: LazyLock<Regex> =
    LazyLock::new(|| re(r"^mcp:[a-z0-9](?:[a-z0-9-]{0,62}\.)*[a-z0-9-]{1,63}(?::\d{1,5})?$"));
static TOOL_PATTERN: LazyLock<Regex> = LazyLock::new(|| re(r"^[A-Za-z0-9_.:/*-]{1,128}$"));
/// `github.create_issue`, or with `*` for any run of characters.
static ACTION_PATTERN: LazyLock<Regex> = LazyLock::new(|| re(r"^[a-z0-9_*][a-z0-9_*]{0,60}\.[A-Za-z0-9_.*-]{1,120}$"));
static PROXY_PATH: LazyLock<Regex> = LazyLock::new(|| re(r"^/[^\s?#\\]*$"));

/// `PLAIN_LINE`: one line, no control or format characters, no leading, trailing or doubled space.
pub fn plain_line(s: &str) -> bool {
    !s.starts_with(' ') && !s.ends_with(' ') && !s.contains("  ") && PLAIN_LINE.is_match(s)
}

pub fn is_mcp_service(service: Option<&str>) -> bool {
    service.is_some_and(|s| s.starts_with("mcp:"))
}

/// `serviceId`: an app's id or `mcp:<host>`.
pub fn service_id_ok(s: &str) -> bool {
    s.encode_utf16().count() <= 270 && (CONNECTOR_SERVICE.is_match(s) || MCP_SERVICE.is_match(s))
}

/// A proxy call's kind, from its method.
pub fn proxy_operation(method: &str) -> AppOperation {
    match method.to_uppercase().as_str() {
        "GET" | "HEAD" => AppOperation::Read,
        "DELETE" => AppOperation::Destructive,
        _ => AppOperation::Write,
    }
}

/// What a call does, for an operation rule. An action the catalog gives no kind counts as
/// destructive: a rule that asks before deleting must not be stepped around by an action nobody
/// labelled.
pub fn operation_of(call: &AppCall) -> AppOperation {
    call.operation.unwrap_or_else(|| {
        call.proxy
            .as_ref()
            .map(|p| proxy_operation(&p.method))
            .unwrap_or(AppOperation::Destructive)
    })
}

/// Whether a (decoded) provider path is at or under a rule's path, segment by segment and
/// ignoring case: `/repos` covers `/repos` and `/repos/a`, not `/repos-archive`.
pub fn path_under(path: &str, prefix: &str) -> bool {
    let p = path.to_lowercase();
    let r = prefix.to_lowercase();
    if r == "/" || p == r || p == r.trim_end_matches('/') {
        return true;
    }
    if r.ends_with('/') {
        p.starts_with(&r)
    } else {
        p.starts_with(&format!("{r}/"))
    }
}

/// `*` is any run of characters (the TS builds `.*` from it).
pub fn glob_match(pattern: &str, value: &str) -> bool {
    if !pattern.contains('*') {
        return pattern == value;
    }
    let parts: Vec<String> = pattern.split('*').map(regex::escape).collect();
    Regex::new(&format!("^{}$", parts.join(".*"))).is_ok_and(|r| r.is_match(value))
}

pub fn rule_matches(rule: &AppRule, call: &AppCall) -> bool {
    if !rule.enabled {
        return false;
    }
    if !rule.agents.is_empty() && !rule.agents.contains(&call.vm_id) {
        return false;
    }
    if let Some(s) = &rule.service
        && *s != call.service
    {
        return false;
    }
    if let Some(c) = &rule.connection_id
        && Some(c) != call.connection_id.as_ref()
    {
        return false;
    }
    match &rule.match_ {
        AppMatch::Any => true,
        AppMatch::Actions { actions } => match &call.action_id {
            // An app's direct API calls can do what its actions do. A rule that asks or blocks
            // actions of one app covers that app's direct calls too; an allow never lets them through.
            None => {
                call.proxy.is_some()
                    && rule.service.as_deref() == Some(call.service.as_str())
                    && rule.then != AppEffect::Allow
            }
            Some(id) => actions.iter().any(|p| glob_match(p, id)),
        },
        AppMatch::Operation { operations } => operations.contains(&operation_of(call)),
        AppMatch::Proxy { method, path } => call.proxy.as_ref().is_some_and(|p| {
            method.as_ref().is_none_or(|m| *m == p.method.to_uppercase())
                && path.as_ref().is_none_or(|r| path_under(&p.path, r))
        }),
        AppMatch::Tools { tools } => call
            .tool
            .as_ref()
            .is_some_and(|t| !t.is_empty() && tools.iter().any(|p| glob_match(p, t))),
    }
}

/// A rule with a sentence that nobody could judge acts with the stricter of its own action and Ask.
fn sentence_unjudged(rule: &AppRule) -> AppDecision {
    AppDecision {
        then: if rule.then.rank() <= AppEffect::Ask.rank() {
            rule.then
        } else {
            AppEffect::Ask
        },
        rule: Some(rule.clone()),
        judged: Some(Judged::Unavailable),
    }
}

/// The rule that decides one call: the first enabled match, or the default (allow). A rule with a
/// sentence is passed over here: [`decide_one_judged`] asks about it.
pub fn decide_one(rules: &[AppRule], call: &AppCall) -> AppDecision {
    for rule in rules {
        if rule_matches(rule, call) {
            if rule.sentence.is_some() {
                return sentence_unjudged(rule);
            }
            return AppDecision {
                then: rule.then,
                rule: Some(rule.clone()),
                judged: None,
            };
        }
    }
    AppDecision::allow()
}

/// [`decide_one`], asking the AI about each rule with a sentence whose fields match.
pub async fn decide_one_judged(rules: &[AppRule], call: &AppCall, judge: Option<SentenceJudge<'_>>) -> AppDecision {
    for rule in rules {
        if !rule_matches(rule, call) {
            continue;
        }
        if rule.sentence.is_none() {
            return AppDecision {
                then: rule.then,
                rule: Some(rule.clone()),
                judged: None,
            };
        }
        let answer = match judge {
            Some(j) => j(rule, call).await,
            None => Fit::Unavailable,
        };
        match answer {
            Fit::Fits => {
                return AppDecision {
                    then: rule.then,
                    rule: Some(rule.clone()),
                    judged: Some(Judged::Fits),
                };
            }
            Fit::Unavailable => return sentence_unjudged(rule),
            Fit::No => {}
        }
    }
    AppDecision::allow()
}

fn candidates(call: &AppCall, connections: &[String]) -> Vec<AppCall> {
    if call.connection_id.is_some() || connections.is_empty() {
        return vec![call.clone()];
    }
    connections
        .iter()
        .map(|id| AppCall {
            connection_id: Some(id.clone()),
            ..call.clone()
        })
        .collect()
}

/// The decision for a call that may use any of `connections` (the agent's connections of that app
/// when it named none the gate can pin down): the strictest of them, so a rule on one connection
/// cannot be stepped around by leaving the name out.
pub fn decide_app(rules: &[AppRule], call: &AppCall, connections: &[String]) -> AppDecision {
    let mut worst: Option<AppDecision> = None;
    for c in candidates(call, connections) {
        let d = decide_one(rules, &c);
        if worst.as_ref().is_none_or(|w| d.then.rank() < w.then.rank()) {
            worst = Some(d);
        }
    }
    worst.unwrap_or_else(AppDecision::allow)
}

/// [`decide_app`] with sentences judged.
pub async fn decide_app_judged(
    rules: &[AppRule],
    call: &AppCall,
    connections: &[String],
    judge: Option<SentenceJudge<'_>>,
) -> AppDecision {
    let mut worst: Option<AppDecision> = None;
    for c in candidates(call, connections) {
        let d = decide_one_judged(rules, &c, judge).await;
        if worst.as_ref().is_none_or(|w| d.then.rank() < w.then.rank()) {
            worst = Some(d);
        }
    }
    worst.unwrap_or_else(AppDecision::allow)
}

pub fn apply_app_change(rules: &[AppRule], change: &AppRulesChange) -> Result<Vec<AppRule>, String> {
    match change {
        AppRulesChange::Delete { id } => {
            let i = rules.iter().position(|r| r.id == *id).ok_or("no such rule")?;
            Ok(rules
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, r)| r.clone())
                .collect())
        }
        AppRulesChange::Move { id, to } => {
            let i = rules.iter().position(|r| r.id == *id).ok_or("no such rule")?;
            let mut rest: Vec<AppRule> = rules
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, r)| r.clone())
                .collect();
            let at = (*to).min(rest.len());
            rest.insert(at, rules[i].clone());
            Ok(rest)
        }
        AppRulesChange::Put { rule, at } => {
            if let Some(i) = rules.iter().position(|r| r.id == rule.id) {
                let mut next = rules.to_vec();
                next[i] = rule.clone();
                return Ok(next);
            }
            if rules.len() >= APP_RULES_MAX {
                return Err("too many rules".into());
            }
            let mut next = rules.to_vec();
            let at = at.unwrap_or(next.len()).min(next.len());
            next.insert(at, rule.clone());
            Ok(next)
        }
    }
}

/// Whether every enabled rule in `list` passes `test`.
fn all(list: &[AppRule], test: impl Fn(&AppRule) -> bool) -> bool {
    list.iter().all(|r| !r.enabled || test(r))
}

/// A rule taken out: what it matched now falls to the rules below it and the default allow.
fn removal_widens(rule: &AppRule) -> bool {
    rule.enabled && rule.then != AppEffect::Allow
}

/// A rule put in: what it matches now gets its effect instead of what the rules below gave.
fn insertion_widens(rule: &AppRule, below: &[AppRule]) -> bool {
    rule.enabled && !all(below, |r| r.then.rank() >= rule.then.rank())
}

fn same_scope(a: &AppRule, b: &AppRule) -> bool {
    a.agents == b.agents && a.service == b.service && a.connection_id == b.connection_id && a.match_ == b.match_
}

/// A sentence change (owner, 2026-10-25): any edit counts as letting more through, except taking
/// the sentence off a Block or Ask rule, which only makes it stop or ask about more.
fn sentence_widens(old: &AppRule, next: &AppRule) -> bool {
    if old.sentence == next.sentence {
        return false;
    }
    !(next.sentence.is_none() && next.then != AppEffect::Allow && old.then == next.then)
}

/// Whether a change lets any call through that was stopped or asked before (block → ask → allow).
/// Those changes need the firewall's code; a change that only narrows applies at once. Decided per
/// change, conservatively: a change that might widen counts as widening.
pub fn widens(rules: &[AppRule], change: &AppRulesChange) -> bool {
    match change {
        AppRulesChange::Delete { id } => rules.iter().find(|r| r.id == *id).is_some_and(removal_widens),
        AppRulesChange::Move { id, to } => {
            let Some(i) = rules.iter().position(|r| r.id == *id) else {
                return false;
            };
            let rule = &rules[i];
            if !rule.enabled {
                return false;
            }
            let rest: Vec<AppRule> = rules
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, r)| r.clone())
                .collect();
            let to = (*to).min(rest.len());
            // Up: what it shares with the rules it passes now gets its effect. Down: theirs.
            if to < i {
                return !all(&rest[to..i], |r| r.then.rank() >= rule.then.rank());
            }
            // `rest.slice(i, to)` is empty when `to <= i`.
            let span = if i < to { &rest[i..to] } else { &rest[0..0] };
            !all(span, |r| r.then.rank() <= rule.then.rank())
        }
        AppRulesChange::Put { rule: next, at } => {
            let Some(i) = rules.iter().position(|r| r.id == next.id) else {
                let at = at.unwrap_or(rules.len()).min(rules.len());
                return insertion_widens(next, &rules[at..]);
            };
            let old = &rules[i];
            let below = &rules[i + 1..];
            if old.enabled && next.enabled && sentence_widens(old, next) {
                return true;
            }
            // A rename, or the same calls answered more strictly.
            if same_scope(old, next) && (!old.enabled || next.enabled) && next.then.rank() <= old.then.rank() {
                return if old.enabled {
                    false
                } else {
                    insertion_widens(next, below)
                };
            }
            removal_widens(old) || insertion_widens(next, below)
        }
    }
}

/// What a rule covers, in words: from the rule's enums and ids only.
pub fn describe_match(rule: &AppRule, app_name: Option<&str>) -> String {
    let app = match &rule.service {
        Some(s) => app_name.map(str::to_string).unwrap_or_else(|| {
            if is_mcp_service(Some(s)) {
                format!("the MCP server {}", &s[4..])
            } else {
                s.clone()
            }
        }),
        None => "any integration".into(),
    };
    match &rule.match_ {
        AppMatch::Any => format!("every call to {app}"),
        AppMatch::Actions { actions } => {
            let what = if actions.len() == 1 {
                actions[0].clone()
            } else {
                format!("{} actions", actions.len())
            };
            format!("{what} in {app}")
        }
        AppMatch::Operation { operations } => {
            let ops: Vec<&str> = operations.iter().map(|o| o.words()).collect();
            format!("{} in {app}", ops.join(" or "))
        }
        AppMatch::Proxy { method, path } => format!(
            "direct {} calls{} in {app}",
            method.as_deref().unwrap_or("API"),
            path.as_ref().map(|p| format!(" to {p}")).unwrap_or_default()
        ),
        AppMatch::Tools { tools } => {
            let what = if tools.len() == 1 {
                format!("the tool {}", tools[0])
            } else {
                format!("{} tools", tools.len())
            };
            format!("{what} in {app}")
        }
    }
}

/// The one line a person reads next to the code. Written on the firewall, never by the console.
pub fn describe_app_change(change: &AppRulesChange, rules: &[AppRule]) -> String {
    match change {
        AppRulesChange::Delete { id } => match rules.iter().find(|r| r.id == *id) {
            Some(old) => format!(
                "Delete the integration rule that {} {}",
                old.then.words(),
                describe_match(old, None)
            ),
            None => "Delete an integration rule".into(),
        },
        AppRulesChange::Move { id, to } => {
            let that = rules
                .iter()
                .find(|r| r.id == *id)
                .map(|old| format!("that {} {} ", old.then.words(), describe_match(old, None)))
                .unwrap_or_default();
            format!("Move the integration rule {that}to position {}", to + 1)
        }
        AppRulesChange::Put { rule: r, .. } => {
            let old = rules.iter().find(|x| x.id == r.id);
            let who = match r.agents.len() {
                0 => "all agents".to_string(),
                1 => "one agent".to_string(),
                n => format!("{n} agents"),
            };
            // The sentence is the owner's own words and part of what the code confirms: said in full.
            let sentence = match (&r.sentence, old.and_then(|o| o.sentence.as_ref())) {
                (Some(s), _) => format!(", when the call fits \"{s}\""),
                (None, Some(_)) => ", with no sentence".into(),
                (None, None) => String::new(),
            };
            format!(
                "{} an integration rule that {} {}{sentence}, for {who}{}",
                if old.is_some() { "Change" } else { "Add" },
                r.then.words(),
                describe_match(r, None),
                if r.enabled { "" } else { " (turned off)" }
            )
        }
    }
}

// ---- shapes, as zod checks them ----------------------------------------------------------------

fn bad<T>(what: &str) -> Result<T, String> {
    Err(format!("invalid {what}"))
}

fn strict_keys(o: &serde_json::Map<String, Value>, allowed: &[&str], what: &str) -> Result<(), String> {
    match o.keys().find(|k| !allowed.contains(&k.as_str())) {
        Some(k) => Err(format!("invalid {what}: unknown key {k}")),
        None => Ok(()),
    }
}

fn string_list(v: Option<&Value>, max: usize, ok: impl Fn(&str) -> bool, what: &str) -> Result<Vec<String>, String> {
    let Some(Value::Array(a)) = v else { return bad(what) };
    if a.is_empty() || a.len() > max {
        return bad(what);
    }
    a.iter()
        .map(|x| match x.as_str() {
            Some(s) if ok(s) => Ok(s.to_string()),
            _ => bad(what),
        })
        .collect()
}

fn proxy_path_ok(p: &str) -> bool {
    p.encode_utf16().count() <= 300 && PROXY_PATH.is_match(p) && !p.split('/').any(|s| s == "." || s == "..")
}

fn parse_match(v: &Value) -> Result<AppMatch, String> {
    let Some(o) = v.as_object() else { return bad("match") };
    match o.get("kind").and_then(Value::as_str) {
        Some("any") => {
            strict_keys(o, &["kind"], "match")?;
            Ok(AppMatch::Any)
        }
        Some("actions") => {
            strict_keys(o, &["kind", "actions"], "match")?;
            Ok(AppMatch::Actions {
                actions: string_list(
                    o.get("actions"),
                    APP_RULE_ACTIONS_MAX,
                    |s| ACTION_PATTERN.is_match(s),
                    "match",
                )?,
            })
        }
        Some("operation") => {
            strict_keys(o, &["kind", "operations"], "match")?;
            let list = string_list(o.get("operations"), 3, |s| AppOperation::parse(s).is_some(), "match")?;
            Ok(AppMatch::Operation {
                operations: list.iter().filter_map(|s| AppOperation::parse(s)).collect(),
            })
        }
        Some("proxy") => {
            strict_keys(o, &["kind", "method", "path"], "match")?;
            let method = match o.get("method") {
                Some(Value::Null) => None,
                Some(Value::String(m)) if PROXY_METHODS.contains(&m.as_str()) => Some(m.clone()),
                _ => return bad("match"),
            };
            let path = match o.get("path") {
                Some(Value::Null) => None,
                Some(Value::String(p)) if proxy_path_ok(p) => Some(p.clone()),
                _ => return bad("match"),
            };
            Ok(AppMatch::Proxy { method, path })
        }
        Some("tools") => {
            strict_keys(o, &["kind", "tools"], "match")?;
            Ok(AppMatch::Tools {
                tools: string_list(
                    o.get("tools"),
                    APP_RULE_TOOLS_MAX,
                    |s| TOOL_PATTERN.is_match(s),
                    "match",
                )?,
            })
        }
        _ => bad("match"),
    }
}

/// `appRule.parse`: a rule as the console or the store sends it, refused when zod would refuse it.
pub fn parse_rule(v: &Value) -> Result<AppRule, String> {
    let Some(o) = v.as_object() else { return bad("rule") };
    strict_keys(
        o,
        &[
            "id",
            "name",
            "enabled",
            "agents",
            "service",
            "connectionId",
            "match",
            "then",
            "sentence",
        ],
        "rule",
    )?;
    let id = match o.get("id").and_then(Value::as_str) {
        Some(s) if RULE_ID.is_match(s) => s.to_string(),
        _ => return bad("rule id"),
    };
    let name = match o.get("name").and_then(Value::as_str) {
        Some(s) if (1..=80).contains(&s.encode_utf16().count()) && plain_line(s) => s.to_string(),
        _ => return bad("rule name"),
    };
    let Some(enabled) = o.get("enabled").and_then(Value::as_bool) else {
        return bad("rule");
    };
    let agents = match o.get("agents") {
        Some(Value::Array(a)) if a.len() <= APP_RULE_AGENTS_MAX => a
            .iter()
            .map(|x| match x.as_str() {
                Some(s) if (1..=100).contains(&s.encode_utf16().count()) => Ok(s.to_string()),
                _ => bad("rule agents"),
            })
            .collect::<Result<Vec<_>, _>>()?,
        _ => return bad("rule agents"),
    };
    if agents.iter().enumerate().any(|(i, a)| agents[..i].contains(a)) {
        return Err("an agent is listed twice".into());
    }
    let service = match o.get("service") {
        Some(Value::Null) => None,
        Some(Value::String(s)) if service_id_ok(s) => Some(s.clone()),
        _ => return Err("must be an app's id or mcp:<host>".into()),
    };
    let connection_id = match o.get("connectionId") {
        Some(Value::Null) => None,
        Some(Value::String(s)) if (1..=100).contains(&s.encode_utf16().count()) => Some(s.clone()),
        _ => return bad("rule connection"),
    };
    let match_ = parse_match(o.get("match").unwrap_or(&Value::Null))?;
    let then = match o.get("then").and_then(Value::as_str) {
        Some("block") => AppEffect::Block,
        Some("ask") => AppEffect::Ask,
        Some("allow") => AppEffect::Allow,
        _ => return bad("rule effect"),
    };
    let sentence = match o.get("sentence") {
        None => None,
        Some(Value::String(s)) if (3..=RULE_SENTENCE_MAX).contains(&s.encode_utf16().count()) && plain_line(s) => {
            Some(s.clone())
        }
        _ => return Err("must be one plain line".into()),
    };
    let rule = AppRule {
        id,
        name,
        enabled,
        agents,
        service,
        connection_id,
        match_,
        then,
        sentence,
    };
    if rule.connection_id.is_some() && rule.service.is_none() {
        return Err("a connection belongs to one app".into());
    }
    if rule.connection_id.is_some() && is_mcp_service(rule.service.as_deref()) {
        return Err("an MCP server has no connections".into());
    }
    let typed = matches!(
        rule.match_,
        AppMatch::Tools { .. } | AppMatch::Actions { .. } | AppMatch::Proxy { .. }
    );
    if typed
        && rule.service.is_some()
        && matches!(rule.match_, AppMatch::Tools { .. }) != is_mcp_service(rule.service.as_deref())
    {
        return Err("tools are an MCP server's; actions and direct calls are an app's".into());
    }
    if let (AppMatch::Actions { actions }, Some(s)) = (&rule.match_, &rule.service)
        && !actions
            .iter()
            .all(|a| a.starts_with(&format!("{s}.")) || a.starts_with("*."))
    {
        return Err("the actions must be the app's".into());
    }
    Ok(rule)
}

fn index(v: Option<&Value>, what: &str) -> Result<Option<usize>, String> {
    match v {
        None => Ok(None),
        Some(Value::Number(n)) => match n.as_u64() {
            Some(i) if i as usize <= APP_RULES_MAX && n.as_f64() == Some(i as f64) => Ok(Some(i as usize)),
            _ => bad(what),
        },
        _ => bad(what),
    }
}

/// `appRulesChange.parse`.
pub fn parse_change(v: &Value) -> Result<AppRulesChange, String> {
    let Some(o) = v.as_object() else { return bad("change") };
    let id = || match o.get("id").and_then(Value::as_str) {
        Some(s) if RULE_ID.is_match(s) => Ok(s.to_string()),
        _ => bad("rule id"),
    };
    match o.get("op").and_then(Value::as_str) {
        Some("put") => {
            strict_keys(o, &["op", "rule", "at"], "change")?;
            Ok(AppRulesChange::Put {
                rule: parse_rule(o.get("rule").unwrap_or(&Value::Null))?,
                at: index(o.get("at"), "position")?,
            })
        }
        Some("delete") => {
            strict_keys(o, &["op", "id"], "change")?;
            Ok(AppRulesChange::Delete { id: id()? })
        }
        Some("move") => {
            strict_keys(o, &["op", "id", "to"], "change")?;
            let to = index(o.get("to"), "position")?.ok_or("invalid position")?;
            Ok(AppRulesChange::Move { id: id()?, to })
        }
        _ => bad("change"),
    }
}

#[cfg(test)]
mod tests;
