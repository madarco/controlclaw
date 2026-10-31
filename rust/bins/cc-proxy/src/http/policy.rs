//! The request steps W1 owns (appendix F §2.1, steps 3-5, 7, 9-12 and the tail): the emergency stop
//! and its code window, the update window, the website rules, the inline AI review, tunnel and
//! block answers, and permissions with their grants. Each is a `flow::Step` in its `order` slot;
//! W2's checks run between them in the addon's order.
//!
//! The host every step matches is the flow's checked destination: the name the firewall resolved,
//! which the SNI and the Host header agreed with (`net::destination`).

use std::collections::HashSet;
use std::sync::{Arc, Mutex, PoisonError};

use cc_contracts::Maybe;
use cc_contracts::{MissingPolicy, MtimeCache, OnError};
use http::StatusCode;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::flow::{Flow, Hook, Pipeline, Step, StepFuture, Verdict, order};
use crate::http::answer;
use crate::log::record::{self, meta_str, redact_path};
use crate::net::Ctx;
use crate::net::hosts::host_matches;
use crate::net::rules::RuleView;

pub const BLOCK_STATUS: u16 = 403;
pub const PERMISSION_STATUS: u16 = 451;
pub const KILL_RULE: &str = "kill_switch";
pub const CODE_RULE: &str = "kill_switch_code";
pub const UPDATE_RULE: &str = "agent_update";

/// The channel providers' own hosts, open to a locked agent while it carries a code (addon.py
/// `CHANNEL_HOSTS`). Built in: nothing here for a deployment to set.
pub const CHANNEL_HOSTS: &[&str] = &[
    "api.telegram.org",
    "slack.com",
    "*.slack.com",
    "graph.facebook.com",
    "*.whatsapp.net",
    "web.whatsapp.com",
];

fn now() -> f64 {
    crate::log::now().as_f64().unwrap_or(0.0)
}

/// The facts of one request the steps match on.
pub struct Req {
    pub host: String,
    pub method: String,
    /// With its query, as mitmproxy's `request.path`.
    pub path: String,
}

pub fn req(flow: &Flow) -> Req {
    let host = record::record_host(flow);
    let (method, path) = flow.request.as_ref().map_or((String::new(), String::new()), |r| {
        (
            r.method().to_string(),
            r.uri().path_and_query().map_or("/", |p| p.as_str()).to_owned(),
        )
    });
    Req { host, method, path }
}

/// addon.py `match_rule`: the first rule by ascending priority (stable) that applies to this agent,
/// whose domain matches (`*` when absent), method and path substring too. `None`: default allow.
pub fn match_rule(rules: &[RuleView], host: &str, method: &str, path: &str, vm_id: Option<&str>) -> Option<RuleView> {
    let mut sorted: Vec<&RuleView> = rules.iter().collect();
    sorted.sort_by(|a, b| a.priority.total_cmp(&b.priority));
    sorted
        .into_iter()
        .find(|r| {
            r.applies_to(vm_id)
                && r.domain_matches(host, "*")
                // `if rm and rm.upper() != ...` / `if mp and mp not in path`: an empty value is no
                // condition; a value that is not a string raises there, so the rule matches nothing.
                && match r.raw.get("match_method") {
                    None | Some(Value::Null) => true,
                    Some(Value::String(m)) => m.is_empty() || m.eq_ignore_ascii_case(method),
                    Some(v) => !truthy(Some(v)),
                }
                && match r.raw.get("match_path") {
                    None | Some(Value::Null) => true,
                    Some(Value::String(p)) => p.is_empty() || path.contains(p.as_str()),
                    Some(v) => !truthy(Some(v)),
                }
        })
        .cloned()
}

/// addon.py `permission_scope`: `"<method> <host><path without query>"`.
pub fn permission_scope(method: &str, host: &str, path: &str) -> String {
    cc_contracts::pending::permission_scope(method, host, path)
}

/// addon.py `permission_id_for`: `perm_` and 32 hex of the scope's sha256.
pub fn permission_id(scope: &str) -> String {
    format!("perm_{}", &hex::encode(Sha256::digest(scope.as_bytes()))[..32])
}

/// addon.py `permission_path`: the redacted path, plus a hash of the real one for AgentMail.
pub fn permission_path(path: &str, host: &str) -> String {
    let redacted = redact_path(path, host);
    let h = host.to_ascii_lowercase();
    if h == "api.agentmail.to" || h == "ws.agentmail.to" {
        let bare = path.split_once('?').map_or(path, |(p, _)| p);
        return format!("{redacted}#{}", &hex::encode(Sha256::digest(bare.as_bytes()))[..24]);
    }
    redacted
}

/// What the policy steps share: the context, grants, the pending writer, the judge.
pub struct Policy {
    pub ctx: Arc<Ctx>,
    /// `grants.json` as the addon reads it (`_DictCache`): each grant checked on its own.
    grants: MtimeCache<serde_json::Map<String, Value>>,
    pending_seen: Mutex<HashSet<String>>,
    permission_ttl: u64,
    judge: crate::http::judge::Judge,
}

impl Policy {
    pub fn new(ctx: Arc<Ctx>) -> Self {
        let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        Self {
            grants: MtimeCache::new(&ctx.config.grants_path, MissingPolicy::Keep, OnError::Empty),
            pending_seen: Mutex::new(HashSet::new()),
            permission_ttl: env("MITM_PERMISSION_TTL").and_then(|v| v.parse().ok()).unwrap_or(300),
            judge: crate::http::judge::Judge::from_env(),
            ctx,
        }
    }

    /// addon.py `grant_active`.
    pub fn grant_active(&self, permission_id: &str) -> bool {
        // `float(grant.get("expires_at", 0)) > time.time()`, a value float() refuses being false.
        self.grants
            .get()
            .get(permission_id)
            .filter(|g| truthy(Some(g)))
            .and_then(|g| g.get("expires_at"))
            .map(|t| crate::net::identity::py_float(Some(t)))
            .is_some_and(|t| t > now())
    }

    /// addon.py `record_pending`: once per id and agent per process, one JSON line appended.
    fn record_pending(&self, permission_id: &str, vm_id: Option<&str>, line: &Value) {
        let seen = format!("{permission_id}|{}", vm_id.unwrap_or(""));
        {
            let mut s = self.pending_seen.lock().unwrap_or_else(PoisonError::into_inner);
            if !s.insert(seen.clone()) {
                return;
            }
        }
        let text = format!("{}\n", crate::http::answer::py_json_utf8(line));
        let r = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.ctx.config.pending_path)
            .and_then(|mut f| std::io::Write::write_all(&mut f, text.as_bytes()));
        if let Err(e) = r {
            // Not seen after all: the next request asks again, rather than the ask being lost.
            self.pending_seen
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(&seen);
            tracing::warn!("[mitm] pending write failed: {e}");
        }
    }

    /// The window flags of this agent: (locked, code window open, update window open).
    fn windows(&self, vm_id: Option<&str>) -> (bool, bool, bool) {
        let t = now();
        match self.ctx.identities.for_vm(vm_id) {
            Some(i) => (i.locked, i.code_until > t, i.update_until > t),
            None => (false, false, false),
        }
    }
}

/// The rule and error of a request refused because `rules.json` was never read.
pub const RULES_UNAVAILABLE: &str = "rules_unavailable";

/// Answer here with a block: the flow's effect and (when given) its label, the record, the JSON.
fn block_answer(
    ctx: &Ctx,
    flow: &mut Flow,
    status: u16,
    rule: Option<&str>,
    body: Value,
    extra: &[(&str, Value)],
) -> Verdict {
    flow.meta.insert("effect", "block".into());
    if let Some(rule) = rule {
        flow.meta.insert("rule", rule.into());
    }
    let mut rec = record::http_record(ctx, flow, "block");
    rec.status = Maybe::Value(u64::from(status).into());
    for (k, v) in extra {
        rec.extra.insert((*k).into(), v.clone());
    }
    record::log_once(ctx, flow, &rec);
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::FORBIDDEN);
    Verdict::Answer(Box::new(answer::json(status, &body)))
}

macro_rules! step {
    ($name:ident, $label:literal, |$self:ident, $flow:ident| $body:block) => {
        pub struct $name(pub Arc<Policy>);
        impl Step for $name {
            fn name(&self) -> &'static str {
                $label
            }
            fn hooks(&self) -> &'static [Hook] {
                &[Hook::Request]
            }
            fn run<'a>(&'a self, _: Hook, $flow: &'a mut Flow) -> StepFuture<'a> {
                let $self = &self.0;
                Box::pin(async move { $body })
            }
            fn reads_body(&self, _: Hook, flow: &mut Flow) -> bool {
                reads_body($label, &self.0, flow)
            }
        }
    };
}

/// Which of these steps read the request's body: only the AI review (and an Ask rule's approval,
/// which asks the same judge), for a host one of whose rules has `ai_review`: the judge sees the
/// start of a text body. The others decide from the head.
fn reads_body(label: &str, p: &Policy, flow: &mut Flow) -> bool {
    if !matches!(label, "ai_review" | "require_permission") {
        return false;
    }
    let r = req(flow);
    rules_for(p, flow).0.iter().any(|rule| {
        rule.applies_to(flow.vm_id.as_deref()) && rule.domain_matches(&r.host, "*") && truthy(rule.raw.get("ai_review"))
    })
}

/// The rules as this flow read them: the first read (deciding whether a step reads the body, or
/// the rule match) is kept on the flow, so a rules file that changes in between cannot make the
/// decision and the match disagree.
/// Whether the file had been read is kept with the rules: an empty list from before the first
/// sync must stay "not read yet", never become "no rules" (which allows).
#[derive(Clone)]
struct RulesSnapshot(Arc<Vec<crate::net::rules::RuleView>>, bool);

fn rules_for(p: &Policy, flow: &mut Flow) -> (Arc<Vec<crate::net::rules::RuleView>>, bool) {
    if let Some(RulesSnapshot(rules, loaded)) = flow.extensions.get::<RulesSnapshot>() {
        return (rules.clone(), *loaded);
    }
    // `loaded` first: rules read after it are at least as new.
    let loaded = p.ctx.rules.loaded();
    let rules = p.ctx.rules.get();
    flow.extensions.insert(RulesSnapshot(rules.clone(), loaded));
    (rules, loaded)
}

/// Drop the flow's rules snapshot: the next step reads the file afresh (once the body is held).
pub fn forget_rules(flow: &mut Flow) {
    flow.extensions.remove::<RulesSnapshot>();
}

// 3. The code window: a locked agent may reach its channel providers while it carries a code.
step!(CodeWindow, "kill_code_window", |p, flow| {
    let r = req(flow);
    let (locked, code_open, _) = p.windows(flow.vm_id.as_deref());
    let sni_ok = flow.sni.as_deref().is_none_or(|s| s == r.host);
    if locked && code_open && CHANNEL_HOSTS.iter().any(|h| host_matches(h, &r.host)) && sni_ok {
        flow.meta.insert("effect", "allow".into());
        flow.meta.insert("rule", CODE_RULE.into());
        return Verdict::Forward;
    }
    Verdict::Continue
});

// 4. The emergency stop: everything. A box's own control-plane paths never reach the steps
// (`http::backup::control_plane`); any other request to that host is an ordinary site.
step!(KillSwitch, "kill_switch", |p, flow| {
    let r = req(flow);
    let (locked, _, _) = p.windows(flow.vm_id.as_deref());
    if locked {
        let body = json!({"error": "blocked_by_kill_switch", "host": r.host, "tenant": p.ctx.config.tenant});
        return block_answer(&p.ctx, flow, BLOCK_STATUS, Some(KILL_RULE), body, &[]);
    }
    Verdict::Continue
});

// 5. The update window: the role's package hosts, for an agent running a confirmed update.
step!(UpdateWindow, "update_window", |p, flow| {
    let r = req(flow);
    let (_, _, update_open) = p.windows(flow.vm_id.as_deref());
    let sni_ok = flow.sni.as_deref().is_none_or(|s| s == r.host);
    if update_open && sni_ok && p.ctx.config.update_hosts.contains(&r.host) {
        flow.meta.insert("effect", "allow".into());
        flow.meta.insert("rule", UPDATE_RULE.into());
        return Verdict::Forward;
    }
    Verdict::Continue
});

/// A rule's label: `rule.get("name") or rule.get("match_domain")`, which is the domain as written
/// (even `""` or null) whenever the name is not truthy.
pub fn rule_label(rule: &RuleView) -> Value {
    match rule.raw.get("name") {
        Some(n) if truthy(Some(n)) => n.clone(),
        _ => rule.raw.get("match_domain").cloned().unwrap_or(Value::Null),
    }
}

/// `str(rule["id"])` for a truthy id, as the addon keeps it (`[:64]`).
fn rule_id(rule: &RuleView) -> Option<String> {
    let id = rule.raw.get("id").filter(|v| truthy(Some(v)))?;
    let text = match id {
        Value::String(s) => s.clone(),
        Value::Bool(true) => "True".into(),
        other => other.to_string(),
    };
    Some(crate::net::target::truncate(&text, 64))
}

/// The rule that matched, kept for the later steps of this flow.
fn matched(flow: &Flow) -> Option<RuleView> {
    flow.meta.get("rule_view").and_then(|v| {
        let raw = v.clone();
        crate::net::rules::RuleView::from_value(&raw)
    })
}

// 7. The website rules: effect, label and id on the flow.
step!(MatchRule, "match_rule", |p, flow| {
    let r = req(flow);
    let (rules, loaded) = rules_for(p, flow);
    // No rules read yet (a cold start before the agent's first sync): refused, never allowed by
    // default as the addon would.
    if rules.is_empty() && !loaded {
        let body = json!({"error": RULES_UNAVAILABLE, "host": r.host, "tenant": p.ctx.config.tenant});
        return block_answer(&p.ctx, flow, 403, Some(RULES_UNAVAILABLE), body, &[]);
    }
    let rule = match_rule(&rules, &r.host, &r.method, &r.path, flow.vm_id.as_deref());
    let effect = rule
        .as_ref()
        .and_then(|r| r.raw.get("effect").and_then(Value::as_str).map(str::to_owned))
        .unwrap_or_else(|| "allow".into());
    flow.meta.insert("effect", effect.into());
    let label = rule.as_ref().map_or(Value::Null, rule_label);
    flow.meta.insert("rule", label.clone());
    if let Some(rule) = &rule {
        if let Some(id) = rule_id(rule) {
            flow.meta.insert("rule_ref", json!([id, label]));
        }
        flow.meta.insert("rule_view", rule.raw.clone());
    }
    Verdict::Continue
});

/// The rule's `ai_review` as Python's truthiness reads it.
pub fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0),
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(o)) => !o.is_empty(),
    }
}

// 9. The inline AI review of an allowed request (unless a person already granted it).
step!(AiReview, "ai_review", |p, flow| {
    if meta_str(flow, "effect") != Some("allow") {
        return Verdict::Continue;
    }
    let Some(rule) = matched(flow) else {
        return Verdict::Continue;
    };
    if !truthy(rule.raw.get("ai_review")) {
        return Verdict::Continue;
    }
    let r = req(flow);
    let pid = permission_id(&permission_scope(
        &r.method,
        &r.host,
        &permission_path(&r.path, &r.host),
    ));
    if p.grant_active(&pid) {
        return Verdict::Continue;
    }
    if let Some(v) = p.judge.ask(&p.ctx, flow, &rule, None).await {
        let decision = v.get("decision").and_then(Value::as_str).unwrap_or("").to_owned();
        flow.meta.insert(
            "ai",
            json!({"verdict": decision, "category": v.get("category").cloned().unwrap_or(Value::Null),
                   "cached": truthy(v.get("cached"))}),
        );
        let effect = match decision.as_str() {
            "block" => "block",
            "ask" => "require_permission",
            _ => "allow",
        };
        flow.meta.insert("effect", effect.into());
    }
    Verdict::Continue
});

// 10. A tunnel destination reached as HTTP: let it through, never swap into it.
step!(TunnelEffect, "tunnel", |p, flow| {
    if meta_str(flow, "effect") != Some("tunnel") {
        return Verdict::Continue;
    }
    let rec = record::http_record(&p.ctx, flow, "tunnel");
    record::log_once(&p.ctx, flow, &rec);
    Verdict::Forward
});

// 11. Block.
step!(BlockEffect, "block", |p, flow| {
    if meta_str(flow, "effect") != Some("block") {
        return Verdict::Continue;
    }
    let host = req(flow).host;
    let tenant = p.ctx.config.tenant.clone();
    let body = match flow.meta.get("ai") {
        Some(ai) => json!({"error": "blocked_by_ai_review", "host": host, "tenant": tenant,
                           "category": ai.get("category").cloned().unwrap_or(Value::Null)}),
        None => json!({"error": "blocked_by_policy", "host": host, "tenant": tenant}),
    };
    block_answer(&p.ctx, flow, BLOCK_STATUS, None, body, &[])
});

// 12. Ask: a grant, or the AI approving under the rule's policy, lets it through; else 451.
step!(Permission, "require_permission", |p, flow| {
    if meta_str(flow, "effect") != Some("require_permission") {
        return Verdict::Continue;
    }
    let r = req(flow);
    let scope = permission_scope(&r.method, &r.host, &permission_path(&r.path, &r.host));
    let pid = permission_id(&scope);
    let rule = matched(flow);
    let mut approved = false;
    if !p.grant_active(&pid)
        && !flow.meta.contains_key("ai")
        && let Some(rule) = &rule
        && truthy(rule.raw.get("ai_review"))
        && truthy(rule.raw.get("ai_policy"))
    {
        // The AI may approve on a person's behalf. It never blocks: "no" or no answer is the 451.
        let ask = json!({"permission_id": pid, "scope": scope});
        if let Some(v) = p.judge.ask(&p.ctx, flow, rule, Some(&ask)).await {
            approved = v.get("decision").and_then(Value::as_str) == Some("allow");
            let mut ai = json!({"verdict": if approved { "allow" } else { "ask" },
                                "category": v.get("category").cloned().unwrap_or(Value::Null),
                                "cached": truthy(v.get("cached"))});
            if approved && let Some(o) = ai.as_object_mut() {
                o.insert("by".into(), "ai".into());
            }
            flow.meta.insert("ai", ai);
        }
    }
    if p.grant_active(&pid) || approved {
        flow.meta.insert("effect", "allow".into());
        flow.meta.insert("granted", pid.into());
        return Verdict::Continue;
    }
    let tenant = p.ctx.config.tenant.clone();
    let mut line = json!({"ts": now(), "tenant": tenant, "vm_id": flow.vm_id, "permission_id": pid,
                          "scope": scope, "host": r.host, "method": r.method,
                          "path": redact_path(&r.path, &r.host)});
    if let (Some(ai), Some(o)) = (flow.meta.get("ai"), line.as_object_mut()) {
        o.insert("ai_category".into(), ai.get("category").cloned().unwrap_or(Value::Null));
    }
    p.record_pending(&pid, flow.vm_id.as_deref(), &line);
    let body = json!({"permission_id": pid,
                      "reason": if flow.meta.contains_key("ai") { "ai_review" } else { "require_permission" },
                      "summary": scope, "expires_at": now() as u64 + p.permission_ttl});
    flow.meta.insert("effect", "require_permission".into());
    let mut rec = record::http_record(&p.ctx, flow, "require_permission");
    rec.extra.insert("permission_id".into(), pid.clone().into());
    rec.status = Maybe::Value(u64::from(PERMISSION_STATUS).into());
    record::log_once(&p.ctx, flow, &rec);
    Verdict::Answer(Box::new(answer::json(
        StatusCode::from_u16(PERMISSION_STATUS).unwrap_or(StatusCode::FORBIDDEN),
        &body,
    )))
});

// The tail of `request`: a granted request with no label is labelled `grant`.
step!(RequestTail, "request_tail", |_p, flow| {
    // `metadata.get("cc_rule") or "grant"`: any falsy label, an empty one too.
    if truthy(flow.meta.get("granted")) && !truthy(flow.meta.get("rule")) {
        flow.meta.insert("rule", "grant".into());
    }
    Verdict::Continue
});

/// Add W1's request steps in the addon's order.
pub fn register(pipeline: &mut Pipeline, ctx: &Arc<Ctx>) {
    let p = Arc::new(Policy::new(ctx.clone()));
    pipeline.push(order::KILL_CODE_WINDOW, Arc::new(CodeWindow(p.clone())));
    pipeline.push(order::KILL_SWITCH, Arc::new(KillSwitch(p.clone())));
    pipeline.push(order::UPDATE_WINDOW, Arc::new(UpdateWindow(p.clone())));
    pipeline.push(order::MATCH_RULE, Arc::new(MatchRule(p.clone())));
    pipeline.push(order::AI_REVIEW, Arc::new(AiReview(p.clone())));
    pipeline.push(order::TUNNEL, Arc::new(TunnelEffect(p.clone())));
    pipeline.push(order::BLOCK, Arc::new(BlockEffect(p.clone())));
    pipeline.push(order::PERMISSION, Arc::new(Permission(p.clone())));
    pipeline.push(order::REQUEST_TAIL, Arc::new(RequestTail(p)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::testing::request_flow;

    fn rules(v: Value) -> Vec<RuleView> {
        v.as_array()
            .map(|a| a.iter().filter_map(RuleView::from_value).collect())
            .unwrap_or_default()
    }

    fn name(r: Option<RuleView>) -> Option<String> {
        r.and_then(|r| r.raw.get("name").and_then(Value::as_str).map(str::to_owned))
    }

    #[test]
    fn the_first_rule_by_priority_that_matches_wins() {
        let rs = rules(json!([
            {"name": "late", "match_domain": "example.com", "priority": 10},
            {"name": "fraction", "match_domain": "example.com", "priority": 1.5},
            {"name": "early-other", "match_domain": "other.com", "priority": 1},
            {"name": "default", "match_domain": "example.com"},
        ]));
        // 1.5 sorts before 10 (and is not cut to 1).
        assert_eq!(
            name(match_rule(&rs, "example.com", "GET", "/", None)).as_deref(),
            Some("fraction")
        );
        assert_eq!(
            name(match_rule(&rs, "other.com", "GET", "/", None)).as_deref(),
            Some("early-other")
        );
        assert!(match_rule(&rs, "nowhere.com", "GET", "/", None).is_none());
        // Equal priorities keep the file's order.
        let tie = rules(json!([
            {"name": "a", "match_domain": "x.com", "priority": 5},
            {"name": "b", "match_domain": "x.com", "priority": 5},
        ]));
        assert_eq!(name(match_rule(&tie, "x.com", "GET", "/", None)).as_deref(), Some("a"));
    }

    #[test]
    fn method_path_and_agent_conditions() {
        let rs = rules(json!([
            {"name": "post-api", "match_domain": "x.com", "match_method": "post", "match_path": "/api", "priority": 1},
            {"name": "bad-method", "match_domain": "x.com", "match_method": 5, "priority": 2},
            {"name": "empty-method", "match_domain": "x.com", "match_method": "", "match_path": "", "priority": 3, "vm_id": "a"},
            {"name": "rest", "match_domain": "x.com", "priority": 4},
        ]));
        assert_eq!(
            name(match_rule(&rs, "x.com", "POST", "/v1/api/x", None)).as_deref(),
            Some("post-api")
        );
        assert_eq!(
            name(match_rule(&rs, "x.com", "GET", "/v1/api/x", None)).as_deref(),
            Some("rest")
        );
        // A method that is not text matches nothing; an empty one is no condition.
        assert_eq!(
            name(match_rule(&rs, "x.com", "GET", "/", Some("a"))).as_deref(),
            Some("empty-method")
        );
        assert_eq!(
            name(match_rule(&rs, "x.com", "GET", "/", Some("b"))).as_deref(),
            Some("rest")
        );
    }

    #[test]
    fn permission_scope_id_and_path_are_the_addons() {
        let scope = permission_scope("GET", "example.com", "/a?secret=1");
        assert_eq!(scope, "GET example.com/a");
        // `"perm_" + sha256(scope)[:32]`, computed with Python's hashlib.
        assert_eq!(permission_id(&scope), "perm_905045d25af812a1984caeef20232fd4");
        assert_eq!(permission_path("/x?y=1", "example.com"), "/x");
        let mail = permission_path("/v0/inboxes/me@x.to/messages/abc", "api.agentmail.to");
        assert!(mail.contains('#') && !mail.contains("me@x.to"), "{mail}");
    }

    #[test]
    fn labels_ids_and_truthiness() {
        let r = |v: Value| RuleView::from_value(&v).expect("a rule");
        assert_eq!(rule_label(&r(json!({"name": "n", "match_domain": "d"}))), json!("n"));
        assert_eq!(rule_label(&r(json!({"name": "", "match_domain": "d"}))), json!("d"));
        assert_eq!(rule_label(&r(json!({}))), Value::Null);
        assert_eq!(rule_id(&r(json!({"id": 7}))).as_deref(), Some("7"));
        assert_eq!(rule_id(&r(json!({"id": true}))).as_deref(), Some("True"));
        assert_eq!(rule_id(&r(json!({"id": ""}))), None);
        assert_eq!(rule_id(&r(json!({"id": "x".repeat(80)}))).map(|s| s.len()), Some(64));
        for (v, t) in [
            (json!(null), false),
            (json!(0), false),
            (json!(0.0), false),
            (json!(""), false),
            (json!([]), false),
            (json!({}), false),
            (json!(1), true),
            (json!("x"), true),
            (json!([0]), true),
        ] {
            assert_eq!(truthy(Some(&v)), t, "{v}");
        }
    }

    /// A policy over a config folder of its own; `rules` is written as `rules.json` when given.
    fn policy(rules: Option<&str>) -> (Arc<Policy>, std::path::PathBuf) {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("cc-proxy-policy-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a temp dir");
        if let Some(r) = rules {
            std::fs::write(dir.join("rules.json"), r).expect("rules.json");
        }
        let vars: std::collections::HashMap<String, String> = [
            ("MITM_RULES_PATH", "rules.json"),
            ("MITM_IDENTITIES_PATH", "identities.json"),
            ("MITM_GRANTS_PATH", "grants.json"),
            ("MITM_PENDING_PATH", "pending.jsonl"),
            ("MITM_LOG_FILE", "traffic.jsonl"),
        ]
        .into_iter()
        .map(|(k, f)| (k.to_owned(), dir.join(f).display().to_string()))
        .chain([("MITM_CA_DIR".to_owned(), "/nonexistent".to_owned())])
        .collect();
        let config =
            crate::config::Config::from_vars("127.0.0.1:0".parse().expect("an address"), &vars).expect("a config");
        (Arc::new(Policy::new(Arc::new(Ctx::new(config)))), dir)
    }

    fn answered(v: &Verdict) -> Option<(u16, Value)> {
        match v {
            Verdict::Answer(r) => Some((r.status().as_u16(), serde_json::from_slice(r.body()).ok()?)),
            _ => None,
        }
    }

    #[tokio::test]
    async fn no_rules_file_at_a_cold_start_refuses() {
        let (p, dir) = policy(None);
        let step = MatchRule(p.clone());
        let mut flow = request_flow("GET", "https://example.com/x", b"");
        let v = step.run(Hook::Request, &mut flow).await;
        let (status, body) = answered(&v).expect("an answer");
        assert_eq!(status, 403);
        assert_eq!(body["error"], RULES_UNAVAILABLE);
        assert_eq!(flow.meta.get("rule"), Some(&json!(RULES_UNAVAILABLE)));
        // A broken file is not read either.
        std::fs::write(dir.join("rules.json"), "[").expect("write");
        let mut flow = request_flow("GET", "https://example.com/x", b"");
        assert!(answered(&step.run(Hook::Request, &mut flow).await).is_some());
        // Once an empty list is read, the default is allow, and stays so if the file goes.
        std::fs::write(dir.join("rules.json"), "[]").expect("write");
        let mut flow = request_flow("GET", "https://example.com/x", b"");
        assert!(matches!(step.run(Hook::Request, &mut flow).await, Verdict::Continue));
        assert_eq!(flow.meta.get("effect"), Some(&json!("allow")));
        std::fs::remove_file(dir.join("rules.json")).expect("remove");
        let mut flow = request_flow("GET", "https://example.com/x", b"");
        assert!(matches!(step.run(Hook::Request, &mut flow).await, Verdict::Continue));
    }

    #[tokio::test]
    async fn a_rule_sets_effect_label_and_id() {
        let (p, _dir) = policy(Some(
            r#"[{"id": "r1", "name": "no", "effect": "block", "match_domain": "example.com"}]"#,
        ));
        let mut flow = request_flow("GET", "https://example.com/x", b"");
        assert!(matches!(
            MatchRule(p).run(Hook::Request, &mut flow).await,
            Verdict::Continue
        ));
        assert_eq!(flow.meta.get("effect"), Some(&json!("block")));
        assert_eq!(flow.meta.get("rule"), Some(&json!("no")));
        assert_eq!(flow.meta.get("rule_ref"), Some(&json!(["r1", "no"])));
    }

    /// The rule a new standalone database starts with (`cc_local::plane::BLOCK_ALL_*`).
    #[tokio::test]
    async fn a_fresh_standalone_firewalls_rule_refuses_every_host() {
        let (p, _dir) = policy(Some(
            r#"[{"id": "block-all", "name": "Block everything until you add rules", "match_domain": "*", "effect": "block", "priority": 100000}]"#,
        ));
        for url in [
            "https://example.com/x",
            "http://api.github.com/",
            "https://a.b.c.example/",
        ] {
            let mut flow = request_flow("GET", url, b"");
            assert!(matches!(
                MatchRule(p.clone()).run(Hook::Request, &mut flow).await,
                Verdict::Continue
            ));
            let (status, body) =
                answered(&BlockEffect(p.clone()).run(Hook::Request, &mut flow).await).expect("refused");
            assert_eq!(
                (status, body["error"].as_str()),
                (BLOCK_STATUS, Some("blocked_by_policy")),
                "{url}"
            );
        }
    }

    #[tokio::test]
    async fn a_granted_request_without_a_label_is_labelled_grant() {
        let (p, _dir) = policy(Some("[]"));
        let step = RequestTail(p);
        for label in [Value::Null, json!(""), json!(0)] {
            let mut flow = request_flow("GET", "https://example.com/x", b"");
            flow.meta.insert("granted", json!(true));
            flow.meta.insert("rule", label);
            step.run(Hook::Request, &mut flow).await;
            assert_eq!(flow.meta.get("rule"), Some(&json!("grant")));
        }
        let mut flow = request_flow("GET", "https://example.com/x", b"");
        flow.meta.insert("granted", json!(true));
        flow.meta.insert("rule", json!("mine"));
        step.run(Hook::Request, &mut flow).await;
        assert_eq!(flow.meta.get("rule"), Some(&json!("mine")));
    }

    #[tokio::test]
    async fn a_failed_pending_write_does_not_count_as_asked() {
        let (p, dir) = policy(Some("[]"));
        // The pending file's folder is a file: every write fails.
        let blocked = dir.join("blocked");
        std::fs::write(&blocked, "").expect("write");
        let mut ctx_config = p.ctx.config.clone();
        ctx_config.pending_path = blocked.join("pending.jsonl");
        let p = Policy::new(Arc::new(Ctx::new(ctx_config)));
        p.record_pending("perm_x", Some("a"), &json!({"id": "perm_x"}));
        assert!(p.pending_seen.lock().expect("lock").is_empty());
        // A write that works is remembered, so the same ask is written once.
        let (ok, dir) = policy(Some("[]"));
        ok.record_pending("perm_y", Some("a"), &json!({"id": "perm_y"}));
        ok.record_pending("perm_y", Some("a"), &json!({"id": "perm_y"}));
        let text = std::fs::read_to_string(dir.join("pending.jsonl")).expect("pending");
        assert_eq!(text.lines().count(), 1);
    }
}
