//! The route table, the no-code apply, and each feature's handlers against an in-memory database,
//! with a fake firewall behind the hooks. `admin/tests.rs` covers the login, session and CSRF in
//! front of them; the conformance cases (`cases/panel`) the real firewall.

use std::sync::{Arc, Mutex};

use serde_json::{Value, json};

use super::*;
use crate::db::Db;
use crate::plane::{ControlPlane, LocalControlPlane};

type Calls = Arc<Mutex<Vec<(String, Value)>>>;

struct World {
    ctx: Ctx,
    calls: Calls,
    woken: Arc<Mutex<u32>>,
    table: Vec<Route>,
}

/// A firewall that holds every change for a code it hands back to the admin, as `Consent` does
/// under `requested_via::local_admin`, and applies it on the right code.
fn world() -> World {
    let db = Arc::new(Db::memory().expect("db"));
    let plane = Arc::new(LocalControlPlane::new(db.clone()));
    plane.register_self("fw").expect("self");
    db.lock()
        .execute(
            "INSERT INTO agents (vm_id, role, name, private_ip, created_at) VALUES ('a1', 'openclaw', 'Atlas', '10.0.0.3', 1)",
            [],
        )
        .expect("agent");
    let calls: Calls = Arc::default();
    let woken = Arc::new(Mutex::new(0));
    let (c, w) = (calls.clone(), woken.clone());
    let hooks = Hooks {
        command: Arc::new(move |action, payload| {
            c.lock()
                .expect("calls")
                .push((action.clone(), Value::Object(payload.clone())));
            Box::pin(async move {
                let id = payload.get("changeId").cloned().unwrap_or(Value::Null);
                Some(match action.rsplit('.').next() {
                    Some("propose" | "release") => {
                        json!({"ok": true, "status": "awaiting_code", "data": {"changeId": id, "sentVia": "local-admin"}, "localCode": "424242"})
                    }
                    Some("confirm") if payload.get("code") == Some(&json!("424242")) => {
                        json!({"ok": true, "status": "applied", "data": {"changeId": id, "sentVia": "local-admin"}})
                    }
                    Some("confirm") => json!({"ok": false, "status": "invalid_code", "message": "Wrong code."}),
                    _ if action == "health.missing" => return None,
                    _ => json!({"ok": true, "status": "done"}),
                })
            })
        }),
        rules_changed: Arc::new(move || *w.lock().expect("woken") += 1),
        ..Default::default()
    };
    World {
        ctx: Ctx {
            db,
            plane,
            hooks,
            params: Default::default(),
            query: String::new(),
        },
        calls,
        woken,
        table: routes(),
    }
}

impl World {
    async fn send(&self, method: &str, path_and_query: &str, body: Value) -> Reply {
        let (path, query) = path_and_query.split_once('?').unwrap_or((path_and_query, ""));
        let method = http::Method::from_bytes(method.as_bytes()).expect("method");
        match find(&self.table, &method, path) {
            Found::Route(r, params) => {
                let ctx = Ctx {
                    params,
                    query: query.into(),
                    ..self.ctx.clone()
                };
                call(r, ctx, body).await
            }
            Found::Method => Reply::error(405, "method"),
            Found::None => Reply::error(404, "none"),
        }
    }

    fn actions(&self) -> Vec<String> {
        self.calls
            .lock()
            .expect("calls")
            .iter()
            .map(|(a, _)| a.clone())
            .collect()
    }
}

#[test]
fn paths_match_with_params_and_methods_apart() {
    let t = routes();
    assert!(matches!(find(&t, &http::Method::PATCH, "/api/egress/rules/r_1"), Found::Route(_, p) if p["id"] == "r_1"));
    assert!(matches!(
        find(&t, &http::Method::PUT, "/api/egress/rules/r_1"),
        Found::Method
    ));
    assert!(matches!(
        find(&t, &http::Method::GET, "/api/egress/rules/r_1/x/y"),
        Found::None
    ));
    assert!(
        matches!(find(&t, &http::Method::POST, "/api/egress/rules/r%201/cycle"), Found::Route(_, p) if p["id"] == "r 1")
    );
    // One route per method and path.
    let mut seen = std::collections::HashSet::new();
    for r in &t {
        assert!(seen.insert((r.method.clone(), r.path)), "{} {} twice", r.method, r.path);
    }
}

#[tokio::test]
async fn a_change_is_proposed_then_confirmed_with_the_code_that_is_never_answered() {
    let w = world();
    let out = w.ctx.apply("rules", serde_json::Map::new()).await.expect("apply");
    assert_eq!(out.status, "applied");
    assert_eq!(w.actions(), ["rules.propose", "rules.confirm"]);
    let calls = w.calls.lock().expect("calls").clone();
    assert_eq!(calls[0].1["changeId"], calls[1].1["changeId"], "the same change");
    assert_eq!(calls[1].1["code"], json!("424242"));
    let body = serde_json::to_string(&out).expect("json");
    assert!(!body.contains("424242"), "no code in the answer: {body}");
    // `/api/commands` answers the proposal as it is: still no code in it.
    let r = w
        .send(
            "POST",
            "/api/commands",
            json!({"action": "rules.propose", "payload": {"changeId": "c1", "change": {"op": "ai"}}}),
        )
        .await;
    assert!(!r.body.to_string().contains("424242"), "{:?}", r.body);
    assert_eq!(r.body["status"], json!("applied"), "confirmed at once");
    // A firewall with no handler for it: 404.
    let missing = w.ctx.command("health.missing", json!({})).await;
    assert_eq!(missing.expect_err("404").status, 404);
}

#[tokio::test]
async fn egress_rules_one_by_one_with_the_saas_checks() {
    let w = world();
    let r = w
        .send(
            "POST",
            "/api/egress/rules",
            json!({"name": "GitHub", "matchDomain": "api.github.com", "matchPort": 443, "aiReview": true, "aiPolicy": " be careful "}),
        )
        .await;
    assert_eq!(r.status, 200, "{:?}", r.body);
    let id = r.body["id"].as_str().expect("id").to_string();
    // A port only on a tunnel rule; the note kept under review, trimmed.
    assert_eq!(r.body["matchPort"], Value::Null);
    assert_eq!(r.body["effect"], json!("allow"));
    assert_eq!(r.body["aiPolicy"], json!("be careful"));
    assert_eq!(*w.woken.lock().expect("woken"), 1, "the sync is woken");
    // Block: no AI review, no note.
    let r = w
        .send("PATCH", &format!("/api/egress/rules/{id}"), json!({"effect": "block"}))
        .await;
    assert_eq!(
        (r.body["aiReview"].clone(), r.body["aiPolicy"].clone()),
        (json!(false), Value::Null)
    );
    // allow -> ask -> block -> allow; block goes back to allow.
    let r = w
        .send("POST", &format!("/api/egress/rules/{id}/cycle"), Value::Null)
        .await;
    assert_eq!(r.body["effect"], json!("allow"));
    // A residential exit only where traffic goes out.
    let r = w
        .send(
            "PATCH",
            &format!("/api/egress/rules/{id}"),
            json!({"exit": "residential", "exitCountry": "de"}),
        )
        .await;
    assert_eq!(
        (r.body["exit"].clone(), r.body["exitCountry"].clone()),
        (json!("residential"), json!("DE"))
    );
    let r = w
        .send("POST", &format!("/api/egress/rules/{id}/cycle"), Value::Null)
        .await;
    assert_eq!(
        (r.body["effect"].clone(), r.body["exit"].clone()),
        (json!("require_permission"), json!("firewall"))
    );
    // Asked for on a block rule: refused, not quietly put back on the firewall.
    let r = w
        .send(
            "POST",
            "/api/egress/rules",
            json!({"name": "x", "matchDomain": "x.example", "effect": "block", "exit": "residential"}),
        )
        .await;
    assert_eq!(r.status, 400, "{:?}", r.body);
    // Bad input: 400; another agent's id: 404; unknown rule: 404.
    for bad in [
        json!({"name": "", "matchDomain": "x"}),
        json!({"name": "x", "matchDomain": "x", "priority": -1}),
        json!({"name": "x"}),
        json!({"name": "x", "matchDomain": "x", "nope": 1}),
    ] {
        assert_eq!(
            w.send("POST", "/api/egress/rules", bad.clone()).await.status,
            400,
            "{bad}"
        );
    }
    assert_eq!(
        w.send(
            "POST",
            "/api/egress/rules",
            json!({"name": "x", "matchDomain": "x", "vmId": "zz"})
        )
        .await
        .status,
        404
    );
    assert_eq!(w.send("PATCH", "/api/egress/rules/none", json!({})).await.status, 404);
    // The list is what the firewall reads too: `null` clears a path.
    w.send("PATCH", &format!("/api/egress/rules/{id}"), json!({"matchPath": "/x"}))
        .await;
    let r = w
        .send("PATCH", &format!("/api/egress/rules/{id}"), json!({"matchPath": null}))
        .await;
    assert_eq!(r.body["matchPath"], Value::Null);
    let list = w.send("GET", "/api/egress/rules", Value::Null).await;
    assert_eq!(list.body.as_array().map(Vec::len), Some(1));
    assert_eq!(
        w.send("DELETE", &format!("/api/egress/rules/{id}"), Value::Null)
            .await
            .status,
        200
    );
    assert_eq!(
        w.send("DELETE", &format!("/api/egress/rules/{id}"), Value::Null)
            .await
            .status,
        404
    );
}

#[tokio::test]
async fn a_model_key_then_the_ai_review_that_uses_it() {
    let w = world();
    // No key: the review cannot be switched on.
    let ai = json!({"enabled": true, "credentialId": null, "model": "typesafe-ai/jev", "dailyCallCap": 5000, "scanIntervalHours": 6, "autoApprovePerHour": 30});
    assert_eq!(w.send("PUT", "/api/egress/ai", ai.clone()).await.status, 400);
    assert_eq!(
        w.send("POST", "/api/llm/keys", json!({"provider": "openai", "key": "nope"}))
            .await
            .status,
        400
    );
    let r = w
        .send(
            "POST",
            "/api/llm/keys",
            json!({"provider": "vercel_gateway", "key": "vck_abcdefghijklmnopqrst"}),
        )
        .await;
    assert_eq!(r.status, 200, "{:?}", r.body);
    assert!(!r.body.to_string().contains("424242"));
    let key = r.body["keys"][0].clone();
    assert_eq!(
        (key["hint"].clone(), key["state"].clone()),
        (json!("…qrst"), json!("active"))
    );
    let propose = w.calls.lock().expect("calls")[0].1.clone();
    assert_eq!(propose["secret"], json!({"apiKey": "vck_abcdefghijklmnopqrst"}));
    assert_eq!(propose["swap"]["matchDomain"], json!("ai-gateway.vercel.sh"));
    assert_eq!(propose["kind"], json!("add"));
    // The endpoint agents get comes with the key; a bind can only add a model to it.
    assert_eq!(
        propose["providerBlock"]["baseUrl"],
        json!("https://ai-gateway.vercel.sh/v1")
    );
    assert_eq!(
        propose["providerBlock"]["models"][0]["id"],
        json!("anthropic/claude-haiku-5.5")
    );
    // Twice without `replace`: 409.
    assert_eq!(
        w.send(
            "POST",
            "/api/llm/keys",
            json!({"provider": "vercel_gateway", "key": "vck_abcdefghijklmnopqrst"})
        )
        .await
        .status,
        409
    );
    let mut on = ai.clone();
    on["credentialId"] = key["id"].clone();
    on["requestInstructions"] = json!("  Be strict.  ");
    let r = w.send("PUT", "/api/egress/ai", on).await;
    assert_eq!(r.status, 200, "{:?}", r.body);
    assert_eq!(r.body["active"], json!(true));
    assert_eq!(r.body["settings"]["requestInstructions"], json!("Be strict."));
    // What the firewall pulls.
    let pulled = w
        .ctx
        .plane
        .call(
            "fw",
            crate::plane::Call {
                method: "GET".into(),
                path: "/api/vm-agent/egress-rules".into(),
                ..Default::default()
            },
        )
        .await;
    assert_eq!(pulled.body["ai"]["provider"], json!("vercel_gateway"));
    assert_eq!(pulled.body["ai"]["checks"], json!(true));
    assert_eq!(pulled.body["ai"]["request_instructions"], json!("Be strict."));
    // An agent is given a model on that key: a bind for it, with its address as its name.
    let give = |m: &str| json!({"provider": "vercel_gateway", "model": m});
    assert_eq!(w.send("POST", "/api/llm/agents/a1", give("a b")).await.status, 400);
    assert_eq!(w.send("POST", "/api/llm/agents/typo", give("x/y")).await.status, 404);
    let r = w
        .send(
            "POST",
            "/api/llm/agents/a1",
            give("vercel-ai-gateway/moonshotai/kimi-k2"),
        )
        .await;
    assert_eq!(r.status, 200, "{:?}", r.body);
    let bind = w
        .calls
        .lock()
        .expect("calls")
        .iter()
        .rfind(|c| c.0 == "llm.propose")
        .map(|c| c.1.clone())
        .expect("bind");
    assert_eq!(
        (bind["kind"].clone(), bind["credentialId"].clone()),
        (json!("bind"), key["id"].clone())
    );
    assert_eq!(
        bind["agents"],
        json!([{"vmId": "a1", "name": "Atlas", "hostname": "10.0.0.3", "model": "vercel-ai-gateway/moonshotai/kimi-k2", "role": "primary"}])
    );
    assert!(bind.get("secret").is_none(), "the key is the firewall's already");
    // Stock OpenClaw has no AI Gateway provider: the bind carries it as a custom one.
    assert_eq!(
        bind["providerBlock"],
        json!({"baseUrl": "https://ai-gateway.vercel.sh/v1", "api": "openai-completions",
               "models": [{"id": "moonshotai/kimi-k2", "name": "moonshotai/kimi-k2"}]})
    );
    // The gateway's own id is taken under the provider, not left with no key.
    let r = w
        .send("POST", "/api/llm/agents/a1", give("anthropic/claude-haiku-5.5"))
        .await;
    assert_eq!(r.status, 200, "{:?}", r.body);
    let bind = w
        .calls
        .lock()
        .expect("calls")
        .iter()
        .rfind(|c| c.0 == "llm.propose")
        .map(|c| c.1.clone())
        .expect("bind");
    assert_eq!(
        bind["agents"][0]["model"],
        json!("vercel-ai-gateway/anthropic/claude-haiku-5.5")
    );
    assert_eq!(
        bind["providerBlock"]["models"][0]["id"],
        json!("anthropic/claude-haiku-5.5")
    );
    // A residential exit over a host the firewall puts the key in: refused.
    let r = w
        .send(
            "POST",
            "/api/egress/rules",
            json!({"name": "gw", "matchDomain": "*.vercel.sh", "exit": "residential"}),
        )
        .await;
    assert_eq!(r.status, 400, "{:?}", r.body);
    // The key goes: so does the review's.
    let r = w.send("DELETE", "/api/llm/keys/vercel_gateway", Value::Null).await;
    assert_eq!(r.status, 200);
    assert_eq!(
        w.send("GET", "/api/egress/ai", Value::Null).await.body["active"],
        json!(false)
    );
}

async fn ship(w: &World, records: Value) {
    let a = w
        .ctx
        .plane
        .call(
            "fw",
            crate::plane::Call {
                method: "POST".into(),
                path: "/api/vm-agent/activity".into(),
                body: Some(json!({"records": records})),
                ..Default::default()
            },
        )
        .await;
    assert_eq!(a.status, 200, "{:?}", a.body);
}

#[tokio::test]
async fn activity_counts_traffic_and_the_overview() {
    let w = world();
    let now = crate::db::now_s() as f64;
    ship(
        &w,
        json!([
            {"source": "egress", "flow_id": "e1", "ts": now - 5.0, "effect": "allow", "host": "api.github.com", "method": "GET", "path": "/", "vm_id": "a1", "duration_ms": 120},
            {"source": "egress", "flow_id": "e2", "ts": now - 4.0, "effect": "block", "host": "paste.example", "method": "POST", "path": "/", "vm_id": "a1"},
            {"source": "egress", "flow_id": "e3", "ts": now - 3.0, "effect": "require_permission", "host": "pay.example", "method": "POST", "path": "/", "vm_id": "a1"},
        ]),
    )
    .await;
    let r = w.send("GET", "/api/activity", Value::Null).await;
    assert_eq!(r.status, 200, "{:?}", r.body);
    assert_eq!(r.body["counts"], json!({"all": 3, "allow": 1, "ask": 1, "block": 1}));
    assert_eq!(r.body["rows"][0]["verdict"], json!("asked"));
    assert_eq!(r.body["rows"][0]["agent"], json!("Atlas"));
    let r = w.send("GET", "/api/activity?verdict=block&q=paste", Value::Null).await;
    assert_eq!(
        (r.body["total"].clone(), r.body["rows"][0]["message"].clone()),
        (json!(1), json!("POST paste.example/"))
    );
    assert_eq!(
        w.send("GET", "/api/activity?verdict=nope", Value::Null).await.status,
        400
    );
    assert_eq!(
        w.send("GET", "/api/activity?source=tools", Value::Null).await.body["total"],
        json!(0)
    );

    let o = w.send("GET", "/api/overview?range=1h", Value::Null).await;
    assert_eq!(o.status, 200, "{:?}", o.body);
    let b = &o.body;
    assert_eq!(b["blocked"]["today"], json!(1));
    assert_eq!(b["traffic"]["points"].as_array().map(Vec::len), Some(60));
    let sum = |k: &str| {
        b["traffic"]["points"]
            .as_array()
            .expect("points")
            .iter()
            .map(|p| p[k].as_i64().unwrap_or(0))
            .sum::<i64>()
    };
    assert_eq!((sum("allowed"), sum("asked"), sum("blocked")), (1, 1, 1));
    assert_eq!(b["live"].as_array().map(Vec::len), Some(3));
    assert_eq!(b["byAgent"][0]["name"], json!("Atlas"));
    assert_eq!(b["byAgent"][0]["total"], json!(3));
    assert_eq!(b["topHosts"].as_array().map(Vec::len), Some(3));
    assert_eq!(b["response"]["value"], json!(120));
    assert_eq!(
        w.send("GET", "/api/traffic?range=7d", Value::Null).await.body["points"]
            .as_array()
            .map(Vec::len),
        Some(56)
    );
    let cursor = b["live"][0]["id"].as_i64().expect("cursor");
    let after = |n: i64| format!("/api/live?afterId={n}");
    assert_eq!(w.send("GET", &after(cursor), Value::Null).await.body, json!([]));
    assert_eq!(
        w.send("GET", &after(cursor - 1), Value::Null)
            .await
            .body
            .as_array()
            .map(Vec::len),
        Some(1)
    );
}

/// `packages/fw-api/openapi.json` is this route table's document: run
/// `cargo run -p cc-local --bin cc-local-openapi > packages/fw-api/openapi.json` (or
/// `pnpm --filter @controlclaw/fw-api generate`) after a change.
#[test]
fn the_checked_in_openapi_document_is_current() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../packages/fw-api/openapi.json");
    let file: Value =
        serde_json::from_str(&std::fs::read_to_string(path).expect("packages/fw-api/openapi.json")).expect("json");
    assert!(
        file == openapi(),
        "packages/fw-api/openapi.json is not the route table's document: run `pnpm --filter @controlclaw/fw-api generate`"
    );
}

#[tokio::test]
async fn a_permission_request_is_listed_and_answered() {
    let w = world();
    let raised = w
        .ctx
        .plane
        .call(
            "fw",
            crate::plane::Call {
                method: "POST".into(),
                path: "/api/vm-agent/permission".into(),
                body: Some(json!({"permission_id": "p1", "kind": "access", "host": "pay.example", "method": "POST", "agent_vm_id": "a1"})),
                ..Default::default()
            },
        )
        .await;
    assert_eq!(raised.status, 200, "{:?}", raised.body);
    let r = w.send("GET", "/api/requests?status=pending", Value::Null).await;
    assert_eq!(r.status, 200, "{:?}", r.body);
    let item = r.body[0].clone();
    assert_eq!(
        (item["kind"].clone(), item["status"].clone(), item["externalId"].clone()),
        (json!("access"), json!("pending"), json!("p1"))
    );
    assert!(item["detail"].as_array().is_some_and(|d| !d.is_empty()), "{item}");
    let id = item["id"].as_str().expect("id").to_string();
    assert_eq!(
        w.send(
            "POST",
            &format!("/api/requests/{id}/resolve"),
            json!({"decision": "maybe"})
        )
        .await
        .status,
        400
    );
    let r = w
        .send(
            "POST",
            &format!("/api/requests/{id}/resolve"),
            json!({"decision": "approved"}),
        )
        .await;
    assert_eq!(r.body["status"], json!("approved"), "{:?}", r.body);
    // Once: a second answer finds nothing pending.
    assert_eq!(
        w.send(
            "POST",
            &format!("/api/requests/{id}/resolve"),
            json!({"decision": "denied"})
        )
        .await
        .status,
        409
    );
    assert_eq!(
        w.send("GET", "/api/requests?status=pending", Value::Null).await.body,
        json!([])
    );
}

#[tokio::test]
async fn an_exit_settings_change_keeps_what_it_leaves_out() {
    let mut w = world();
    w.ctx.hooks.status = Arc::new(|| {
        let mut m = serde_json::Map::new();
        m.insert("residential".into(), json!({"configured": true, "sticky": true}));
        m
    });
    let r = w.send("PATCH", "/api/exit", json!({"capBytes": null})).await;
    assert_eq!(r.status, 200, "{:?}", r.body);
    let propose = w.calls.lock().expect("calls")[0].1.clone();
    assert_eq!(propose["kind"], json!("settings"));
    assert_eq!(propose["sticky"], json!(true), "kept: {propose}");
    assert_eq!(propose["capBytes"], Value::Null, "null lifts the cap");
    assert!(propose.get("country").is_none(), "left out: unchanged");
    assert_eq!(
        w.send("PATCH", "/api/exit", json!({"country": "Germany"})).await.status,
        400
    );
}

#[tokio::test]
async fn a_release_through_commands_is_confirmed_with_its_scope() {
    let w = world();
    let r = w
        .send(
            "POST",
            "/api/commands",
            json!({"action": "kill.release", "payload": {"changeId": "k1", "scope": "agent", "vmId": "a1", "agents": []}}),
        )
        .await;
    assert_eq!(r.body["status"], json!("applied"), "{:?}", r.body);
    let calls = w.calls.lock().expect("calls").clone();
    assert_eq!(
        calls.iter().map(|c| c.0.as_str()).collect::<Vec<_>>(),
        ["kill.release", "kill.confirm"]
    );
    assert_eq!(
        calls[1].1,
        json!({"changeId": "k1", "code": "424242", "scope": "agent", "vmId": "a1"})
    );
}

#[tokio::test]
async fn a_release_of_everything_also_releases_each_agent_stopped_on_its_own() {
    let mut w = world();
    let set = |kill: Value| -> Arc<dyn Fn() -> serde_json::Map<String, Value> + Send + Sync> {
        Arc::new(move || {
            let mut m = serde_json::Map::new();
            m.insert("kill".into(), kill.clone());
            m
        })
    };
    let releases = |w: &World| -> Vec<(Value, Value)> {
        let calls = w.calls.lock().expect("calls").clone();
        calls
            .iter()
            .filter(|c| c.0 == "kill.release")
            .map(|c| (c.1["scope"].clone(), c.1.get("vmId").cloned().unwrap_or(Value::Null)))
            .collect()
    };
    // One agent stopped on its own, nothing org-wide: that agent's release, not an org one.
    w.ctx.hooks.status = set(json!({"org": null, "agents": [{"vmId": "a1", "name": "Atlas"}]}));
    let r = w.send("POST", "/api/kill/release", json!({})).await;
    assert_eq!(r.body["status"], json!("applied"), "{:?}", r.body);
    assert_eq!(releases(&w), [(json!("agent"), json!("a1"))]);
    // Both: the org stop first (an agent's release under it starts nothing), then the agent.
    w.calls.lock().expect("calls").clear();
    w.ctx.hooks.status = set(json!({"org": {"at": "t"}, "agents": [{"vmId": "a1"}]}));
    w.send("POST", "/api/kill/release", json!({"vmId": null})).await;
    assert_eq!(
        releases(&w),
        [(json!("org"), Value::Null), (json!("agent"), json!("a1"))]
    );
    // Nothing stopped: one org release, as before.
    w.calls.lock().expect("calls").clear();
    w.ctx.hooks.status = set(json!({"org": null, "agents": []}));
    w.send("POST", "/api/kill/release", json!({})).await;
    assert_eq!(releases(&w), [(json!("org"), Value::Null)]);
}

#[tokio::test]
async fn the_whole_list_gets_the_same_checks_as_one_rule() {
    let w = world();
    for (bad, why) in [
        (json!({"match_domain": "x.example", "effect": "nope"}), "effect"),
        (json!({"match_domain": "x.example", "priority": -5}), "priority"),
        (json!({"match_domain": "x.example", "vm_id": "zz"}), "agent"),
        (
            json!({"match_domain": "x.example", "effect": "block", "exit": "residential"}),
            "residential",
        ),
    ] {
        let r = w.send("PUT", "/api/egress-rules", json!({"rules": [bad]})).await;
        assert_eq!(r.status, 400, "{why}: {:?}", r.body);
    }
    // Settled as one rule is: no port on an allow rule, no AI review on a block rule.
    let r = w
        .send(
            "PUT",
            "/api/egress-rules",
            json!({"rules": [{"match_domain": "a.example", "match_port": 443}, {"match_domain": "b.example", "effect": "block", "ai_review": true}]}),
        )
        .await;
    assert_eq!(r.status, 200, "{:?}", r.body);
    let list = w.send("GET", "/api/egress/rules", Value::Null).await.body;
    assert_eq!(list[0]["matchPort"], Value::Null);
    assert_eq!(list[1]["aiReview"], json!(false));
}

#[tokio::test]
async fn commands_leave_the_panels_own_records_to_their_routes() {
    let w = world();
    for action in [
        "llm.propose",
        "llm.forget",
        "search.propose",
        "search.push",
        "channels.propose",
    ] {
        let r = w
            .send("POST", "/api/commands", json!({"action": action, "payload": {}}))
            .await;
        assert_eq!(r.status, 403, "{action}: {:?}", r.body);
    }
    // The stop is typed there too.
    let engage = json!({"changeId": "k1", "scope": "org", "agents": []});
    assert_eq!(
        w.send(
            "POST",
            "/api/commands",
            json!({"action": "kill.engage", "payload": engage})
        )
        .await
        .status,
        400
    );
    let mut typed = engage.clone();
    typed["confirm"] = json!("STOP");
    assert_eq!(
        w.send(
            "POST",
            "/api/commands",
            json!({"action": "kill.engage", "payload": typed})
        )
        .await
        .status,
        200
    );
}

#[tokio::test]
async fn the_whole_list_keeps_a_residential_exit_and_its_country() {
    let w = world();
    let r = w
        .send(
            "PUT",
            "/api/egress-rules",
            json!({"rules": [{"match_domain": "shop.example", "exit": "residential", "exit_country": "de"}]}),
        )
        .await;
    assert_eq!(r.status, 200, "{:?}", r.body);
    let list = w.send("GET", "/api/egress/rules", Value::Null).await.body;
    assert_eq!(
        (list[0]["exit"].clone(), list[0]["exitCountry"].clone()),
        (json!("residential"), json!("DE"))
    );
    assert_eq!(
        w.send(
            "PUT",
            "/api/egress-rules",
            json!({"rules": [{"match_domain": "shop.example", "exit": "residential", "exit_country": "Germany"}]})
        )
        .await
        .status,
        400
    );
}

/// A firewall with a GitHub connection, an MCP sign-in waiting on state `s-mcp`, and nothing else.
fn integrations_world() -> World {
    let mut w = world();
    let calls = w.calls.clone();
    w.ctx.hooks.command = Arc::new(move |action, payload| {
        calls
            .lock()
            .expect("calls")
            .push((action.clone(), Value::Object(payload.clone())));
        Box::pin(async move {
            let state = payload.get("state").cloned().unwrap_or(Value::Null);
            Some(match action.as_str() {
                "connectors.read" => {
                    json!({"ok": true, "status": "done", "data": {"kind": "connections", "connections": [{"id": "c1", "service": "github"}]}})
                }
                "connectors.propose" => {
                    json!({"ok": true, "status": "applied", "data": {"changeId": payload["changeId"]}})
                }
                "connectors.callback" => {
                    json!({"ok": false, "status": "expired", "message": "no", "data": {"state": state}})
                }
                "mcpservers.callback" if state == json!("s-mcp") => {
                    json!({"ok": true, "status": "applied", "data": {"changeId": "m1"}})
                }
                "mcpservers.callback" => {
                    json!({"ok": false, "status": "expired", "message": "no", "data": {"state": state}})
                }
                "google.callback" => {
                    json!({"ok": false, "status": "failed", "message": "This sign-in does not match an authorization your firewall started."})
                }
                _ => json!({"ok": true, "status": "done"}),
            })
        })
    });
    w
}

#[tokio::test]
async fn a_change_to_a_connection_names_its_app() {
    let w = integrations_world();
    let r = w.send("DELETE", "/api/connectors/c1", Value::Null).await;
    assert_eq!(r.status, 200, "{:?}", r.body);
    let propose = w
        .calls
        .lock()
        .expect("calls")
        .iter()
        .find(|c| c.0 == "connectors.propose")
        .cloned()
        .expect("propose");
    assert_eq!(
        (propose.1["service"].clone(), propose.1["kind"].clone()),
        (json!("github"), json!("remove"))
    );
    assert_eq!(w.send("DELETE", "/api/connectors/nope", Value::Null).await.status, 404);
    assert_eq!(
        w.send(
            "POST",
            "/api/connectors",
            json!({"service": "google-drive", "apiKey": "k"})
        )
        .await
        .status,
        400
    );
}

#[tokio::test]
async fn a_sign_in_goes_to_the_module_that_started_it() {
    let w = integrations_world();
    let r = w
        .send("POST", "/api/oauth/callback", json!({"state": "s-mcp", "code": "abc"}))
        .await;
    assert_eq!(
        (r.status, r.body["status"].clone()),
        (200, json!("applied")),
        "{:?}",
        r.body
    );
    // Nobody's: refused with the last module's answer.
    let r = w
        .send("POST", "/api/oauth/callback", json!({"state": "forged", "code": "abc"}))
        .await;
    assert_eq!(r.status, 409, "{:?}", r.body);
    // The connectors' own refusal ("start it again"), not Google's.
    assert_eq!(r.body["status"], json!("expired"), "{:?}", r.body);
    let tried: Vec<String> = w.calls.lock().expect("calls").iter().map(|c| c.0.clone()).collect();
    assert_eq!(
        tried.iter().filter(|a| a.as_str() == "google.callback").count(),
        1,
        "{tried:?}"
    );
}

#[tokio::test]
async fn a_bot_goes_to_the_firewall_with_the_last_characters_of_its_token() {
    let w = world();
    let r = w
        .send(
            "POST",
            "/api/channels",
            json!({"type": "telegram", "botToken": "123456:AAtokentokentokené"}),
        )
        .await;
    assert_eq!(r.status, 200, "{:?}", r.body);
    let propose = w
        .calls
        .lock()
        .expect("calls")
        .iter()
        .find(|c| c.0 == "channels.propose")
        .cloned()
        .expect("propose");
    assert_eq!(propose.1["hint"], json!("…kené"));
    assert_eq!(propose.1["secret"]["botToken"], json!("123456:AAtokentokentokené"));
}

/// A firewall that lists one bot, `ch1`, on agent a1, and otherwise answers as `world()` does.
fn bot_world() -> World {
    let mut w = world();
    let (calls, inner) = (w.calls.clone(), w.ctx.hooks.command.clone());
    w.ctx.hooks.command = Arc::new(move |action, payload| {
        if action == "channels.read" {
            calls
                .lock()
                .expect("calls")
                .push((action.clone(), Value::Object(payload)));
            return Box::pin(async {
                Some(json!({"ok": true, "status": "done", "data": {"connections": [
                    {"id": "ch1", "type": "telegram", "hint": "…abcd", "label": "@bot", "assignedVmId": "a1", "approvedSenders": 0}
                ]}}))
            });
        }
        inner(action, payload)
    });
    w
}

#[tokio::test]
async fn a_real_agent_goes_through_the_contract_checks() {
    let w = bot_world();
    // An agent's ref as the agents table makes it ({vmId, name, hostname, privateIp}) passes the
    // contract's types on each kind of change that names one.
    let r = w
        .send(
            "POST",
            "/api/channels",
            json!({"type": "slack", "botToken": "xoxb-1-2-abcdefgh", "appToken": "xapp-1-abc", "vmId": "a1"}),
        )
        .await;
    assert_eq!(r.status, 200, "add: {:?}", r.body);
    let r = w
        .send(
            "POST",
            "/api/channels/ch1/pairing",
            json!({"code": "ABCD1234", "senderId": "42"}),
        )
        .await;
    assert_eq!(r.status, 200, "pairing: {:?}", r.body);
    let r = w.send("POST", "/api/channels/ch1/unassign", Value::Null).await;
    assert_eq!(r.status, 200, "unassign: {:?}", r.body);
    // a1 has a Telegram bot already: a second one there is refused before the firewall is asked.
    let r = w
        .send(
            "POST",
            "/api/channels",
            json!({"type": "telegram", "botToken": "123:AAAAAAAAAA", "vmId": "a1"}),
        )
        .await;
    assert_eq!(r.status, 409, "{:?}", r.body);
    let proposals: Vec<Value> = w
        .calls
        .lock()
        .expect("calls")
        .iter()
        .filter(|c| c.0 == "channels.propose")
        .map(|c| c.1.clone())
        .collect();
    assert_eq!(
        proposals[0]["agent"],
        // No hostname: named by its address, where the firewall's call goes.
        json!({"vmId": "a1", "name": "Atlas", "hostname": "10.0.0.3", "privateIp": "10.0.0.3"})
    );
    assert_eq!(proposals[1]["pairing"]["code"], json!("ABCD1234"));
    // Assigning needs the agent: a1, then the stop and an AgentMail inbox name it too.
    let r = w
        .send(
            "POST",
            "/api/connectors",
            json!({"service": "github", "apiKey": "k", "vmIds": ["a1"]}),
        )
        .await;
    assert_eq!(r.status, 200, "connect: {:?}", r.body);
    // An agent with no address at all is refused (agentmail_refuses_an_unknown_agent_or_an_empty_address).
    let create = json!({"vmId": "a1", "username": "atlas"});
    w.ctx
        .db
        .lock()
        .execute("UPDATE agents SET hostname = 'atlas.example' WHERE vm_id = 'a1'", [])
        .expect("hostname");
    let r = w.send("POST", "/api/agentmail/create", create).await;
    assert_eq!(r.status, 200, "agentmail: {:?}", r.body);
    let create = w
        .calls
        .lock()
        .expect("calls")
        .iter()
        .find(|c| c.0 == "agentmail.create")
        .cloned()
        .expect("create");
    // The agent's address is filled in; the inbox's name is the caller's to give.
    assert_eq!(create.1["hostname"], json!("atlas.example"));
    assert!(create.1.get("name").is_none(), "{}", create.1);
}

#[tokio::test]
async fn google_and_logins() {
    let w = world();
    let r = w
        .send(
            "POST",
            "/api/google",
            json!({"clientId": "123-abc.apps.googleusercontent.com", "clientSecret": "s", "services": ["gmail", "calendar"], "audience": "external_testing", "vmIds": ["a1"]}),
        )
        .await;
    assert_eq!(r.status, 200, "{:?}", r.body);
    let p = w
        .calls
        .lock()
        .expect("calls")
        .iter()
        .find(|c| c.0 == "google.propose")
        .cloned()
        .expect("propose")
        .1;
    assert_eq!(p["kind"], json!("connect_account"));
    assert!(
        p["client"]["redirectUri"]
            .as_str()
            .is_some_and(|u| u.ends_with("/oauth/callback")),
        "{p}"
    );
    assert_eq!(p["clientSecret"], json!("s"));
    assert_eq!(
        w.send(
            "POST",
            "/api/google",
            json!({"clientId": "nope", "clientSecret": "s", "services": ["gmail"], "audience": "internal"})
        )
        .await
        .status,
        400
    );
    assert_eq!(
        w.send("PUT", "/api/google/services", json!({"services": ["fax"]}))
            .await
            .status,
        400
    );
    // A login change is confirmed with its id, as the module's confirm reads it.
    let r = w
        .send(
            "POST",
            "/api/logins/change",
            json!({"action": "update", "id": "lg_1", "sites": ["example.com"], "vmIds": ["a1"]}),
        )
        .await;
    assert_eq!(r.status, 200, "{:?}", r.body);
    let confirm = w
        .calls
        .lock()
        .expect("calls")
        .iter()
        .find(|c| c.0 == "logins.confirm")
        .cloned()
        .expect("confirm")
        .1;
    assert_eq!(
        (confirm["id"].clone(), confirm["code"].clone()),
        (json!("lg_1"), json!("424242"))
    );
    assert_eq!(w.send("POST", "/api/agentmail/nope", json!({})).await.status, 404);
}

#[tokio::test]
async fn agentmail_needs_an_address_only_to_write_an_inbox_and_mcp_a_public_name() {
    let w = world();
    // a1 has no address: forgetting its inboxes still works, and the inbox name stays the caller's.
    let r = w.send("POST", "/api/agentmail/forget", json!({"vmId": "a1"})).await;
    assert_eq!(r.status, 200, "{:?}", r.body);
    let forget = w
        .calls
        .lock()
        .expect("calls")
        .iter()
        .find(|c| c.0 == "agentmail.forget")
        .cloned()
        .expect("forget")
        .1;
    assert!(
        forget.get("name").is_none() && forget.get("hostname").is_none(),
        "{forget}"
    );
    for url in ["https://intranet/mcp", "http://mcp.example.com/mcp"] {
        let r = w
            .send(
                "POST",
                "/api/mcp-servers",
                json!({"name": "x", "url": url, "auth": "none"}),
            )
            .await;
        assert_eq!(r.status, 400, "{url}");
    }
    let r = w
        .send(
            "POST",
            "/api/mcp-servers",
            json!({"name": "x", "url": "https://[2001:db8::1]/mcp", "auth": "none"}),
        )
        .await;
    assert_eq!(r.status, 200, "an address is the module's to check: {:?}", r.body);
}

#[tokio::test]
async fn an_inbox_goes_to_the_paired_address_whatever_the_request_says() {
    let w = world();
    w.ctx
        .db
        .lock()
        .execute("UPDATE agents SET hostname = 'atlas.example' WHERE vm_id = 'a1'", [])
        .expect("hostname");
    let body = json!({"vmId": "a1", "username": "atlas", "hostname": "evil.example"});
    assert_eq!(w.send("POST", "/api/agentmail/create", body.clone()).await.status, 200);
    let r = w
        .send(
            "POST",
            "/api/commands",
            json!({"action": "agentmail.create", "payload": body}),
        )
        .await;
    assert_eq!(r.status, 200, "{:?}", r.body);
    let sent: Vec<Value> = w
        .calls
        .lock()
        .expect("calls")
        .iter()
        .filter(|c| c.0 == "agentmail.create")
        .map(|c| c.1.clone())
        .collect();
    assert_eq!(sent.len(), 2);
    for p in sent {
        assert_eq!(p["hostname"], json!("atlas.example"), "{p}");
    }
    // A forget names no address at all, and a sent one is dropped.
    w.send(
        "POST",
        "/api/agentmail/forget",
        json!({"vmId": "a1", "hostname": "evil.example"}),
    )
    .await;
    let forget = w
        .calls
        .lock()
        .expect("calls")
        .iter()
        .find(|c| c.0 == "agentmail.forget")
        .cloned()
        .expect("forget")
        .1;
    assert!(forget.get("hostname").is_none(), "{forget}");
}

#[test]
fn google_takes_https_or_localhost_only() {
    use super::accounts::google_takes;
    for ok in [
        "https://fw.example.com/oauth/callback",
        "http://localhost:8800/oauth/callback",
        "http://127.0.0.1:8800/oauth/callback",
    ] {
        assert!(google_takes(ok), "{ok}");
    }
    for no in [
        "http://10.0.0.2:8800/oauth/callback",
        "http://fw.example.com/oauth/callback",
        "ftp://x/",
    ] {
        assert!(!google_takes(no), "{no}");
    }
}

#[tokio::test]
async fn a_secret_change_is_confirmed_with_its_name() {
    let w = world();
    let r = w
        .send("POST", "/api/commands", json!({"action": "secrets.propose", "payload": {"changeId": "s1", "action": "remove", "name": "STRIPE_KEY"}}))
        .await;
    assert_eq!(r.body["status"], json!("applied"), "{:?}", r.body);
    let confirm = w
        .calls
        .lock()
        .expect("calls")
        .iter()
        .find(|c| c.0 == "secrets.confirm")
        .cloned()
        .expect("confirm")
        .1;
    assert_eq!(
        confirm,
        json!({"changeId": "s1", "code": "424242", "name": "STRIPE_KEY"})
    );
}

#[tokio::test]
async fn a_bot_can_be_removed_by_force() {
    let w = bot_world();
    assert_eq!(
        w.send("DELETE", "/api/channels/ch1?force=true", Value::Null)
            .await
            .status,
        200
    );
    assert_eq!(w.send("DELETE", "/api/channels/ch1", Value::Null).await.status, 200);
    let removes: Vec<Value> = w
        .calls
        .lock()
        .expect("calls")
        .iter()
        .filter(|c| c.0 == "channels.propose")
        .map(|c| c.1.clone())
        .collect();
    assert_eq!(removes[0]["force"], json!(true));
    assert!(removes[1].get("force").is_none());
}

#[tokio::test]
async fn agentmail_refuses_an_unknown_agent_or_an_empty_address() {
    let w = world();
    assert_eq!(
        w.send("POST", "/api/agentmail/forget", json!({"vmId": "typo"}))
            .await
            .status,
        404
    );
    w.ctx
        .db
        .lock()
        .execute(
            "UPDATE agents SET hostname = '', private_ip = '' WHERE vm_id = 'a1'",
            [],
        )
        .expect("hostname");
    assert_eq!(
        w.send(
            "POST",
            "/api/agentmail/create",
            json!({"vmId": "a1", "username": "atlas"})
        )
        .await
        .status,
        400
    );
}

#[tokio::test]
async fn every_other_site_is_allow_until_the_admin_blocks_it() {
    let w = world();
    let effect = |r: Reply| r.body["effect"].clone();
    assert_eq!(
        effect(w.send("GET", "/api/egress/default", Value::Null).await),
        json!("allow")
    );
    let r = w.send("PUT", "/api/egress/default", json!({"effect": "block"})).await;
    assert_eq!((r.status, r.body["effect"].clone()), (200, json!("block")));
    assert_eq!(*w.woken.lock().expect("woken"), 1, "the firewall syncs at once");
    // Twice is once: one rule, after every other.
    w.send("PUT", "/api/egress/default", json!({"effect": "block"})).await;
    let rules = crate::plane::ControlPlane::call(
        &*w.ctx.plane,
        "fw",
        crate::plane::Call {
            method: "GET".into(),
            path: "/api/vm-agent/egress-rules".into(),
            ..Default::default()
        },
    )
    .await
    .body["rules"]
        .clone();
    assert_eq!(
        rules,
        json!([{"id": "block-all", "name": "Every other site", "match_domain": "*", "effect": "block", "priority": 100000}])
    );
    // Not a rule in the list, and not one to change there.
    let list = w.send("GET", "/api/egress/rules", Value::Null).await;
    assert_eq!(list.body, json!([]));
    for (m, path) in [
        ("PATCH", "/api/egress/rules/block-all"),
        ("POST", "/api/egress/rules/block-all/cycle"),
        ("DELETE", "/api/egress/rules/block-all"),
    ] {
        let r = w
            .send(m, path, if m == "PATCH" { json!({}) } else { Value::Null })
            .await;
        assert_eq!(r.status, 400, "{m} {path}");
        assert!(
            r.body["error"].as_str().is_some_and(|e| e.contains("Every other site")),
            "{:?}",
            r.body
        );
    }
    // The whole list, written back as it was read, leaves it blocked; it cannot name or bend it.
    let whole = w.send("GET", "/api/egress-rules", Value::Null).await.body;
    assert_eq!(whole["rules"], json!([]));
    let r = w
        .send(
            "PUT",
            "/api/egress-rules",
            json!({"rules": [{"match_domain": "example.com"}]}),
        )
        .await;
    assert_eq!(r.status, 200, "{:?}", r.body);
    assert_eq!(
        effect(w.send("GET", "/api/egress/default", Value::Null).await),
        json!("block")
    );
    let r = w
        .send(
            "PUT",
            "/api/egress-rules",
            json!({"rules": [{"id": "block-all", "match_domain": "*", "effect": "allow"}]}),
        )
        .await;
    assert_eq!(r.status, 400, "{:?}", r.body);
    w.send("PUT", "/api/egress/default", json!({"effect": "allow"})).await;
    assert_eq!(
        effect(w.send("GET", "/api/egress/default", Value::Null).await),
        json!("allow")
    );
    assert_eq!(
        w.send("PUT", "/api/egress/default", json!({"effect": "ask"}))
            .await
            .status,
        400
    );
}

#[tokio::test]
async fn a_model_key_and_a_bot_bring_their_rules_which_cannot_be_changed() {
    let w = bot_world();
    w.ctx
        .db
        .lock()
        .execute(
            "INSERT INTO llm_keys (id, provider, hint, placeholder, state, created_at, updated_at)
             VALUES ('k1', 'openrouter', '…1', 'x', 'active', 0, 0)",
            [],
        )
        .expect("key");
    // The bot list as the firewall holds it: bot ch1 on a1.
    assert_eq!(w.send("GET", "/api/channels", Value::Null).await.status, 200);
    assert_eq!(*w.woken.lock().expect("woken"), 1, "a new bot starts a sync");
    w.send("GET", "/api/channels", Value::Null).await;
    assert_eq!(*w.woken.lock().expect("woken"), 1, "the same list does not");
    let list = w.send("GET", "/api/egress/rules", Value::Null).await.body;
    let managed: Vec<(Value, Value, Value)> = list
        .as_array()
        .expect("list")
        .iter()
        .map(|r| (r["id"].clone(), r["managed"].clone(), r["vmId"].clone()))
        .collect();
    assert_eq!(
        managed,
        vec![
            (
                json!("managed:openrouter:openrouter.ai"),
                json!("openrouter"),
                Value::Null
            ),
            (
                json!("managed:telegram:api.telegram.org:a1"),
                json!("telegram"),
                json!("a1")
            ),
        ]
    );
    let id = "managed:telegram:api.telegram.org:a1";
    for (m, path) in [
        ("PATCH", format!("/api/egress/rules/{id}")),
        ("POST", format!("/api/egress/rules/{id}/cycle")),
        ("DELETE", format!("/api/egress/rules/{id}")),
    ] {
        let body = if m == "PATCH" {
            json!({"effect": "block"})
        } else {
            Value::Null
        };
        assert_eq!(w.send(m, &path, body).await.status, 403, "{m}");
    }
    // Nor written as a row through the whole list.
    let r = w
        .send(
            "PUT",
            "/api/egress-rules",
            json!({"rules": [{"id": "managed:x", "match_domain": "evil.example"}]}),
        )
        .await;
    assert_eq!(r.status, 400, "{:?}", r.body);
}

#[tokio::test]
async fn routine_traffic_is_out_of_activity_unless_asked_or_searched() {
    let w = world();
    let now = crate::db::now_s() as f64;
    let tg = |id: &str, ts: f64, more: Value| {
        let mut r = json!({"source": "egress", "flow_id": id, "ts": now - ts, "effect": "allow", "host": "api.telegram.org",
                           "method": "POST", "path": "/bot<redacted>/getUpdates", "vm_id": "a1", "status": 200,
                           "rule": "Channel: Telegram", "rule_id": "managed:telegram:api.telegram.org:a1", "managed": "telegram",
                           "swapped": ["CC-TG-1"]});
        for (k, v) in more.as_object().expect("more") {
            r[k] = v.clone();
        }
        r
    };
    ship(
        &w,
        json!([
            tg("r1", 9.0, json!({})),
            tg("r2", 8.0, json!({})),
            // Failed, refused, and someone else's token: all stay.
            tg("f1", 7.0, json!({"status": 502})),
            tg("b1", 6.0, json!({"effect": "block"})),
            tg("x1", 5.0, json!({"swapped": []})),
            {"source": "egress", "flow_id": "o1", "ts": now - 4.0, "effect": "allow", "host": "api.github.com", "method": "GET", "path": "/", "vm_id": "a1"},
        ]),
    )
    .await;
    let r = w.send("GET", "/api/activity?source=network", Value::Null).await;
    assert_eq!(r.status, 200, "{:?}", r.body);
    assert_eq!(
        (r.body["total"].clone(), r.body["routine"].clone()),
        (json!(4), json!(2))
    );
    assert_eq!(
        r.body["counts"]["allow"],
        json!(3),
        "not counted in the list's own tabs either"
    );
    let all = w
        .send("GET", "/api/activity?source=network&routine=true", Value::Null)
        .await;
    assert_eq!(
        (all.body["total"].clone(), all.body["routine"].clone()),
        (json!(6), json!(0))
    );
    let site = w
        .send("GET", "/api/activity?source=network&q=telegram", Value::Null)
        .await;
    assert_eq!(site.body["total"], json!(5), "a search for the site shows them");
    let blocked = w
        .send("GET", "/api/activity?source=network&verdict=block", Value::Null)
        .await;
    assert_eq!(
        (blocked.body["total"].clone(), blocked.body["routine"].clone()),
        (json!(1), json!(0)),
        "none could show there"
    );
    let failed = r.body["rows"]
        .as_array()
        .expect("rows")
        .iter()
        .find(|x| x["statusCode"] == json!(502));
    assert!(failed.is_some(), "the status shows: {:?}", r.body["rows"]);
    // The overview still counts them.
    let o = w.send("GET", "/api/overview?range=1h", Value::Null).await;
    let allowed: i64 = o.body["traffic"]["points"]
        .as_array()
        .expect("points")
        .iter()
        .map(|p| p["allowed"].as_i64().unwrap_or(0))
        .sum();
    assert_eq!(allowed, 5);
}
