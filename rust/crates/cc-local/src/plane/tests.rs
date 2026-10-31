//! The local control plane's answers, endpoint by endpoint. The conformance cases (`cases/cp`)
//! hold it to the SaaS's answers over HTTP; these check what they cannot see.

use std::sync::Arc;

use serde_json::{Value, json};

use super::*;

fn plane() -> LocalControlPlane {
    let p = LocalControlPlane::new(Arc::new(Db::memory().expect("db")));
    p.register_self("fw").expect("self");
    p.db.lock()
        .execute(
            "INSERT INTO agents (vm_id, role, name, private_ip, created_at) VALUES ('a1', 'openclaw', 'agent-1', '10.0.0.3', 1)",
            [],
        )
        .expect("agent");
    p
}

fn call(p: &LocalControlPlane, who: &str, method: &str, path: &str, query: &str, body: Option<Value>) -> Answer {
    p.handle(
        who,
        &Call {
            method: method.into(),
            path: format!("/api/vm-agent{path}"),
            query: query.into(),
            body,
        },
    )
}

#[test]
fn an_unknown_caller_and_a_saas_only_endpoint() {
    let p = plane();
    assert_eq!(call(&p, "nobody", "GET", "/identities", "", None).status, 401);
    assert_eq!(call(&p, "fw", "GET", "/store", "", None).status, 404);
    assert_eq!(call(&p, "fw", "GET", "/firewall", "", None).status, 405);
}

#[test]
fn a_beat_never_gets_a_command() {
    let p = plane();
    let a = call(&p, "fw", "POST", "/firewall", "", Some(json!({"proxy": "active"})));
    assert_eq!(a, Answer::ok(json!({"command": null})));
    assert!(p.db.setting("last_beat").is_some());
    assert_eq!(call(&p, "fw", "POST", "/firewall", "", Some(json!({}))).status, 400);
    assert_eq!(
        call(&p, "a1", "POST", "/firewall", "", Some(json!({"proxy": "active"}))).status,
        403
    );
}

#[test]
fn activity_is_rolled_up_by_hour_once() {
    let p = plane();
    // The hour before this one, so no record of the test crosses an hour or the clamp.
    let hour = now_s() - now_s().rem_euclid(3600) - 3600;
    let rec = |f: &str, ts: i64| json!({"flow_id": f, "ts": ts as f64 + 0.5, "vm_id": "a1", "host": "example.com", "effect": "allow"});
    let batch = json!({"records": [rec("f1", hour + 10), rec("f2", hour + 20), {"flow_id": "bad"}]});
    let a = call(&p, "fw", "POST", "/activity", "", Some(batch));
    assert_eq!(a.body, json!({"accepted": 2, "duplicates": 0, "skipped": 1}));
    let a = call(
        &p,
        "fw",
        "POST",
        "/activity",
        "",
        Some(json!({"records": [rec("f1", hour + 10)]})),
    );
    assert_eq!(a.body, json!({"accepted": 0, "duplicates": 1}));
    let n: i64 =
        p.db.lock()
            .query_row(
                "SELECT count FROM activity_hourly WHERE hour = ?1 AND vm_id = 'a1' AND status = 'allow'",
                [hour],
                |r| r.get(0),
            )
            .expect("rollup");
    assert_eq!(n, 2);
}

#[test]
fn a_box_clock_cannot_file_activity_outside_the_window_and_keys_are_the_saas_ones() {
    let p = plane();
    let now = now_s();
    let old = json!({"flow_id": "old", "ts": 1.0, "vm_id": "a1", "host": "a.example", "effect": "block"});
    let ahead =
        json!({"flow_id": "ahead", "ts": (now + 86_400) as f64, "vm_id": "a1", "host": "b.example", "effect": "allow"});
    let finding = json!({"source": "ai_review", "finding_id": "x1", "severity": "high", "ts": now as f64});
    let nameless = json!({"source": "ai_review", "severity": "low"});
    let a = call(
        &p,
        "fw",
        "POST",
        "/activity",
        "",
        Some(json!({"records": [old, ahead, finding, nameless]})),
    );
    assert_eq!(
        a.body,
        json!({"accepted": 3, "duplicates": 0, "skipped": 1}),
        "a finding needs its finding_id"
    );
    let rows: Vec<(String, i64, String)> = {
        let c = p.db.lock();
        let mut q = c
            .prepare("SELECT dedupe_key, occurred_at, status FROM activity_raw ORDER BY id")
            .expect("q");
        q.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .expect("rows")
            .collect::<rusqlite::Result<_>>()
            .expect("all")
    };
    assert_eq!(rows[0].0, "fw:egress:old");
    assert!(rows[0].1 >= now - 30 * 86_400 - 5, "kept inside the retention window");
    assert!(rows[1].1 <= now_s() + 300, "never more than 5 minutes ahead");
    assert_eq!((rows[2].0.as_str(), rows[2].2.as_str()), ("fw:ai:x1", "high"));
}

#[test]
fn a_person_answers_a_permission_request() {
    let p = plane();
    let raise =
        json!({"permission_id": "p1", "kind": "access", "host": "example.com", "method": "POST", "agent_vm_id": "a1"});
    assert_eq!(
        call(&p, "fw", "POST", "/permission", "", Some(raise)).body,
        json!({"ok": true, "status": "pending"})
    );
    let row = p.pending_row("p1").expect("db").expect("pending");
    assert_eq!(
        p.resolve_permission(row, "approved").expect("db").as_deref(),
        Some("approved")
    );
    assert_eq!(p.resolve_permission(row, "denied").expect("db"), None, "settled once");
    let a = call(&p, "a1", "GET", "/permission", "permission_id=p1", None);
    assert_eq!(a.body["status"], "approved");
}

#[test]
fn iso_round_trips() {
    for s in [0, 1_761_800_000, 1_793_368_031] {
        assert_eq!(parse_iso(&iso(s)), Some(s));
    }
    assert_eq!(iso(1_761_800_000), "2025-10-30T04:53:20.000Z");
}

#[test]
fn an_expired_request_cannot_be_approved() {
    let p = plane();
    let raise = json!({"permission_id": "p2", "kind": "access", "host": "example.com", "expires_at": "2001-01-01T00:00:00.000Z"});
    assert_eq!(call(&p, "fw", "POST", "/permission", "", Some(raise)).status, 200);
    let row: i64 =
        p.db.lock()
            .query_row("SELECT id FROM permission_requests WHERE external_id = 'p2'", [], |r| {
                r.get(0)
            })
            .expect("row");
    assert_eq!(p.resolve_permission(row, "approved").expect("db"), None);
    assert_eq!(
        call(&p, "fw", "GET", "/permission", "permission_id=p2", None).body["status"],
        "expired"
    );
}

#[test]
fn an_agent_ships_only_about_itself_and_ids_are_per_box() {
    let p = plane();
    p.db.lock()
        .execute("INSERT INTO agents (vm_id, role, name, private_ip, created_at) VALUES ('a2', 'openclaw', 'agent-2', '10.0.0.4', 1)", [])
        .expect("agent");
    let run = json!({"source": "agent_run", "run_id": "r1", "vm_id": "a2", "ts": 7200.0});
    assert_eq!(
        call(
            &p,
            "a1",
            "POST",
            "/activity",
            "",
            Some(json!({"records": [run.clone()]}))
        )
        .body["accepted"],
        1
    );
    assert_eq!(
        call(&p, "a2", "POST", "/activity", "", Some(json!({"records": [run]}))).body["accepted"],
        1,
        "another box's r1"
    );
    let owners: Vec<String> = {
        let c = p.db.lock();
        let mut q = c.prepare("SELECT vm_id FROM activity_raw ORDER BY id").expect("q");
        q.query_map([], |r| r.get(0))
            .expect("rows")
            .collect::<rusqlite::Result<_>>()
            .expect("all")
    };
    assert_eq!(owners, ["a1", "a2"], "a1's record names a2 but is a1's");
}

#[test]
fn only_block_all_is_the_new_databases_state() {
    let d = tempfile::tempdir().expect("dir");
    let p = LocalControlPlane::new(Arc::new(Db::open(&d.path().join("local.db")).expect("db")));
    p.register_self("fw").expect("self");
    assert!(p.only_block_all().expect("only"));
    assert_eq!(
        call(&p, "fw", "GET", "/egress-rules", "", None).body["rules"],
        json!([{"id": BLOCK_ALL_ID, "name": BLOCK_ALL_NAME, "match_domain": "*", "effect": "block", "priority": BLOCK_ALL_PRIORITY}])
    );
    p.db.lock().execute("DELETE FROM egress_rules", []).expect("delete");
    assert!(!p.only_block_all().expect("none"));
}
