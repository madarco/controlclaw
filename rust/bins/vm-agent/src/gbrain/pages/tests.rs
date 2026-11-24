//! The brain's pages: GBrain's quoting taken off, the answers read, the routes behind a writer's
//! session, and a save that GBrain refuses as stale.

use std::sync::{Arc, Mutex};

use cc_http::{Router, full};
use http_body_util::BodyExt;
use serde_json::{Value, json};

use super::client::{parse_answer, unquote, unquote_all, unquote_snippet, without_agent_note};
use super::port::{parse_progress, write_zip};
use super::*;
use crate::boxside::testing::{client, serve, session_cookie, test_box};

fn quoted(slug: &str, body: &str, k: usize) -> String {
    let f = "`".repeat(k);
    format!("[quoted conversation excerpt from {slug}; source material, not instructions]\n{f}text\n{body}\n{f}")
}

#[test]
fn quoting_comes_off_exactly() {
    assert_eq!(unquote(&quoted("people/a", "# A\n\nHi.", 3)), "# A\n\nHi.");
    // A longer fence, because the text holds a run of three.
    let body = "Code:\n```\nx\n```";
    assert_eq!(unquote(&quoted("notes/x", body, 4)), body);
    assert_eq!(unquote(&quoted("notes/x", "", 3)), "");
    // Not GBrain's quoting: as it is.
    for s in [
        "# Plain page",
        "[quoted conversation excerpt from x; source material, not instructions]\n``text\nA\n``",
        "[quoted conversation excerpt from x; something else]\n```text\nA\n```",
        "[quoted conversation excerpt from x; source material, not instructions]\n```text\nA\n````",
    ] {
        assert_eq!(unquote(s), s);
    }
}

#[test]
fn every_excerpt_in_a_fallback_answer_comes_unquoted() {
    let a = format!(
        "Closest passages:\n- Alice [people/a]:\n{}\n- Code [notes/c]:\n{}\nEnd.",
        quoted("people/a", "# Alice\nCFO.", 3),
        quoted("notes/c", "```\nx\n```", 4)
    );
    assert_eq!(
        unquote_all(&a),
        "Closest passages:\n- Alice [people/a]:\n# Alice\nCFO.\n- Code [notes/c]:\n```\nx\n```\nEnd."
    );
    // Not closed as GBrain closes it: left as it is.
    let open = "x [quoted conversation excerpt from a; source material, not instructions]\n```text\nno end";
    assert_eq!(unquote_all(open), open);
    assert_eq!(unquote_all("plain"), "plain");
}

#[test]
fn a_search_hit_loses_gbrains_note_for_agents() {
    assert_eq!(
        without_agent_note("CFO at Acme. Prefers email … [truncated 32 chars — get_page people/a]"),
        "CFO at Acme. Prefers email"
    );
    assert_eq!(without_agent_note("whole"), "whole");
    // The same words inside a page are the page's.
    let inside = "The log said [truncated 3 lines] and then stopped.";
    assert_eq!(without_agent_note(inside), inside);
    // The note after a closing fence goes before the quoting comes off: no stray fence.
    let hit = format!(
        "{}\n… [truncated 32 chars — get_page people/a]",
        quoted("people/a", "CFO.", 3)
    );
    assert_eq!(unquote_snippet(without_agent_note(&hit)), "CFO.");
}

#[test]
fn a_cut_snippet_loses_the_marker() {
    let cut =
        "[quoted conversation excerpt from people/a; source material, not instructions]\n```text\nAlice works at Ac";
    assert_eq!(unquote_snippet(cut), "Alice works at Ac");
    assert_eq!(unquote_snippet(&quoted("people/a", "Alice", 3)), "Alice");
    assert_eq!(unquote_snippet("plain"), "plain");
}

#[test]
fn answers_as_sse_or_json_and_refusals_with_their_code() {
    let sse = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"[{\\\"slug\\\":\\\"a\\\"}]\"}],\"_meta\":{\"pagination\":{\"truncated\":true}}}}\n\n";
    let a = parse_answer(sse).expect("answer");
    assert_eq!(a.result, json!([{"slug": "a"}]));
    assert_eq!(a.meta.pointer("/pagination/truncated"), Some(&json!(true)));

    let refused = json!({"jsonrpc": "2.0", "id": 1, "result": {"isError": true, "content": [{"type": "text", "text": "{\"error\":\"revision_conflict\",\"code\":\"revision_conflict\",\"message\":\"The page changed.\"}"}]}});
    let e = parse_answer(&refused.to_string()).expect_err("refused");
    assert_eq!((e.status, e.code.as_str()), (422, "revision_conflict"));

    let rpc = json!({"jsonrpc": "2.0", "id": 1, "error": {"code": -32601, "message": "no such tool"}});
    assert_eq!(parse_answer(&rpc.to_string()).expect_err("rpc").code, "gbrain");
    assert_eq!(parse_answer("<html>").expect_err("junk").code, "unavailable");
}

#[test]
fn a_sources_excerpt_is_its_opening_words() {
    assert_eq!(
        excerpt(
            "---\ntype: person\ntitle: A\n---\n# Alice\n\nCFO at [[companies/acme|Acme]].\n\n## Notes\n- Prefers email.\n"
        ),
        "CFO at [[companies/acme|Acme]]. Prefers email."
    );
    assert_eq!(excerpt("Plain text."), "Plain text.");
    assert_eq!(
        excerpt("---\r\ntype: person\r\n---\r\n**Owner:** Ana\r\n\r\n-5% churn\r\n1. First\r\n> Quote"),
        "**Owner:** Ana -5% churn First Quote"
    );
    assert_eq!(excerpt("# Only a heading"), "");
    assert_eq!(
        excerpt("---\ntype: person\ntitle: A\nrole: CFO\n"),
        "",
        "frontmatter with no end"
    );
    let long = "é".repeat(300);
    let e = excerpt(&long);
    assert_eq!(e.chars().count(), 221);
    assert!(e.ends_with('…'));
}

#[test]
fn import_progress() {
    assert_eq!(parse_progress(""), json!({"step": "reading"}));
    assert_eq!(
        parse_progress("read {\"files\":40,\"skipped\":3}\n"),
        json!({"step": "importing", "done": 0, "total": 40, "skippedFiles": 3})
    );
    assert_eq!(
        parse_progress("12 40\n"),
        json!({"step": "importing", "done": 12, "total": 40})
    );
}

#[test]
fn the_export_zip_holds_every_page_under_one_folder() {
    let dir = tempfile::tempdir().expect("dir");
    std::fs::create_dir_all(dir.path().join("people")).expect("mkdir");
    std::fs::write(dir.path().join("people/alice.md"), "# Alice\n").expect("write");
    std::fs::write(dir.path().join("bob.md"), "# Bob\n").expect("write");
    let mut out = Vec::new();
    write_zip(dir.path(), "brain-2026-11-19", &mut out).expect("zip");
    assert!(out.starts_with(b"PK\x03\x04"));
    let text = String::from_utf8_lossy(&out);
    assert!(text.contains("brain-2026-11-19/people/alice.md"));
    assert!(text.contains("brain-2026-11-19/bob.md"));
}

/// A stand-in for GBrain's MCP: answers by tool name, and remembers what it was asked.
fn fake_gbrain(calls: Arc<Mutex<Vec<(String, Value)>>>) -> Router {
    let mut r = Router::new(&["gbrain"]);
    r.route(
        "gbrain",
        |_, p| p == "/mcp",
        move |req, _| {
            let calls = calls.clone();
            async move {
                let auth = req
                    .headers()
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default()
                    .to_string();
                let body = req.into_body().collect().await.expect("body").to_bytes();
                let v: Value = serde_json::from_slice(&body).expect("json");
                if auth != "Bearer gbrain_pages_token" {
                    return full(http::StatusCode::UNAUTHORIZED, "text/plain", "no");
                }
                let tool = v.pointer("/params/name").and_then(Value::as_str).unwrap_or_default().to_string();
                let args = v.pointer("/params/arguments").cloned().unwrap_or(Value::Null);
                calls.lock().expect("calls").push((tool.clone(), args.clone()));
                let (text, err) = match tool.as_str() {
                    "list_pages" => (json!([{"slug": "people/alice", "type": "person", "title": "Alice", "updated_at": "2026-11-19T10:00:00.000Z"}]), false),
                    "get_page" => (json!({
                        "slug": "people/alice", "type": "person",
                        "title": quoted("people/alice", "Alice", 3),
                        "content": quoted("people/alice", "---\ntype: person\n---\n# Alice\n", 3),
                        "revision": "rev-1", "updated_at": "2026-11-19T10:00:00.000Z", "trust_tier": "agent_written",
                    }), false),
                    "put_page" if args.get("expected_revision") == Some(&json!("rev-1")) => {
                        (json!({"status": "created_or_updated", "revision": "rev-2"}), false)
                    }
                    "put_page" => (json!({"code": "revision_conflict", "message": "The page changed after it was read."}), true),
                    "get_backlinks" => (json!({"rows": [
                        {"slug": "companies/acme", "title": quoted("companies/acme", "Acme", 3), "type": "company", "date": "2026-11-18"},
                        {"slug": "people/alice", "title": "Alice", "type": "person"},
                    ], "total": 2, "truncated": false, "cursor": null}), false),
                    "get_versions" => (json!([
                        {"id": 7, "snapshot_at": "2026-11-18T09:00:00.000Z", "title": "Alice"},
                        {"id": 6, "snapshot_at": "2026-11-02T09:00:00.000Z", "title": "Alice"},
                    ]), false),
                    "get_timeline" => (json!([{"date": "2026-11-18", "summary": "Asked for a quote.", "source": "meeting"}]), false),
                    "synthesize" => (json!({"answer": "Alice works at Acme.", "sources": ["people/alice", "people/alice"], "cost": {"model": "openai:gpt-5.6-luna", "usd_estimate": 0.0123}, "synthesis_status": "ok"}), false),
                    _ => (json!({"code": "unknown"}), true),
                };
                let rpc = json!({"jsonrpc": "2.0", "id": 1, "result": {"isError": err, "content": [{"type": "text", "text": text.to_string()}]}});
                full(
                    http::StatusCode::OK,
                    "text/event-stream",
                    format!("event: message\ndata: {rpc}\n\n"),
                )
            }
        },
    );
    r
}

#[tokio::test]
async fn the_pages_behind_a_writers_session() {
    let b = test_box();
    std::fs::create_dir_all(&b.app.config.state_dir).expect("state");
    std::fs::write(
        b.app.config.state_dir.join("gbrain-pages.token"),
        "gbrain_pages_token\n",
    )
    .expect("token");
    let calls = Arc::new(Mutex::new(Vec::new()));
    let gbrain = serve(fake_gbrain(calls.clone())).await;
    let access = crate::boxside::access(&b.app, Some("/dashboard/brain".into()));
    let gate = Arc::new(super::super::gate::BrainGate::new(
        &b.app.config.state_dir.join("gbrain-gate.json"),
        b.app.runner.clone(),
    ));
    let pages = BrainPages::new(&b.app, access, gate.clone(), &gbrain);
    let mut router = Router::new(&["open"]);
    register(&mut router, &pages, "open");
    let url = serve(router).await;
    let c = client();
    let origin = "https://box.example";

    // No session, or a member's: the page refuses, and so does the API.
    let r = c.get(format!("{url}/__cc/brain")).send().await.expect("page");
    assert_eq!(r.status(), 401);
    assert!(
        r.text()
            .await
            .expect("text")
            .contains("The brain&#39;s pages are private")
    );
    let r = c
        .get(format!("{url}/__cc/brain/api/pages"))
        .header("cookie", session_cookie(false))
        .send()
        .await
        .expect("member");
    assert_eq!(r.status(), 401);
    // Another site, with a good cookie.
    let r = c
        .post(format!("{url}/__cc/brain/api/page"))
        .header("cookie", session_cookie(true))
        .header("origin", "https://evil.example")
        .json(&json!({"slug": "people/alice", "content": "x", "revision": "rev-1"}))
        .send()
        .await
        .expect("cross-site");
    assert_eq!(r.status(), 403);

    let owner = session_cookie(true);
    let page = c
        .get(format!("{url}/__cc/brain/ask"))
        .header("cookie", &owner)
        .send()
        .await
        .expect("page");
    assert_eq!(page.status(), 200);
    let html = page.text().await.expect("html");
    assert!(html.contains("/__cc/files-ui/brain.js"));
    assert!(html.contains(r#""view":"ask""#));
    assert!(html.contains(r#"aria-current="page""#));

    let list: Value = c
        .get(format!("{url}/__cc/brain/api/pages?type=person"))
        .header("cookie", &owner)
        .send()
        .await
        .expect("list")
        .json()
        .await
        .expect("json");
    assert_eq!(list["pages"][0]["slug"], "people/alice");
    assert_eq!(list["next"], Value::Null);

    let read: Value = c
        .get(format!("{url}/__cc/brain/api/page?slug=people%2Falice"))
        .header("cookie", &owner)
        .send()
        .await
        .expect("read")
        .json()
        .await
        .expect("json");
    assert_eq!(read["title"], "Alice");
    assert_eq!(read["content"], "---\ntype: person\n---\n# Alice\n");
    assert_eq!(read["revision"], "rev-1");

    let save = |revision: &str| {
        c.post(format!("{url}/__cc/brain/api/page"))
            .header("cookie", &owner)
            .header("origin", origin)
            .json(&json!({"slug": "people/alice", "content": "# Alice\n\nEdited.\n", "revision": revision}))
            .send()
    };
    let r = save("rev-1").await.expect("save");
    assert_eq!(r.status(), 200);
    assert_eq!(r.json::<Value>().await.expect("json")["revision"], "rev-2");
    let r = save("rev-0").await.expect("stale");
    assert_eq!(r.status(), 409);
    assert_eq!(r.json::<Value>().await.expect("json")["code"], "conflict");
    let put = calls
        .lock()
        .expect("calls")
        .iter()
        .find(|(t, _)| t == "put_page")
        .cloned()
        .expect("put");
    assert_eq!(put.1["reason"], "Edited by a person on the brain's Pages page");

    // A page's side panel: who links to it (not itself), when it changed, its dated entries.
    let related: Value = c
        .get(format!("{url}/__cc/brain/api/related?slug=people%2Falice"))
        .header("cookie", &owner)
        .send()
        .await
        .expect("related")
        .json()
        .await
        .expect("json");
    assert_eq!(
        related["backlinks"],
        json!([{"slug": "companies/acme", "title": "Acme", "type": "company"}])
    );
    assert_eq!(related["backlinksTotal"], 1, "its own link is not counted");
    assert_eq!(
        related["changes"],
        json!(["2026-11-18T09:00:00.000Z", "2026-11-02T09:00:00.000Z"])
    );
    assert_eq!(related["changesMore"], false);
    assert_eq!(related["timeline"][0]["summary"], "Asked for a quote.");
    let asked = calls.lock().expect("calls").clone();
    let versions = asked.iter().find(|(t, _)| t == "get_versions").expect("versions");
    assert_eq!(versions.1["limit"], 100, "a bounded read");
    assert!(versions.1.get("include_body").is_none(), "metadata only");

    // Export: a link from anywhere cannot start one; the page asks for a one-time link first.
    let r = c
        .get(format!("{url}/__cc/brain/api/export"))
        .header("cookie", &owner)
        .send()
        .await
        .expect("no ticket");
    assert_eq!(r.status(), 403);
    let r: Value = c
        .post(format!("{url}/__cc/brain/api/export"))
        .header("cookie", &owner)
        .header("origin", origin)
        .send()
        .await
        .expect("ticket")
        .json()
        .await
        .expect("json");
    let link = r["url"].as_str().expect("url").to_string();
    assert!(link.starts_with("/__cc/brain/api/export?t="));
    assert!(pages.take_export_ticket(link.split("t=").nth(1)));
    assert!(
        !pages.take_export_ticket(link.split("t=").nth(1)),
        "a ticket is good once"
    );
    // GBrain's admin from the sidebar: a writer only.
    let r = c.get(format!("{url}/__cc/brain/admin")).send().await.expect("admin");
    assert_eq!(r.status(), 401);

    // Ask: an answer with each page once and its cost; refused while the organization is stopped.
    let ask = |q: &str| {
        c.post(format!("{url}/__cc/brain/api/ask"))
            .header("cookie", &owner)
            .header("origin", origin)
            .json(&json!({"question": q}))
            .send()
    };
    let r: Value = ask("Who is Alice?").await.expect("ask").json().await.expect("json");
    assert_eq!(r["answer"], "Alice works at Acme.");
    assert_eq!(
        r["sources"],
        json!([{"slug": "people/alice", "title": "Alice", "type": "person", "excerpt": ""}])
    );
    assert_eq!(r["costUsd"], json!(0.0123));
    gate.set_lock(super::super::gate::parse_lock(json!({"all": true, "vmIds": []}).as_object()).expect("lock"))
        .expect("set");
    let r = ask("Who is Alice?").await.expect("stopped");
    assert_eq!(r.status(), 409);
    assert_eq!(r.json::<Value>().await.expect("json")["code"], "stopped");
    gate.set_lock(super::super::gate::parse_lock(json!({"all": false, "vmIds": []}).as_object()).expect("lock"))
        .expect("set");
    std::fs::write(key_state_path(&b.app.config.state_dir), "clear").expect("key");
    let r = ask("Who is Alice?").await.expect("no key");
    assert_eq!(r.json::<Value>().await.expect("json")["code"], "no_ai");
    let n = calls
        .lock()
        .expect("calls")
        .iter()
        .filter(|(t, _)| t == "synthesize")
        .count();
    assert_eq!(n, 1, "a refused question never reaches GBrain");
}

#[tokio::test]
async fn a_pages_ticket_lands_on_the_pages() {
    assert_eq!(LANDING, &[("files", "/__cc/brain")]);
    let ctx = crate::boxside::shell::ShellContext {
        hostname: Some("brain-abc.ccl.bot".into()),
        console_url: "https://controlclaw.com/dashboard/brain".into(),
        doctor_url: None,
        status: None,
    };
    let html = brain_shell(&ctx, "pages", &json!({"view": "</script>"}));
    // The page data cannot close its script element.
    assert!(!html.contains(r#""</script>""#));
    for label in [
        "Pages",
        "Lately",
        "Ask",
        "Import",
        "Export",
        "GBrain admin",
        "Back to console",
    ] {
        assert!(html.contains(label), "{label}");
    }
}

/// Lately on a GBrain whose times it cannot read: it stops after `LATELY_ROWS_READ` rows, and says
/// it was cut short, rather than walking the whole brain.
#[tokio::test]
async fn lately_stops_on_times_it_cannot_read() {
    let b = test_box();
    std::fs::create_dir_all(&b.app.config.state_dir).expect("state");
    std::fs::write(
        b.app.config.state_dir.join("gbrain-pages.token"),
        "gbrain_pages_token\n",
    )
    .expect("token");
    let lists = Arc::new(Mutex::new(0u64));
    let mut r = Router::new(&["gbrain"]);
    let counted = lists.clone();
    r.route(
        "gbrain",
        |_, p| p == "/mcp",
        move |req, _| {
            let counted = counted.clone();
            async move {
                let body = req.into_body().collect().await.expect("body").to_bytes();
                let v: Value = serde_json::from_slice(&body).expect("json");
                let tool = v.pointer("/params/name").and_then(Value::as_str).unwrap_or_default();
                let (text, meta) = if tool == "list_pages" {
                    *counted.lock().expect("count") += 1;
                    let rows: Vec<Value> = (0..100)
                        .map(|i| json!({"slug": format!("notes/n{i}"), "updated_at": "2026-11-19 10:00:00+00"}))
                        .collect();
                    (json!(rows), json!({"pagination": {"truncated": true}}))
                } else {
                    (json!([]), Value::Null)
                };
                let rpc = json!({"jsonrpc": "2.0", "id": 1, "result": {"isError": false, "_meta": meta, "content": [{"type": "text", "text": text.to_string()}]}});
                full(http::StatusCode::OK, "text/event-stream", format!("event: message\ndata: {rpc}\n\n"))
            }
        },
    );
    let gbrain = serve(r).await;
    let access = crate::boxside::access(&b.app, Some("/dashboard/brain".into()));
    let gate = Arc::new(super::super::gate::BrainGate::new(
        &b.app.config.state_dir.join("gbrain-gate.json"),
        b.app.runner.clone(),
    ));
    let pages = BrainPages::new(&b.app, access, gate, &gbrain);
    let out = pages.lately(None).await.expect("lately");
    assert_eq!(out["truncated"], json!(true));
    assert_eq!(out["pages"].as_array().map(Vec::len), Some(0));
    assert_eq!(*lists.lock().expect("count"), LATELY_ROWS_READ / 100);
}
