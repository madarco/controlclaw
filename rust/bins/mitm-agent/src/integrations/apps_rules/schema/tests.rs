//! `connector-gate.test.ts`: the parts that test the rules alone (widens, direct calls).

use serde_json::{Value, json};

use super::*;

fn with(base: &AppRule, f: impl FnOnce(&mut AppRule)) -> AppRule {
    let mut r = base.clone();
    f(&mut r);
    r
}

fn put(rule: AppRule, at: Option<usize>) -> AppRulesChange {
    AppRulesChange::Put { rule, at }
}

#[test]
fn widens_loosening_needs_a_code_narrowing_does_not() {
    let seeded = seeded_app_rule();
    let block = with(&seeded, |r| {
        r.id = "b".into();
        r.name = "b".into();
        r.then = AppEffect::Block;
    });
    let allow = with(&seeded, |r| {
        r.id = "a".into();
        r.name = "a".into();
        r.then = AppEffect::Allow;
    });
    let list = vec![seeded.clone(), block.clone()];
    // Adding a block anywhere narrows; an allow above a block widens; an allow at the end changes nothing.
    assert!(!widens(&list, &put(with(&block, |r| r.id = "b2".into()), Some(0))));
    assert!(widens(&list, &put(allow.clone(), Some(0))));
    assert!(!widens(&list, &put(allow.clone(), None)));
    // An ask above a block widens; at the end it narrows.
    let x = with(&seeded, |r| r.id = "x".into());
    assert!(widens(std::slice::from_ref(&block), &put(x.clone(), Some(0))));
    assert!(!widens(std::slice::from_ref(&block), &put(x, None)));
    // Deleting a block or an ask widens; deleting an allow does not.
    assert!(widens(&list, &AppRulesChange::Delete { id: "b".into() }));
    assert!(widens(&list, &AppRulesChange::Delete { id: seeded.id.clone() }));
    assert!(!widens(
        std::slice::from_ref(&allow),
        &AppRulesChange::Delete { id: "a".into() }
    ));
    // Turning a block off widens, on narrows; ask → block narrows, block → allow widens; a rename does nothing.
    let off = with(&block, |r| r.enabled = false);
    assert!(widens(std::slice::from_ref(&block), &put(off.clone(), None)));
    assert!(!widens(&[off], &put(block.clone(), None)));
    assert!(!widens(
        std::slice::from_ref(&seeded),
        &put(with(&seeded, |r| r.then = AppEffect::Block), None)
    ));
    assert!(widens(
        std::slice::from_ref(&block),
        &put(with(&block, |r| r.then = AppEffect::Allow), None)
    ));
    assert!(!widens(
        std::slice::from_ref(&block),
        &put(with(&block, |r| r.name = "renamed".into()), None)
    ));
    // Changing what a block matches widens.
    let narrower = with(&block, |r| {
        r.match_ = AppMatch::Actions {
            actions: vec!["github.x".into()],
        }
    });
    assert!(widens(std::slice::from_ref(&block), &put(narrower, None)));
    // Moving a block up narrows; moving an allow up past a block widens; moving a block down past an allow widens.
    let mv = |id: &str, to| AppRulesChange::Move { id: id.into(), to };
    assert!(!widens(&[allow.clone(), block.clone()], &mv("b", 0)));
    assert!(widens(&[block.clone(), allow.clone()], &mv("a", 0)));
    assert!(widens(&[block.clone(), allow.clone()], &mv("b", 1)));
    let moved = apply_app_change(&[block, allow], &mv("b", 1)).expect("moved");
    assert_eq!(moved.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(), ["a", "b"]);
}

fn proxy_call(method: &str, path: &str) -> AppCall {
    AppCall {
        vm_id: "vm".into(),
        service: "github".into(),
        connection_id: None,
        action_id: None,
        operation: None,
        proxy: Some(ProxyCall {
            method: method.into(),
            path: path.into(),
        }),
        tool: None,
        input: Value::Null,
    }
}

#[test]
fn actions_rules_cover_the_apps_direct_calls_unless_they_allow() {
    let seeded = seeded_app_rule();
    let block_some = with(&seeded, |r| {
        r.id = "b".into();
        r.name = "b".into();
        r.service = Some("github".into());
        r.match_ = AppMatch::Actions {
            actions: vec!["github.get_user".into()],
        };
        r.then = AppEffect::Block;
    });
    assert_eq!(
        decide_app(std::slice::from_ref(&block_some), &proxy_call("GET", "/repos"), &[]).then,
        AppEffect::Block
    );
    let allow_some = with(&block_some, |r| r.then = AppEffect::Allow);
    let d = decide_app(std::slice::from_ref(&allow_some), &proxy_call("DELETE", "/x"), &[]);
    assert_eq!(d.then, AppEffect::Allow);
    assert!(d.rule.is_none(), "the default, not the rule");
    assert_eq!(
        decide_app(&[allow_some, seeded], &proxy_call("DELETE", "/x"), &[]).then,
        AppEffect::Ask
    );
}

#[test]
fn proxy_paths_match_without_case_segment_by_segment() {
    assert!(path_under("/repos", "/repos"));
    assert!(path_under("/Repos/a", "/repos"));
    assert!(path_under("/repos/a", "/repos/"));
    assert!(!path_under("/repos-archive", "/repos"));
    assert!(path_under("/anything", "/"));
}

#[test]
fn an_unknown_kind_counts_as_destructive() {
    let mut call = proxy_call("GET", "/");
    call.proxy = None;
    call.action_id = Some("github.mystery".into());
    assert_eq!(operation_of(&call), AppOperation::Destructive);
    assert_eq!(decide_app(&[seeded_app_rule()], &call, &[]).then, AppEffect::Ask);
}

#[test]
fn a_rule_on_one_connection_is_not_stepped_around_by_naming_none() {
    let rule = with(&seeded_app_rule(), |r| {
        r.id = "no-work".into();
        r.service = Some("github".into());
        r.connection_id = Some("conn-work".into());
        r.match_ = AppMatch::Any;
        r.then = AppEffect::Block;
    });
    let call = proxy_call("GET", "/");
    let both = ["conn-home".to_string(), "conn-work".to_string()];
    assert_eq!(
        decide_app(std::slice::from_ref(&rule), &call, &both).then,
        AppEffect::Block
    );
    assert_eq!(decide_app(&[rule], &call, &both[..1]).then, AppEffect::Allow);
}

#[tokio::test]
async fn a_sentence_is_judged_and_unjudged_asks() {
    let rule = with(&seeded_app_rule(), |r| {
        r.id = "s".into();
        r.match_ = AppMatch::Any;
        r.then = AppEffect::Block;
        r.sentence = Some("only when it deletes".into());
    });
    let call = proxy_call("GET", "/");
    let rules = [rule];
    // Not judged (a listing): the stricter of the rule's own and Ask.
    let d = decide_app(&rules, &call, &[]);
    assert_eq!((d.then, d.judged), (AppEffect::Block, Some(Judged::Unavailable)));
    let no: &(dyn Fn(&AppRule, &AppCall) -> cc_http::BoxFuture<Fit> + Send + Sync) =
        &|_, _| Box::pin(async { Fit::No });
    assert_eq!(
        decide_app_judged(&rules, &call, &[], Some(no)).await.then,
        AppEffect::Allow
    );
    let fits: &(dyn Fn(&AppRule, &AppCall) -> cc_http::BoxFuture<Fit> + Send + Sync) =
        &|_, _| Box::pin(async { Fit::Fits });
    let d = decide_app_judged(&rules, &call, &[], Some(fits)).await;
    assert_eq!((d.then, d.judged), (AppEffect::Block, Some(Judged::Fits)));
}

#[test]
fn shapes_are_checked_as_zod_checks_them() {
    let ok = json!({"id": "no-gh", "name": "No GitHub", "enabled": true, "agents": [], "service": "github",
        "connectionId": null, "match": {"kind": "actions", "actions": ["github.delete_*"]}, "then": "block"});
    let rule = parse_rule(&ok).expect("a good rule");
    assert_eq!(
        serde_json::to_value(&rule).expect("json"),
        ok,
        "written back the same, key for key"
    );
    let refuse = |f: &dyn Fn(&mut serde_json::Map<String, Value>)| {
        let mut v = ok.as_object().expect("object").clone();
        f(&mut v);
        parse_rule(&Value::Object(v)).is_err()
    };
    assert!(refuse(&|v| {
        v.insert("then".into(), json!("maybe"));
    }));
    assert!(refuse(&|v| {
        v.insert("extra".into(), json!(1));
    }));
    assert!(refuse(&|v| {
        v.insert("name".into(), json!("two  spaces"));
    }));
    assert!(refuse(&|v| {
        v.insert("name".into(), json!("a\u{200b}b"));
    }));
    assert!(refuse(&|v| {
        v.insert("match".into(), json!({"kind": "actions", "actions": ["notion.search"]}));
    }));
    assert!(refuse(&|v| {
        v.insert("match".into(), json!({"kind": "tools", "tools": ["x"]}));
    }));
    assert!(refuse(&|v| {
        v.insert("agents".into(), json!(["a", "a"]));
    }));
    assert!(!refuse(&|v| {
        v.insert("service".into(), json!(null));
    }));
    assert!(
        parse_change(&json!({"op": "delete", "id": "nope"})).is_ok(),
        "an unknown id is the store's to refuse"
    );
    assert!(parse_change(&json!({"op": "move", "id": "a", "to": 101})).is_err());
    assert!(parse_change(&json!({"op": "move", "id": "a", "to": 1.5})).is_err());
    assert!(plain_line("Ask before deleting"));
    assert!(!plain_line(" lead"));
}

#[test]
fn describes_rules_and_changes() {
    let block = with(&seeded_app_rule(), |r| {
        r.id = "no-github-writes".into();
        r.service = Some("github".into());
        r.match_ = AppMatch::Operation {
            operations: vec![AppOperation::Write],
        };
        r.then = AppEffect::Block;
    });
    assert_eq!(
        describe_app_change(
            &AppRulesChange::Delete { id: block.id.clone() },
            std::slice::from_ref(&block)
        ),
        "Delete the integration rule that blocks changing in github"
    );
    assert_eq!(
        describe_app_change(&put(seeded_app_rule(), None), &[]),
        "Add an integration rule that asks a person before deleting in any integration, for all agents"
    );
    let mcp = with(&block, |r| {
        r.service = Some("mcp:mcp.example.com".into());
        r.match_ = AppMatch::Tools {
            tools: vec!["delete_*".into()],
        };
    });
    assert_eq!(
        describe_match(&mcp, None),
        "the tool delete_* in the MCP server mcp.example.com"
    );
}

#[test]
fn lengths_are_counted_in_utf16_units_as_zod_counts_them() {
    let mut v = serde_json::to_value(seeded_app_rule()).expect("json");
    v["name"] = json!("\u{1F600}".repeat(41));
    assert!(parse_rule(&v).is_err(), "82 units");
    v["name"] = json!("\u{1F600}".repeat(40));
    assert!(parse_rule(&v).is_ok());
}
