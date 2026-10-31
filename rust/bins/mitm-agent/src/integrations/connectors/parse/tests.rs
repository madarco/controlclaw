//! `connector-gate.test.ts`: the parser's own cases.

use serde_json::json;

use super::*;

const J: RouteHeaders = RouteHeaders {
    content_type: Some("application/json"),
    alias: None,
};

fn b(v: serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(&v).expect("json")
}

#[test]
fn parse_route_reads_each_route() {
    let none = RouteHeaders::default();
    assert_eq!(parse_route("GET", "/v1/health", &none, None), Ok(Route::Pass));
    let init = b(json!({"jsonrpc": "2.0", "method": "initialize", "id": 1}));
    assert_eq!(parse_route("POST", "/mcp", &J, Some(&init)), Ok(Route::Pass));
    let call = b(
        json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "execute_action",
        "arguments": {"actionId": "x.y", "input": {"a": 1}, "connectionName": "w"}}}),
    );
    assert_eq!(
        parse_route("POST", "/mcp", &J, Some(&call)),
        Ok(Route::Action {
            via: Via::Mcp,
            action_id: "x.y".into(),
            input: json!({"a": 1}),
            connection_name: Some("w".into()),
            rpc_id: Some(json!(3)),
        })
    );
    assert!(matches!(
        parse_route("GET", "/v1/actions?service=github", &none, None),
        Ok(Route::List { .. })
    ));
    assert_eq!(parse_route("GET", "/v1/actions", &none, None), Ok(Route::Pass));
    let evil = b(json!({"endpoint": "https://evil.example/x", "method": "GET"}));
    assert!(parse_route("POST", "/v1/proxy/github", &J, Some(&evil)).is_err());
    assert_eq!(
        parse_route("POST", "/mcp", &J, Some(&[0x7b, 0xff, 0x7d])),
        Err(GateParseError("the body is not UTF-8".into()))
    );
    // #488 review 4 and 6: an MCP action id of another shape, and a body sent as anything but JSON.
    let traversal = b(json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "execute_action", "arguments": {"actionId": "../x"}}}));
    assert!(parse_route("POST", "/mcp", &J, Some(&traversal)).is_err());
    let input = b(json!({"input": {}}));
    let typed = |t: &'static str| RouteHeaders {
        content_type: Some(t),
        alias: None,
    };
    let as_json = Err(GateParseError("send it as application/json".into()));
    assert_eq!(
        parse_route("POST", "/v1/actions/x.y", &typed("text/plain"), Some(&input)),
        as_json
    );
    assert_eq!(parse_route("POST", "/mcp", &none, Some(&init)), as_json);
    // The media type exactly, parameters aside.
    assert_eq!(
        parse_route(
            "POST",
            "/v1/actions/x.y",
            &typed("application/json-patch+json"),
            Some(&input)
        ),
        as_json
    );
    assert!(matches!(
        parse_route(
            "POST",
            "/v1/actions/x.y",
            &typed("Application/JSON; charset=utf-8"),
            Some(&input)
        ),
        Ok(Route::Action { .. })
    ));
    let guide = b(json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "get_action_guide", "arguments": {"actionId": "../x"}}}));
    assert!(parse_route("POST", "/mcp", &J, Some(&guide)).is_err());
}

#[test]
fn writes_the_gate_does_not_read_are_refused() {
    let input = b(json!({"input": {}}));
    for path in ["/v1/actions/x.y/", "/v1/actions/x.y/run", "/v1/proxy/github/x"] {
        assert!(parse_route("POST", path, &J, Some(&input)).is_err(), "{path}");
    }
    assert!(parse_route("PUT", "/v1/actions/x.y", &RouteHeaders::default(), None).is_err());
    assert_eq!(
        parse_route("HEAD", "/v1/actions/x.y", &RouteHeaders::default(), None),
        Ok(Route::Pass)
    );
}

#[test]
fn connection_name_of_reads_the_runtimes_five_places_in_its_order() {
    let q = |s: &str| query_pairs(s);
    let alias = json!({"alias": "a"});
    assert_eq!(
        connection_name_of(alias.as_object(), None, &q("")),
        Ok(Some("a".into()))
    );
    assert_eq!(connection_name_of(None, Some("h"), &q("alias=h")), Ok(Some("h".into())));
    let named = json!({"connectionName": "a"});
    assert!(connection_name_of(named.as_object(), Some("b"), &q("")).is_err());
    assert!(connection_name_of(None, None, &q("alias=a&alias=b")).is_err());
    assert_eq!(connection_name_of(None, Some("  "), &q("")), Ok(None));
}

#[test]
fn proxy_path_refuses_traversal_encoded_too() {
    assert_eq!(proxy_path("/repos/a?x=1"), Ok("/repos/a".into()));
    assert_eq!(proxy_path("/%61dmin"), Ok("/admin".into()));
    assert!(proxy_path("/repos/%2e%2e/admin").is_err());
    assert!(proxy_path("/a%2fb").is_err());
    assert!(proxy_path("/a%zz").is_err());
    assert!(proxy_path("//evil").is_err());
    assert!(proxy_path("/a\\b").is_err());
}

#[test]
fn an_approvals_key_is_the_same_for_the_same_input_whatever_the_key_order() {
    assert_eq!(
        canonical_json(&json!({"b": 1, "a": [1, {"d": 2, "c": 3}]}), 0),
        Ok(r#"{"a":[1,{"c":3,"d":2}],"b":1}"#.into())
    );
    let k = |v| call_key("vm", Some("c"), "x.y", &v).expect("key");
    assert_eq!(k(json!({"a": 1, "b": 2})), k(json!({"b": 2, "a": 1})));
    assert_ne!(k(json!({"a": 1})), k(json!({"a": 2})));
    // The key the TS makes for the same call (computed with connector-parse.ts), so an ask filed by
    // one build is the same ask for the other.
    let input = json!({"title": "hi", "n": 1.5, "big": 1e21, "é": [true, null], "\u{1F600}": 1, "\u{FF01}": 2});
    assert_eq!(
        call_key("vm-a", Some("conn-gh"), "github.create_issue", &input).expect("key"),
        "0ed31137ed9fd94c85ebd24c126b07fc93b6149fc68bb20e8b6b0d8c5b227cb4"
    );
    assert_eq!(
        canonical_json(&json!({"\u{FF01}": 2, "\u{1F600}": 1}), 0),
        Ok("{\"\u{1F600}\":1,\"\u{FF01}\":2}".into()),
        "sorted by UTF-16 units, as JavaScript sorts"
    );
    let mut deep = json!(1);
    for _ in 0..70 {
        deep = json!([deep]);
    }
    assert!(canonical_json(&deep, 0).is_err());
}

#[test]
fn sse_round_trips() {
    let text = "event: message\ndata: {\"a\":1}\n\n: comment\ndata: x\ndata: y\n\n";
    let events = parse_sse(text);
    assert_eq!(events[1].data.as_deref(), Some("x\ny"));
    assert_eq!(parse_sse(&write_sse(&events)), events);
    assert_eq!(parse_sse("data: a\r\n\r\ndata: b\r\n").len(), 2);
}

#[test]
fn the_content_rules_read_the_whole_answer() {
    let http = json!({"success": true, "data": 1, "meta": {"note": "x"}});
    assert_eq!(result_part(&http), http);
    let m = json!({"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": "dup"}], "structuredContent": {"ok": true, "data": 2}}});
    assert_eq!(
        result_part(&m),
        json!({"jsonrpc": "2.0", "id": 1, "result": {"structuredContent": {"ok": true, "data": 2}}})
    );
}

#[test]
fn tool_answers_as_openconnector_writes_them() {
    let payload = json!({"ok": false, "error": {"code": "x", "message": "y"}});
    let doc = tool_answer(Some(&json!(7)), payload.as_object().cloned().expect("object"), true);
    assert_eq!(
        crate::integrations::js::stringify(&doc),
        r#"{"jsonrpc":"2.0","id":7,"result":{"content":[{"type":"text","text":"{\n  \"ok\": false,\n  \"error\": {\n    \"code\": \"x\",\n    \"message\": \"y\"\n  }\n}"}],"structuredContent":{"ok":false,"error":{"code":"x","message":"y"}},"isError":true}}"#
    );
    assert_eq!(tool_payload(&doc), payload.as_object().cloned());
    let replaced = with_tool_payload(
        doc.as_object().expect("object"),
        json!({"ok": true}).as_object().cloned().expect("o"),
        false,
    );
    assert!(replaced["result"].get("isError").is_none());
    assert_eq!(run_of(&replaced, Via::Mcp).ok, Some(true));
    let with_body = with_connection_name(Some(br#"{"input":{"a":1.0}}"#), Via::Http, "work");
    assert_eq!(
        String::from_utf8(with_body).expect("utf8"),
        r#"{"input":{"a":1},"connectionName":"work"}"#
    );
}
