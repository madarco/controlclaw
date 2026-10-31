//! Ported from test_mcp.py.

use bytes::Bytes;
use serde_json::{Value, json};

use super::*;
use crate::checks::creds::Creds;
use crate::checks::testkit::{Answer, FakeService};
use crate::checks::{META_BODY_DECODED, META_EFFECT, META_MCP_CHECKED};
use crate::flow::testing::request_flow;

struct Kit {
    dir: tempfile::TempDir,
    svc: FakeService,
    mcp: Arc<Mcp>,
}

async fn kit() -> Kit {
    let dir = tempfile::tempdir().expect("dir");
    let svc = FakeService::start().await.expect("svc");
    let creds = Arc::new(Creds::new(dir.path().join("credentials.json")));
    let web = Arc::new(Web {
        content: crate::checks::testkit::Rig::new().await.content,
        control_plane_host: None,
        creds: creds.clone(),
    });
    let mcp = Arc::new(Mcp {
        url: svc.url(""),
        creds,
        web,
        logins: None,
    });
    Kit { dir, svc, mcp }
}

fn flow(body: &[u8], ctype: &str, host: &str, port: u16, method: &str) -> Flow {
    let url = if port == 443 {
        format!("https://{host}/mcp")
    } else {
        format!("https://{host}:{port}/mcp")
    };
    let mut f = request_flow(method, &url, b"");
    f.request = http::Request::builder()
        .method(method)
        .uri(&url)
        .header("content-type", ctype)
        .header("authorization", "Bearer agents-own-key")
        .header("cookie", "nope")
        .body(Bytes::from(body.to_vec()))
        .ok();
    f.vm_id = Some("vm1".into());
    f.meta.insert(META_BODY_DECODED, json!(true));
    f
}

fn call() -> Value {
    json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "delete_doc", "arguments": {"id": "x"}}})
}

fn j(v: &Value) -> Vec<u8> {
    v.to_string().into_bytes()
}

async fn run(k: &Kit, f: &mut Flow) -> Option<(u16, String)> {
    match McpRequest(k.mcp.clone()).run(Hook::Request, f).await {
        Verdict::Continue => None,
        Verdict::Answer(r) => Some((r.status().as_u16(), String::from_utf8_lossy(r.body()).into_owned())),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn what_is_mcp() {
    let k = |b: &[u8], m: &str| kind(&flow(b, "application/json", "mcp.example.com", 443, m));
    assert_eq!(k(b"<xml/>", "POST"), None);
    assert_eq!(k(&j(&json!({"hello": "world"})), "POST"), None);
    assert_eq!(k(&j(&call()), "GET"), None);
    assert_eq!(k(&j(&call()), "POST"), Some("call"));
    let late = format!(
        r#"{{"method":"tools/call","params":{{"name":"x","pad":"{}"}},"id":1,"jsonrpc":"2.0"}}"#,
        "a".repeat(700)
    );
    assert_eq!(k(late.as_bytes(), "POST"), Some("call"));
    assert_eq!(
        k(&j(&json!([call(), {"jsonrpc": "2.0", "id": 5, "result": {}}])), "POST"),
        Some("call")
    );
    assert_eq!(
        k(&j(&json!({"method": "tools/call", "params": {"name": "x"}})), "POST"),
        Some("call"),
        "no jsonrpc field"
    );
    assert_eq!(k(&j(&json!({"jsonrpc_like": 1, "method": "note"})), "POST"), None);
    assert_eq!(
        k(
            &j(&json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})),
            "POST"
        ),
        Some("other")
    );
    assert_eq!(
        k(
            &j(
                &json!([{"jsonrpc": "2.0", "id": 1, "method": "ping"}, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}])
            ),
            "POST"
        ),
        Some("list")
    );
}

#[tokio::test]
async fn calls_are_admitted() {
    let k = kit().await;
    // Not a tool call: no question asked.
    assert!(
        run(
            &k,
            &mut flow(&j(&json!({"a": 1})), "application/json", "mcp.example.com", 443, "POST")
        )
        .await
        .is_none()
    );
    assert!(
        run(
            &k,
            &mut flow(
                &j(&json!({"jsonrpc": "2.0", "id": 1, "method": "initialize"})),
                "application/json",
                "mcp.example.com",
                443,
                "POST"
            )
        )
        .await
        .is_none()
    );
    assert!(k.svc.all_calls().is_empty());
    // Refused by the service: its answer is the agent's.
    let answer_body = json!({"jsonrpc": "2.0", "id": 7, "result": {"isError": true, "content": [{"type": "text", "text": "blocked"}]}}).to_string();
    k.svc.answer(
        "/call",
        Answer::json(
            200,
            json!({"action": "answer", "status": 200, "content_type": "application/json", "body": answer_body}),
        ),
    );
    let mut f = flow(&j(&call()), "application/json", "mcp.example.com", 8443, "POST");
    let (status, body) = run(&k, &mut f).await.expect("answered");
    assert_eq!((status, body.contains("blocked")), (200, true));
    assert_eq!(f.meta[META_EFFECT], "block");
    let sent = k.svc.calls("/call").pop().unwrap_or_default();
    assert_eq!(
        (sent["vm_id"].as_str(), sent["host"].as_str(), sent["url"].as_str()),
        (
            Some("vm1"),
            Some("mcp.example.com:8443"),
            Some("https://mcp.example.com:8443/mcp")
        )
    );
    assert_eq!(
        (
            sent["headers"]["authorization"].as_str(),
            sent["headers"]["cookie"].as_str()
        ),
        (Some("Bearer agents-own-key"), Some("nope"))
    );
    assert!(sent["headers"].get("host").is_none());
    assert!(k.svc.calls("/held").is_empty());
    // No agent, or a TLS name that is not the server: refused, nothing asked.
    let n = k.svc.calls("/call").len();
    let mut f = flow(&j(&call()), "application/json", "mcp.example.com", 443, "POST");
    f.vm_id = None;
    assert_eq!(run(&k, &mut f).await.map(|a| a.0), Some(403));
    let mut f = flow(&j(&call()), "application/json", "mcp.example.com", 443, "POST");
    f.sni = Some("other.example.com".into());
    assert_eq!(run(&k, &mut f).await.map(|a| a.0), Some(403));
    assert_eq!(k.svc.calls("/call").len(), n);
    // Allowed, result not read: the row closed with the status.
    k.svc.answer(
        "/call",
        Answer::json(200, json!({"action": "allow", "ticket": "t1", "read_result": false})),
    );
    let mut f = flow(&j(&call()), "application/json", "mcp.example.com", 443, "POST");
    assert!(run(&k, &mut f).await.is_none());
    assert_eq!(f.meta[META_MCP_CHECKED], json!(true));
    f.response = Some(crate::checks::raw_response(
        200,
        br#"{"jsonrpc":"2.0","id":7,"result":{"content":[]}}"#.to_vec(),
        "application/json",
    ));
    McpResponse(k.mcp.clone()).run(Hook::Response, &mut f).await;
    assert_eq!(
        k.svc.calls("/done").pop(),
        Some(json!({"ticket": "t1", "status": 200, "ok": true}))
    );
    // Allowed, result read: the replacement is what the agent gets.
    k.svc.answer(
        "/call",
        Answer::json(200, json!({"action": "allow", "ticket": "t2", "read_result": true})),
    );
    k.svc.answer(
        "/result",
        Answer::json(
            200,
            json!({"action": "replace", "body": r#"{"jsonrpc":"2.0","id":7,"result":{"isError":true}}"#}),
        ),
    );
    let mut f = flow(&j(&call()), "application/json", "mcp.example.com", 443, "POST");
    run(&k, &mut f).await;
    f.response = Some(crate::checks::raw_response(
        200,
        b"event: message\ndata: {\"result\":\"secret\"}\n\n".to_vec(),
        "text/event-stream",
    ));
    McpResponse(k.mcp.clone()).run(Hook::Response, &mut f).await;
    let r = k.svc.calls("/result").pop().unwrap_or_default();
    assert!(r["body"].as_str().is_some_and(|b| b.contains("secret")) && r["content_type"] == "text/event-stream");
    assert_eq!(
        f.response.as_ref().map(|r| r.body().clone()),
        Some(Bytes::from_static(
            br#"{"jsonrpc":"2.0","id":7,"result":{"isError":true}}"#
        ))
    );
    // The service fails on a result to be read: the agent does not get it.
    k.svc.answer("/result", Answer::json(500, json!({})));
    let mut f = flow(&j(&call()), "application/json", "mcp.example.com", 443, "POST");
    run(&k, &mut f).await;
    f.response = Some(crate::checks::raw_response(200, b"secret".to_vec(), "text/plain"));
    McpResponse(k.mcp.clone()).run(Hook::Response, &mut f).await;
    assert!(
        f.response
            .as_ref()
            .is_some_and(|r| String::from_utf8_lossy(r.body()).contains("kept it from you"))
    );
    // tools/list: to the catalog, rewritten.
    k.svc.answer(
        "/tools",
        Answer::json(
            200,
            json!({"action": "replace", "body": r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}"#}),
        ),
    );
    let mut f = flow(
        &j(&json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})),
        "application/json",
        "mcp.example.com",
        443,
        "POST",
    );
    assert!(run(&k, &mut f).await.is_none());
    f.response = Some(crate::checks::raw_response(
        200,
        br#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"delete_doc"}]}}"#.to_vec(),
        "application/json",
    ));
    McpResponse(k.mcp.clone()).run(Hook::Response, &mut f).await;
    assert_eq!(
        k.svc
            .calls("/tools")
            .pop()
            .map(|c| (c["host"].clone(), c["vm_id"].clone())),
        Some((json!("mcp.example.com"), json!("vm1")))
    );
    assert_eq!(
        f.response.as_ref().map(|r| r.body().clone()),
        Some(Bytes::from_static(br#"{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}"#))
    );
    // A pass leaves the website check to run.
    k.svc.answer("/call", Answer::json(200, json!({"action": "pass"})));
    let mut f = flow(&j(&call()), "application/json", "mcp.example.com", 443, "POST");
    assert!(run(&k, &mut f).await.is_none());
    assert!(!f.meta.contains_key(META_MCP_CHECKED));
    // An error closes the row.
    let mut f = flow(&j(&call()), "application/json", "mcp.example.com", 443, "POST");
    f.meta.insert(META_TICKET, json!("t9"));
    McpError(k.mcp.clone()).run(Hook::Error, &mut f).await;
    assert_eq!(
        k.svc.calls("/done").pop(),
        Some(json!({"ticket": "t9", "status": 0, "ok": false, "error": "server_unreachable"}))
    );
}

#[tokio::test]
async fn held_large_and_down() {
    let k = kit().await;
    std::fs::write(
        k.dir.path().join("credentials.json"),
        r#"[{"match_domain": "mcp.example.com", "placeholder": "CC-PH-mcp-key", "secret": "the-real-key"}]"#,
    )
    .expect("creds");
    k.svc.answer("/call", Answer::json(200, json!({"action": "answer", "status": 200, "content_type": "application/json", "body": "{}", "hold_ref": "h1"})));
    let mut f = flow(&j(&call()), "application/json", "mcp.example.com", 443, "POST");
    if let Some(r) = f.request.as_mut() {
        r.headers_mut()
            .insert("authorization", http::HeaderValue::from_static("Bearer CC-PH-mcp-key"));
    }
    assert!(run(&k, &mut f).await.is_some());
    assert_eq!(
        k.svc.calls("/call")[0]["headers"]["authorization"],
        "Bearer CC-PH-mcp-key",
        "the check sees the agent's request"
    );
    let held = k.svc.calls("/held").pop().unwrap_or_default();
    assert_eq!(
        (held["hold_ref"].as_str(), held["headers"]["authorization"].as_str()),
        (Some("h1"), Some("Bearer the-real-key"))
    );
    // Not parsed on a model provider; under the parse limit a quote of tools/call is not a call.
    let model = json!({"model": "claude", "messages": [{"role": "user", "content": format!("the \"method\": \"tools/call\" docs {}", "x".repeat(1536 * 1024))}]}).to_string();
    let n = k.svc.calls("/call").len();
    assert!(
        run(
            &k,
            &mut flow(model.as_bytes(), "application/json", "api.anthropic.com", 443, "POST")
        )
        .await
        .is_none()
    );
    assert!(
        run(
            &k,
            &mut flow(
                model.as_bytes(),
                "application/json",
                "llm.internal.example",
                443,
                "POST"
            )
        )
        .await
        .is_none()
    );
    assert_eq!(k.svc.calls("/call").len(), n);
    // Past the parse limit, and past the body limit: refused as too large.
    let huge = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "x", "arguments": {"text": "a".repeat(MCP_PARSE_MAX + 10)}}}).to_string();
    assert_eq!(
        run(
            &k,
            &mut flow(huge.as_bytes(), "application/json", "mcp.example.com", 443, "POST")
        )
        .await
        .map(|a| a.0),
        Some(413)
    );
    let big = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "x", "arguments": {"text": "a".repeat(MCP_BODY_MAX + 10)}}}).to_string();
    assert_eq!(
        run(
            &k,
            &mut flow(big.as_bytes(), "application/json", "mcp.example.com", 443, "POST")
        )
        .await
        .map(|a| a.0),
        Some(413)
    );
    // The service down: refused.
    let down = Mcp {
        url: "http://127.0.0.1:1".into(),
        creds: k.mcp.creds.clone(),
        web: k.mcp.web.clone(),
        logins: None,
    };
    let mut f = flow(&j(&call()), "application/json", "mcp.example.com", 443, "POST");
    assert_eq!(
        request(&down, &mut f)
            .await
            .map(|_| f.meta[crate::checks::META_RECORD]["status"].clone()),
        Some(json!(503))
    );
}

#[tokio::test]
async fn review_fixes() {
    let k = kit().await;
    // A body the plumbing has not decoded: refused, never sent unchecked.
    let mut f = flow(&j(&call()), "application/json", "mcp.example.com", 443, "POST");
    f.meta.remove(META_BODY_DECODED);
    assert_eq!(run(&k, &mut f).await.map(|a| a.0), Some(503));
    assert!(k.svc.calls("/call").is_empty());
    // A status sent as a float is the number.
    k.svc.answer(
        "/call",
        Answer::json(200, json!({"action": "answer", "status": 403.0, "body": "{}"})),
    );
    let mut f = flow(&j(&call()), "application/json", "mcp.example.com", 443, "POST");
    assert_eq!(run(&k, &mut f).await.map(|a| a.0), Some(403));
    // A repeated header reaches the check with its values joined, as mitmproxy gives them.
    let mut f = flow(&j(&call()), "application/json", "mcp.example.com", 443, "POST");
    if let Some(r) = f.request.as_mut() {
        r.headers_mut().append("cookie", http::HeaderValue::from_static("b=2"));
    }
    run(&k, &mut f).await;
    assert_eq!(
        k.svc.calls("/call").pop().unwrap_or_default()["headers"]["cookie"],
        "nope, b=2"
    );
    // A tools/list answer that is not decoded is kept from the agent.
    let mut f = flow(
        &j(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})),
        "application/json",
        "mcp.example.com",
        443,
        "POST",
    );
    assert!(run(&k, &mut f).await.is_none());
    f.meta.remove(META_BODY_DECODED);
    f.response = Some(crate::checks::raw_response(
        200,
        b"\x1f\x8b gzip".to_vec(),
        "application/json",
    ));
    McpResponse(k.mcp.clone()).run(Hook::Response, &mut f).await;
    let body = f.response.as_ref().map(|r| r.body().clone()).unwrap_or_default();
    assert!(String::from_utf8_lossy(&body).contains("could not check this list"));
    assert!(k.svc.calls("/tools").is_empty());
}

#[tokio::test]
async fn host_review_552_probes() {
    let k = kit().await;
    let k_of = |b: &[u8]| kind(&flow(b, "application/json", "mcp.example.com", 443, "POST"));
    // One byte that is not UTF-8: the TypeScript SDK reads it with a replacement character.
    let bad = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"delete_doc\",\"arguments\":{\"id\":\"x\xff\"}}}";
    assert_eq!(k_of(bad), Some("call"));
    // UTF-16 with no mark (Python's `json.loads` detects it), with a mark, and big-endian.
    let text = call().to_string();
    let le: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let be: Vec<u8> = text.encode_utf16().flat_map(u16::to_be_bytes).collect();
    assert_eq!(k_of(&le), Some("call"));
    assert_eq!(k_of(&[b"\xff\xfe".as_slice(), &le].concat()), Some("call"));
    assert_eq!(k_of(&[b"\xfe\xff".as_slice(), &be].concat()), Some("call"));
    let list = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).to_string();
    let list16: Vec<u8> = list.encode_utf16().flat_map(u16::to_le_bytes).collect();
    assert_eq!(k_of(&list16), Some("list"));
    // Not JSON and no tool call: still not MCP.
    assert_eq!(k_of(b"{not json \xff"), None);
    // A call in UTF-16 is refused before it is checked (#561): the check would read it one way and
    // the server another.
    let before = k.svc.calls("/call").len();
    let mut f = flow(
        &le,
        "application/json; charset=utf-16le",
        "mcp.example.com",
        443,
        "POST",
    );
    assert_eq!(run(&k, &mut f).await.map(|a| a.0), Some(400));
    assert_eq!(k.svc.calls("/call").len(), before);
    // A tools/list the service could not check is kept from the agent.
    let mut f = flow(list.as_bytes(), "application/json", "mcp.example.com", 443, "POST");
    assert!(run(&k, &mut f).await.is_none());
    k.svc.answer("/tools", Answer::raw(500, "down"));
    f.response = Some(crate::checks::raw_response(
        200,
        br#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"delete_doc"}]}}"#.to_vec(),
        "application/json",
    ));
    McpResponse(k.mcp.clone()).run(Hook::Response, &mut f).await;
    let body = f.response.as_ref().map(|r| r.body().clone()).unwrap_or_default();
    assert!(!String::from_utf8_lossy(&body).contains("delete_doc"));
    // A list too large to check is kept from the agent too (the addon passed it; on purpose).
    let before = k.svc.calls("/tools").len();
    let mut f = flow(list.as_bytes(), "application/json", "mcp.example.com", 443, "POST");
    assert!(run(&k, &mut f).await.is_none());
    let big = format!(
        r#"{{"jsonrpc":"2.0","id":1,"result":{{"tools":[{{"name":"delete_doc","description":"{}"}}]}}}}"#,
        "x".repeat(MCP_ANSWER_MAX)
    );
    f.response = Some(crate::checks::raw_response(200, big.into_bytes(), "application/json"));
    McpResponse(k.mcp.clone()).run(Hook::Response, &mut f).await;
    let body = f.response.as_ref().map(|r| r.body().clone()).unwrap_or_default();
    assert!(String::from_utf8_lossy(&body).contains("could not check this list"));
    assert_eq!(k.svc.calls("/tools").len(), before, "not sent to the service");
}

/// A tool call body, its kind, plainness and id.
fn read_of(b: &[u8]) -> Option<Reading> {
    read(&flow(b, "application/json", "mcp.example.com", 443, "POST"))
}

#[test]
fn production_561_readings() {
    let text = call().to_string();
    let plain_call = read_of(text.as_bytes()).expect("call");
    assert_eq!((plain_call.kind, plain_call.plain), ("call", true));
    // A BOM, UTF-16 and UTF-32 (with and without a mark), a bad byte, NaN: calls, not plain.
    let u16le: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let u32le: Vec<u8> = text.chars().flat_map(|c| u32::from(c).to_le_bytes()).collect();
    let u32be: Vec<u8> = text.chars().flat_map(|c| u32::from(c).to_be_bytes()).collect();
    let nan = br#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"x","arguments":{"n":NaN}}}"#;
    let bad = b"{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"x\xff\"}}";
    for (what, body) in [
        ("utf-8 BOM", [b"\xef\xbb\xbf".as_slice(), text.as_bytes()].concat()),
        ("utf-16", u16le.clone()),
        ("utf-32 LE", u32le.clone()),
        ("utf-32 BE", u32be),
        ("utf-32 mark", [b"\xff\xfe\x00\x00".as_slice(), &u32le].concat()),
        ("NaN", nan.to_vec()),
        ("bad byte", bad.to_vec()),
    ] {
        let r = read_of(&body).unwrap_or_else(|| panic!("{what}: not read"));
        assert_eq!((r.kind, r.plain), ("call", false), "{what}");
    }
    // Stricter than the addon (review): UTF-32 BE with its mark, and UTF-16/32 with leading spaces
    // that push the `{` past the first 8 bytes, are read too.
    let be32: Vec<u8> = text.chars().flat_map(|c| u32::from(c).to_be_bytes()).collect();
    let spaced: Vec<u8> = format!("    {text}")
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    for (what, body) in [
        ("utf-32 BE mark", [b"\x00\x00\xfe\xff".as_slice(), &be32].concat()),
        ("utf-16 after spaces", spaced),
    ] {
        let r = read_of(&body).unwrap_or_else(|| panic!("{what}: not read"));
        assert_eq!((r.kind, r.plain, r.id), ("call", false, Some(json!(7))), "{what}");
    }
    // NaN inside a string is text, not a constant.
    let r = read_of(br#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"NaN Infinity"}}"#);
    assert_eq!(r.map(|r| r.plain), Some(true));
    // A key in another case, also folded (the Kelvin sign, the long s): a call, not plain, its id kept.
    for body in [
        r#"{"jsonrpc":"2.0","id":"a1","Method":"tools/call","params":{"name":"x"}}"#,
        "{\"j\u{17f}onrpc\":\"2.0\",\"id\":\"a1\",\"method\":\"tools/call\",\"params\":{\"name\":\"x\"}}",
        "{\"jsonrpc\":\"2.0\",\"id\":\"a1\",\"method\":\"tools/call\",\"param\u{17f}\":{\"name\":\"x\"}}",
        r#"{"jsonrpc":"2.0","id":"a1","method":"tools/call","params":{"Name":"x"}}"#,
    ] {
        let r = read_of(body.as_bytes()).unwrap_or_else(|| panic!("{body}"));
        assert_eq!((r.kind, r.plain, r.id), ("call", false, Some(json!("a1"))), "{body}");
    }
    // The Kelvin sign folds to `k`, which none of the keys has: not odd, as in Python.
    let kelvin = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"x\",\"\u{212a}\":1}}";
    assert_eq!(read_of(kelvin.as_bytes()).map(|r| r.plain), Some(true));
    // Other JSON with such a key is not a call.
    assert_eq!(read_of(br#"{"Name": "x", "Method": "post"}"#), None);
    // Not JSON to us but naming a call, escaped or wide: a call.
    assert_eq!(
        read_of(br#"{"method": "tools\u002fcall", oops"#).map(|r| r.kind),
        Some("call")
    );
    let wide: Vec<u8> = r#"{"m": "tools/call", oops"#.chars().flat_map(|c| u32::from(c).to_le_bytes()).collect();
    assert_eq!(read_of(&wide).map(|r| r.kind), Some("call"));
    // Over the parse limit, anything that starts like JSON is a call, an escaped one too.
    let big = format!(
        r#"{{"method": "tools\u002fcall", "pad": "{}"}}"#,
        "a".repeat(MCP_PARSE_MAX)
    );
    assert_eq!(read_of(big.as_bytes()).map(|r| r.kind), Some("call"));
    // The id: the first tools/call's, a string or a whole number, never a bool.
    let batch = json!([{"jsonrpc": "2.0", "id": 1, "method": "ping"}, {"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": {"name": "x"}}]);
    assert_eq!(read_of(&j(&batch)).and_then(|r| r.id), Some(json!(9)));
    let boolean = json!({"jsonrpc": "2.0", "id": true, "method": "tools/call", "params": {"name": "x"}});
    assert_eq!(read_of(&j(&boolean)).map(|r| r.id), Some(None));
}

#[tokio::test]
async fn production_561_refusals_carry_the_id() {
    let k = kit().await;
    // Not plain: refused with 400 and the call's id, never asked about.
    let body = br#"{"jsonrpc":"2.0","id":42,"method":"tools/call","params":{"name":"x","arguments":{"n":NaN}}}"#;
    let mut f = flow(body, "application/json", "mcp.example.com", 443, "POST");
    let (status, text) = run(&k, &mut f).await.expect("refused");
    assert_eq!(status, 400);
    let doc: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    assert_eq!(doc["id"], json!(42));
    assert!(
        doc["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("plain UTF-8 JSON")
    );
    assert_eq!(f.meta[crate::checks::META_RULE], json!("integrations: unreadable"));
    assert!(k.svc.calls("/call").is_empty());
    // Unknown agent: 403 with the id.
    let mut f = flow(
        &j(&json!({"jsonrpc": "2.0", "id": "c7", "method": "tools/call", "params": {"name": "x"}})),
        "application/json",
        "mcp.example.com",
        443,
        "POST",
    );
    f.vm_id = None;
    let (status, text) = run(&k, &mut f).await.expect("refused");
    assert_eq!(status, 403);
    assert_eq!(
        serde_json::from_str::<Value>(&text).unwrap_or(Value::Null)["id"],
        json!("c7")
    );
}
