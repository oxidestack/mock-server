//! `McpContractTestAgainstMockServerTest` (mockserver-netty, in-JVM over an `EmbeddedChannel`): the conformance
//! checker run by `run_mcp_contract_test` against a second in-process server's `/mockserver/mcp`, and the session
//! semantics over plain HTTP. (Against the oracle itself the tool cannot run: MockServer's MCP handler blocks on
//! its own event loop when the tool calls back into the same server.)

use std::io::{Read, Write};

use serde_json::{Value, json};

use crate::common;

async fn contract(target: u16, protocol: Option<&str>, tool: Option<&str>) -> Value {
    let caller = common::start(&[]).await;
    let mut args = json!({"targetUrl": format!("http://127.0.0.1:{target}/mockserver/mcp")});
    if let Some(p) = protocol {
        args["protocolVersion"] = json!(p);
    }
    if let Some(t) = tool {
        args["toolName"] = json!(t);
    }
    let report = caller.server.call_mcp_tool("run_mcp_contract_test", &args).await;
    caller.server.shutdown().await;
    report
}

/// A POST (or DELETE) to `/mockserver/mcp`: the status, the session header and the body.
async fn mcp(port: u16, method: &str, body: &str, session: Option<&str>) -> (u16, Option<String>, String) {
    let (method, body, session) = (method.to_string(), body.to_string(), session.map(str::to_string));
    tokio::task::spawn_blocking(move || {
        let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        let session = session.map(|id| format!("Mcp-Session-Id: {id}\r\n")).unwrap_or_default();
        write!(
            s,
            "{method} /mockserver/mcp HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nAccept: application/json, text/event-stream\r\n{session}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
        let mut raw = Vec::new();
        s.read_to_end(&mut raw).unwrap();
        let text = String::from_utf8_lossy(&raw).into_owned();
        let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
        let status = head.split(' ').nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
        let id = head.lines().find_map(|l| l.split_once(':').filter(|(k, _)| k.eq_ignore_ascii_case("mcp-session-id")).map(|(_, v)| v.trim().to_string()));
        (status, id, body.to_string())
    })
    .await
    .unwrap()
}

const INITIALIZE: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}"#;
const TOOLS_LIST: &str = r#"{"jsonrpc":"2.0","id":99,"method":"tools/list","params":{}}"#;

#[tokio::test(flavor = "multi_thread")]
async fn should_pass_its_own_mcp_conformance_suite() {
    let target = common::start(&[]).await;
    let report = contract(target.port, None, Some("get_status")).await;
    let failures: Vec<&Value> = report["results"].as_array().unwrap().iter().filter(|c| c["passed"] != true).collect();
    assert!(failures.is_empty(), "{report}");
    assert_eq!(report["totalChecks"], 6);
    assert_eq!(report["serverInfo"]["name"], "MockServer");
    assert!(report["serverInfo"]["version"].is_string());
    target.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_negotiate_an_older_protocol_version_during_conformance_run() {
    let target = common::start(&[]).await;
    let report = contract(target.port, Some("2025-03-26"), None).await;
    assert_eq!(report["protocolVersion"], "2025-03-26");
    assert!(report["results"].as_array().unwrap().iter().all(|c| c["passed"] == true), "{report}");
    target.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_fall_back_to_latest_protocol_version_for_unsupported_revision() {
    let target = common::start(&[]).await;
    assert_eq!(contract(target.port, Some("1999-01-01"), None).await["protocolVersion"], "2025-06-18");
    target.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_return_not_found_for_unknown_session() {
    let target = common::start(&[]).await;
    assert_eq!(mcp(target.port, "POST", TOOLS_LIST, Some("a-session-that-was-never-issued")).await.0, 404);
    target.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_return_not_found_for_terminated_session() {
    let target = common::start(&[]).await;
    let session = mcp(target.port, "POST", INITIALIZE, None).await.1.expect("session id");
    assert_eq!(mcp(target.port, "DELETE", "", Some(&session)).await.0, 200);
    assert_eq!(mcp(target.port, "POST", TOOLS_LIST, Some(&session)).await.0, 404);
    target.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_return_bad_request_when_session_id_is_missing_on_non_initialize() {
    let target = common::start(&[]).await;
    assert_eq!(mcp(target.port, "POST", TOOLS_LIST, None).await.0, 400);
    target.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_treat_blank_session_id_as_missing_rather_than_unknown() {
    let target = common::start(&[]).await;
    assert_eq!(mcp(target.port, "POST", TOOLS_LIST, Some("")).await.0, 400);
    assert_eq!(mcp(target.port, "POST", TOOLS_LIST, Some("   ")).await.0, 400);
    assert_eq!(mcp(target.port, "POST", TOOLS_LIST, Some("never-issued")).await.0, 404);
    target.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_return_accepted_with_no_body_for_notification() {
    let target = common::start(&[]).await;
    let session = mcp(target.port, "POST", INITIALIZE, None).await.1;
    let (status, _, body) = mcp(target.port, "POST", r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#, session.as_deref()).await;
    assert_eq!(status, 202);
    assert!(body.is_empty(), "{body}");
    target.server.shutdown().await;
}

// ------------------------------------------------------------------ McpContractTestTest

/// One stubbed answer of a simulated MCP server: the JSON-RPC method it answers, the status, a session id and the
/// body (none for an empty one).
struct Answer {
    method: &'static str,
    status: u16,
    session: Option<&'static str>,
    body: Option<Value>,
}

fn answer(method: &'static str, status: u16, session: Option<&'static str>, body: Option<Value>) -> Answer {
    Answer { method, status, session, body }
}

/// `conformant`: a fully conformant MCP server simulation.
fn conformant() -> Vec<Answer> {
    vec![
        answer(
            "initialize",
            200,
            Some("session-1"),
            Some(json!({"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2025-03-26", "capabilities": {}, "serverInfo": {"name": "StubServer", "version": "9.9"}}})),
        ),
        answer("notifications/initialized", 202, None, None),
        answer("ping", 200, None, Some(json!({"jsonrpc": "2.0", "id": 2, "result": {}}))),
        answer("tools/list", 200, None, Some(json!({"jsonrpc": "2.0", "id": 3, "result": {"tools": [{"name": "do_thing", "inputSchema": {"type": "object"}}]}}))),
        answer("tools/call", 200, None, Some(json!({"jsonrpc": "2.0", "id": 5, "result": {"content": [{"type": "text", "text": "hi"}], "isError": false}}))),
    ]
}

/// A stub server answering `/mcp` with `overrides` first, then the conformant answers, then "method not found".
async fn stub(overrides: Vec<Answer>) -> common::Running {
    let server = common::start(&[]).await;
    let expectation = |a: &Answer, priority: i64| {
        let mut response = json!({"statusCode": a.status});
        if let Some(s) = a.session {
            response["headers"] = json!({"Mcp-Session-Id": [s]});
        }
        if let Some(b) = &a.body {
            response["body"] = json!(b.to_string());
        }
        json!({"priority": priority, "httpRequest": {"method": "POST", "path": "/mcp", "body": {"type": "JSON", "json": {"method": a.method}}}, "httpResponse": response})
    };
    for a in &overrides {
        common::expect(server.port, &expectation(a, 10)).await;
    }
    for a in conformant() {
        common::expect(server.port, &expectation(&a, 0)).await;
    }
    common::expect(
        server.port,
        &json!({"priority": -1, "httpRequest": {"method": "POST", "path": "/mcp"}, "httpResponse": {"body": json!({"jsonrpc": "2.0", "id": 4, "error": {"code": -32601, "message": "Method not found"}}).to_string()}}),
    )
    .await;
    server
}

async fn run(target: &common::Running, protocol: Option<&str>, tool: Option<&str>) -> Value {
    let caller = common::start(&[]).await;
    let mut args = json!({"targetUrl": format!("http://127.0.0.1:{}/mcp", target.port)});
    if let Some(p) = protocol {
        args["protocolVersion"] = json!(p);
    }
    if let Some(t) = tool {
        args["toolName"] = json!(t);
    }
    let report = caller.server.call_mcp_tool("run_mcp_contract_test", &args).await;
    caller.server.shutdown().await;
    report
}

fn check<'a>(report: &'a Value, name: &str) -> &'a Value {
    report["results"].as_array().unwrap().iter().find(|c| c["check"].as_str().unwrap().starts_with(name)).unwrap_or_else(|| panic!("no check named {name}: {report}"))
}

fn errors(check: &Value) -> Vec<String> {
    check["validationErrors"].as_array().map(|a| a.iter().map(|e| e.as_str().unwrap().to_string()).collect()).unwrap_or_default()
}

fn has_error(check: &Value, text: &str) -> bool {
    errors(check).iter().any(|e| e.contains(text))
}

#[tokio::test(flavor = "multi_thread")]
async fn conformant_server_passes_all_core_checks() {
    let target = stub(vec![]).await;
    let report = run(&target, None, None).await;
    assert_eq!(report["totalChecks"], 5, "{report}");
    assert!(report["results"].as_array().unwrap().iter().all(|c| c["passed"] == true), "{report}");
    assert_eq!(report["protocolVersion"], "2025-03-26");
    assert_eq!(report["serverInfo"], json!({"name": "StubServer", "version": "9.9"}));
    assert_eq!(check(&report, "initialize")["detail"], "session established");
    assert_eq!(check(&report, "tools/list")["detail"], "1 tools advertised");
    target.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn exercises_tools_call_when_tool_name_provided() {
    let target = stub(vec![]).await;
    let report = run(&target, None, Some("do_thing")).await;
    assert_eq!(report["totalChecks"], 6);
    let call = check(&report, "tools/call");
    assert!(call["check"].as_str().unwrap().contains("do_thing"));
    assert_eq!(call["passed"], true, "{report}");
    assert_eq!(call["detail"], "isError=false");
    target.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn uses_supplied_protocol_version_when_server_echoes_none() {
    let target = stub(vec![answer("initialize", 200, Some("s"), Some(json!({"jsonrpc": "2.0", "id": 1, "result": {"capabilities": {}, "serverInfo": {"name": "StubServer"}}})))]).await;
    let report = run(&target, Some("2025-06-18"), None).await;
    assert_eq!(report["protocolVersion"], "2025-06-18");
    assert_eq!(check(&report, "initialize")["passed"], false);
    assert!(has_error(check(&report, "initialize"), "protocolVersion is missing"));
    target.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn transport_error_on_initialize_reports_only_initialize() {
    let caller = common::start(&[]).await;
    let report = caller.server.call_mcp_tool("run_mcp_contract_test", &json!({"targetUrl": "http://127.0.0.1:1/mcp"})).await;
    assert_eq!(report["totalChecks"], 1, "{report}");
    assert_eq!(check(&report, "initialize")["passed"], false);
    assert!(has_error(check(&report, "initialize"), "could not connect"));
    caller.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn initialize_missing_server_info_fails() {
    let target = stub(vec![answer("initialize", 200, Some("s"), Some(json!({"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2025-03-26", "capabilities": {}}})))]).await;
    let report = run(&target, None, None).await;
    assert_eq!(check(&report, "initialize")["passed"], false);
    assert!(has_error(check(&report, "initialize"), "serverInfo.name is missing"));
    target.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn tools_list_with_malformed_tool_fails() {
    let target = stub(vec![answer("tools/list", 200, None, Some(json!({"jsonrpc": "2.0", "id": 3, "result": {"tools": [{"name": "missing_schema"}]}})))]).await;
    let report = run(&target, None, None).await;
    let list = check(&report, "tools/list");
    assert_eq!(list["passed"], false);
    assert!(has_error(list, "inputSchema"));
    target.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_method_with_wrong_error_code_fails() {
    let target = stub(vec![answer(
        "mockserver/contract-test/does-not-exist",
        200,
        None,
        Some(json!({"jsonrpc": "2.0", "id": 4, "error": {"code": -32000, "message": "Server error"}})),
    )])
    .await;
    let report = run(&target, None, None).await;
    let unknown = check(&report, "rejects unknown method");
    assert_eq!(unknown["passed"], false);
    assert!(has_error(unknown, "expected error code -32601"));
    target.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_method_accepted_without_error_fails() {
    let target = stub(vec![answer("mockserver/contract-test/does-not-exist", 200, None, Some(json!({"jsonrpc": "2.0", "id": 4, "result": {}})))]).await;
    let report = run(&target, None, None).await;
    assert_eq!(check(&report, "rejects unknown method")["passed"], false);
    target.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn tools_list_accepts_input_schema_without_type_keyword() {
    let target = stub(vec![answer("tools/list", 200, None, Some(json!({"jsonrpc": "2.0", "id": 3, "result": {"tools": [{"name": "do_thing", "inputSchema": {"properties": {}}}]}})))]).await;
    let report = run(&target, None, None).await;
    assert_eq!(check(&report, "tools/list")["passed"], true, "{report}");
    target.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn tools_call_accepts_omitted_is_error() {
    let target = stub(vec![answer("tools/call", 200, None, Some(json!({"jsonrpc": "2.0", "id": 5, "result": {"content": [{"type": "text", "text": "hi"}]}})))]).await;
    let report = run(&target, None, Some("do_thing")).await;
    let call = check(&report, "tools/call");
    assert_eq!(call["passed"], true, "{report}");
    assert_eq!(call["detail"], "isError=false");
    target.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn reports_negotiated_2025_06_18_version_and_validates_new_capability_shapes() {
    let target = stub(vec![
        answer(
            "initialize",
            200,
            Some("session-1"),
            Some(json!({"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2025-06-18", "capabilities": {}, "serverInfo": {"name": "StubServer", "version": "9.9"}}})),
        ),
        answer(
            "tools/call",
            200,
            None,
            Some(json!({"jsonrpc": "2.0", "id": 5, "result": {"content": [{"type": "text", "text": "done"}, {"type": "resource_link", "uri": "file:///out.txt", "name": "out"}], "structuredContent": {"ok": true}, "isError": false}})),
        ),
    ])
    .await;
    let report = run(&target, Some("2025-06-18"), Some("do_thing")).await;
    assert_eq!(report["protocolVersion"], "2025-06-18");
    assert_eq!(check(&report, "tools/call")["passed"], true, "{report}");
    target.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn resource_link_missing_uri_fails() {
    let target = stub(vec![answer("tools/call", 200, None, Some(json!({"jsonrpc": "2.0", "id": 5, "result": {"content": [{"type": "resource_link"}]}})))]).await;
    let report = run(&target, Some("2025-06-18"), Some("do_thing")).await;
    let call = check(&report, "tools/call");
    assert_eq!(call["passed"], false);
    assert!(has_error(call, "resource_link content item is missing 'uri'"));
    target.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn non_object_structured_content_fails() {
    let target = stub(vec![answer(
        "tools/call",
        200,
        None,
        Some(json!({"jsonrpc": "2.0", "id": 5, "result": {"content": [{"type": "text", "text": "hi"}], "structuredContent": "not-an-object"}})),
    )])
    .await;
    let report = run(&target, Some("2025-06-18"), Some("do_thing")).await;
    let call = check(&report, "tools/call");
    assert_eq!(call["passed"], false);
    assert!(has_error(call, "structuredContent is present but not a JSON object"));
    target.server.shutdown().await;
}

async fn notification_check(status: u16, body: Option<Value>) -> Value {
    let target = stub(vec![answer("notifications/initialized", status, None, body)]).await;
    let report = run(&target, None, None).await;
    target.server.shutdown().await;
    check(&report, "notifications/initialized").clone()
}

#[tokio::test(flavor = "multi_thread")]
async fn fails_notification_check_for_two_hundred_with_result_body() {
    let check = notification_check(200, Some(json!({"jsonrpc": "2.0", "result": {}, "id": null}))).await;
    assert_eq!(check["passed"], false);
    assert!(has_error(&check, "expected HTTP 202 Accepted"));
    assert_eq!(errors(&check).len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn fails_notification_check_for_accepted_with_body() {
    let check = notification_check(202, Some(json!({"jsonrpc": "2.0", "result": {}, "id": null}))).await;
    assert_eq!(check["passed"], false);
    assert!(has_error(&check, "expected no body"));
}

#[tokio::test(flavor = "multi_thread")]
async fn does_not_object_to_a_body_on_the_notification_rejection_path() {
    let check = notification_check(400, Some(json!({"jsonrpc": "2.0", "error": {"code": -32600, "message": "cannot accept"}, "id": null}))).await;
    assert!(has_error(&check, "expected HTTP 202 Accepted"));
    assert!(!has_error(&check, "expected no body"));
}

#[tokio::test(flavor = "multi_thread")]
async fn fails_notification_check_for_two_hundred_with_no_body() {
    let check = notification_check(200, None).await;
    assert_eq!(check["passed"], false);
    assert!(has_error(&check, "expected HTTP 202 Accepted"));
    assert_eq!(errors(&check).len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn fails_notification_check_for_no_content_status() {
    let check = notification_check(204, None).await;
    assert_eq!(check["passed"], false);
    assert!(has_error(&check, "expected HTTP 202 Accepted"));
}
