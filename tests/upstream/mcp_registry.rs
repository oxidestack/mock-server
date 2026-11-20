//! `McpToolRegistryTest` (mockserver-netty, in-JVM unit test of `McpToolRegistry`): the tests of the fifteen tools
//! built here, through `Server::call_mcp_tool`. The tool definitions come from `tools/list` over the MCP endpoint.
//! Where upstream logs a forwarded exchange straight into `HttpState`, the port has the server answer a request
//! with that response instead (a mocked exchange is recorded the same way).

use serde_json::{Value, json};

use crate::common;

pub(crate) async fn call(server: &common::Running, tool: &str, args: Value) -> Value {
    server.server.call_mcp_tool(tool, &args).await
}

/// `tools/list` over the MCP endpoint.
pub(crate) async fn tools_list(server: &common::Running) -> Vec<Value> {
    let (_, session) = post(server.port, None, r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}"#).await;
    post(server.port, session.as_deref(), r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#).await;
    let (body, _) = post(server.port, session.as_deref(), r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#).await;
    let list: Value = serde_json::from_str(&body).unwrap();
    list["result"]["tools"].as_array().cloned().unwrap_or_default()
}

/// A tool's definition from `tools/list`.
pub(crate) async fn definition(server: &common::Running, name: &str) -> Value {
    tools_list(server).await.into_iter().find(|t| t["name"] == name).unwrap_or(Value::Null)
}

/// A JSON-RPC POST to `/mockserver/mcp`: the body and the session id answered.
async fn post(port: u16, session: Option<&str>, body: &str) -> (String, Option<String>) {
    use std::io::{Read, Write};
    let (session, body) = (session.map(str::to_string), body.to_string());
    tokio::task::spawn_blocking(move || {
        let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        let session = session.map(|id| format!("Mcp-Session-Id: {id}\r\n")).unwrap_or_default();
        write!(
            s,
            "POST /mockserver/mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nAccept: application/json, text/event-stream\r\n{session}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
        let mut raw = Vec::new();
        s.read_to_end(&mut raw).unwrap();
        let text = String::from_utf8_lossy(&raw).into_owned();
        let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
        let id = head.lines().find_map(|l| l.split_once(':').filter(|(k, _)| k.eq_ignore_ascii_case("mcp-session-id")).map(|(_, v)| v.trim().to_string()));
        (body.to_string(), id)
    })
    .await
    .unwrap()
}

fn has_properties(tool: &Value, names: &[&str]) -> bool {
    names.iter().all(|n| tool["inputSchema"]["properties"].get(*n).is_some())
}

const SPEC: &str = "org/mockserver/openapi/openapi_simple_example.json";

#[tokio::test(flavor = "multi_thread")]
async fn should_register_all_tools() {
    let server = common::start(&[]).await;
    let tools = tools_list(&server).await;
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    for expected in [
        "create_expectation", "verify_request", "retrieve_recorded_requests", "clear_expectations", "reset", "get_status", "verify_request_sequence",
        "retrieve_request_responses", "create_forward_expectation", "debug_request_mismatch", "create_expectation_from_openapi", "stop_server",
        "raw_expectation", "raw_retrieve", "raw_verify", "explain_unmatched_requests", "create_expectations_from_recorded_traffic",
        "verify_traffic_against_openapi", "run_contract_test", "run_resiliency_test", "record_llm_fixtures", "load_expectations_from_file",
        "mock_llm_completion", "create_llm_conversation", "verify_tool_call", "explain_agent_run", "detect_llm_drift", "mock_adversarial_llm_response",
        "run_mcp_contract_test", "verify_structured_output", "verify_cost_budget", "manage_service_chaos", "list_mock_tools", "retrieve_logs",
        "mock_llm_failover", "export_optimisation_report", "diff_agent_runs", "list_expectations", "set_operating_mode", "promote_recordings",
        "explain_request", "diagnose_config", "explain_forward_failure", "test_template", "lint_expectations", "suggest_expectation_fix",
    ] {
        assert!(names.contains(&expected), "{expected}");
    }
    assert_eq!(names.len(), 46);
    // Every catalogued tool answers (none falls through to a "not supported" error).
    for name in &names {
        if *name == "stop_server" {
            continue;
        }
        let result = call(&server, name, json!({})).await;
        assert!(!result["message"].as_str().unwrap_or_default().contains("not supported"), "{name}: {result}");
    }
    server.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_verify_traffic_against_open_api_tool_has_schema() {
    let server = common::start(&[]).await;
    let tool = definition(&server, "verify_traffic_against_openapi").await;
    assert!(tool["description"].as_str().unwrap().contains("recorded by MockServer"));
    assert!(has_properties(&tool, &["specUrlOrPayload", "method", "path"]));
    server.server.shutdown().await;
}

async fn assert_error(server: &common::Running, tool: &str, args: Value, message: &str, exact: bool) {
    let result = call(server, tool, args).await;
    assert_eq!(result["error"], true, "{result}");
    let text = result["message"].as_str().unwrap();
    if exact {
        assert_eq!(text, message);
    } else {
        assert!(text.contains(message), "{message} in {text}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reject_blank_spec_for_verify_traffic() {
    let server = common::start(&[]).await;
    assert_error(&server, "verify_traffic_against_openapi", json!({"specUrlOrPayload": ""}), "'specUrlOrPayload' is required and must not be blank", true).await;
    server.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_return_no_traffic_when_none_exists() {
    let server = common::start(&[]).await;
    let result = call(&server, "verify_traffic_against_openapi", json!({"specUrlOrPayload": SPEC})).await;
    assert_eq!(result["status"], "no_traffic");
    assert_eq!(result["totalPairs"], 0);
    server.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_run_contract_test_tool_has_schema() {
    let server = common::start(&[]).await;
    let tool = definition(&server, "run_contract_test").await;
    let description = tool["description"].as_str().unwrap();
    assert!(description.contains("example requests") && description.contains("OpenAPI"));
    assert!(has_properties(&tool, &["specUrlOrPayload", "baseUrl", "operationId"]));
    server.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_run_resiliency_test_tool_has_schema() {
    let server = common::start(&[]).await;
    let tool = definition(&server, "run_resiliency_test").await;
    let description = tool["description"].as_str().unwrap();
    assert!(description.contains("malformed") && description.contains("boundary") && description.contains("OpenAPI"));
    assert!(has_properties(&tool, &["specUrlOrPayload", "baseUrl", "operationId"]));
    server.server.shutdown().await;
}

async fn rejects(tool: &str, args: Value, message: &str, exact: bool) {
    let server = common::start(&[]).await;
    assert_error(&server, tool, args, message, exact).await;
    server.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reject_blank_spec_for_contract_test() {
    rejects("run_contract_test", json!({"specUrlOrPayload": "", "baseUrl": "http://localhost:8080"}), "'specUrlOrPayload' is required and must not be blank", true).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reject_blank_base_url_for_contract_test() {
    rejects("run_contract_test", json!({"specUrlOrPayload": SPEC, "baseUrl": ""}), "'baseUrl' is required and must not be blank", true).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reject_invalid_base_url_for_contract_test() {
    rejects("run_contract_test", json!({"specUrlOrPayload": SPEC, "baseUrl": "not a url"}), "'baseUrl' is not a valid URL", false).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reject_base_url_with_no_host_for_contract_test() {
    rejects("run_contract_test", json!({"specUrlOrPayload": SPEC, "baseUrl": "file:///some/path"}), "must be an absolute HTTP/HTTPS URL with a hostname", false).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reject_non_http_scheme_for_contract_test() {
    rejects("run_contract_test", json!({"specUrlOrPayload": SPEC, "baseUrl": "ftp://example.com/path"}), "must use the http or https scheme", false).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reject_blank_spec_for_resiliency_test() {
    rejects("run_resiliency_test", json!({"specUrlOrPayload": "", "baseUrl": "http://localhost:8080"}), "'specUrlOrPayload' is required and must not be blank", true).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reject_blank_base_url_for_resiliency_test() {
    rejects("run_resiliency_test", json!({"specUrlOrPayload": SPEC, "baseUrl": ""}), "'baseUrl' is required and must not be blank", true).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reject_invalid_base_url_for_resiliency_test() {
    rejects("run_resiliency_test", json!({"specUrlOrPayload": SPEC, "baseUrl": "not a url"}), "'baseUrl' is not a valid URL", false).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reject_base_url_with_no_host_for_resiliency_test() {
    rejects("run_resiliency_test", json!({"specUrlOrPayload": SPEC, "baseUrl": "file:///some/path"}), "must be an absolute HTTP/HTTPS URL with a hostname", false).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reject_non_http_scheme_for_resiliency_test() {
    rejects("run_resiliency_test", json!({"specUrlOrPayload": SPEC, "baseUrl": "ftp://example.com/path"}), "must use the http or https scheme", false).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_run_mcp_contract_test_tool_has_schema() {
    let server = common::start(&[]).await;
    let tool = definition(&server, "run_mcp_contract_test").await;
    let description = tool["description"].as_str().unwrap();
    assert!(description.contains("MCP") && description.contains("JSON-RPC"));
    assert!(has_properties(&tool, &["targetUrl", "protocolVersion", "toolName"]));
    server.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reject_blank_target_url_for_mcp_contract_test() {
    let server = common::start(&[]).await;
    assert_error(&server, "run_mcp_contract_test", json!({"targetUrl": ""}), "'targetUrl' is required and must not be blank", true).await;
    server.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reject_target_url_with_no_host_for_mcp_contract_test() {
    let server = common::start(&[]).await;
    assert_error(&server, "run_mcp_contract_test", json!({"targetUrl": "file:///some/path"}), "must be an absolute HTTP/HTTPS URL with a hostname", false).await;
    server.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reject_non_http_scheme_for_mcp_contract_test() {
    let server = common::start(&[]).await;
    assert_error(&server, "run_mcp_contract_test", json!({"targetUrl": "ftp://example.com/mcp"}), "must use the http or https scheme", false).await;
    server.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_verify_structured_output_tool_has_schema() {
    let server = common::start(&[]).await;
    let tool = definition(&server, "verify_structured_output").await;
    assert!(tool["description"].as_str().unwrap().contains("JSON Schema"));
    assert!(has_properties(&tool, &["provider", "schema"]));
    server.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reject_missing_provider_for_verify_structured_output() {
    let server = common::start(&[]).await;
    assert_error(&server, "verify_structured_output", json!({"schema": "{\"type\":\"object\"}"}), "'provider' is required", true).await;
    server.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reject_blank_schema_for_verify_structured_output() {
    let server = common::start(&[]).await;
    assert_error(&server, "verify_structured_output", json!({"provider": "ANTHROPIC", "schema": ""}), "'schema' is required and must not be blank", true).await;
    server.server.shutdown().await;
}

const CITY_SCHEMA: &str = r#"{"type":"object","required":["city"]}"#;

#[tokio::test(flavor = "multi_thread")]
async fn should_return_zero_checked_when_no_recorded_responses() {
    let server = common::start(&[]).await;
    let result = call(&server, "verify_structured_output", json!({"provider": "ANTHROPIC", "schema": CITY_SCHEMA})).await;
    assert!(result.get("error").is_none(), "{result}");
    assert_eq!(result["checked"], 0);
    assert_eq!(result["allConform"], false);
    server.server.shutdown().await;
}

/// Recorded exchanges on `/v1/messages`: each request body answered with the Anthropic response body given.
pub(crate) async fn recorded(server: &common::Running, exchanges: &[(&str, &str)]) {
    for (i, (request_body, response_body)) in exchanges.iter().enumerate() {
        let marker = format!("/v1/messages/{i}");
        common::expect(server.port, &json!({"httpRequest": {"method": "POST", "path": marker}, "httpResponse": {"statusCode": 200, "body": response_body}, "times": {"remainingTimes": 1}})).await;
        let _ = common::send(server.port, "POST", &marker, request_body).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn should_report_conforming_structured_output() {
    let server = common::start(&[]).await;
    recorded(&server, &[("", r#"{"content":[{"type":"text","text":"{\"city\":\"Paris\"}"}],"usage":{"input_tokens":1,"output_tokens":1}}"#)]).await;
    let result = call(&server, "verify_structured_output", json!({"provider": "ANTHROPIC", "path": "/v1/messages/0", "schema": CITY_SCHEMA})).await;
    assert!(result.get("error").is_none(), "{result}");
    assert_eq!(result["checked"], 1);
    assert_eq!(result["conforming"], 1);
    assert_eq!(result["allConform"], true);
    server.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_flag_non_conforming_structured_output() {
    let server = common::start(&[]).await;
    recorded(&server, &[("", r#"{"content":[{"type":"text","text":"{\"foo\":1}"}],"usage":{"input_tokens":1,"output_tokens":1}}"#)]).await;
    let result = call(&server, "verify_structured_output", json!({"provider": "ANTHROPIC", "path": "/v1/messages/0", "schema": CITY_SCHEMA})).await;
    assert_eq!(result["checked"], 1, "{result}");
    assert_eq!(result["nonConforming"], 1);
    assert_eq!(result["allConform"], false);
    server.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reject_missing_max_cost_for_verify_cost_budget() {
    let server = common::start(&[]).await;
    assert_error(&server, "verify_cost_budget", json!({"provider": "ANTHROPIC"}), "maxCostUsd", false).await;
    server.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reject_negative_max_cost_for_verify_cost_budget() {
    let server = common::start(&[]).await;
    assert_error(&server, "verify_cost_budget", json!({"provider": "ANTHROPIC", "maxCostUsd": -1.0}), "negative", false).await;
    server.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_report_zero_cost_when_no_recorded_responses() {
    let server = common::start(&[]).await;
    let result = call(&server, "verify_cost_budget", json!({"provider": "ANTHROPIC", "maxCostUsd": 5.0})).await;
    assert!(result.get("error").is_none(), "{result}");
    assert_eq!(result["checked"], 0);
    assert_eq!(result["totalCostUsd"].as_f64(), Some(0.0));
    assert_eq!(result["withinBudget"], true);
    server.server.shutdown().await;
}

fn usage(input: i64, output: i64) -> String {
    format!(r#"{{"content":[{{"type":"text","text":"ok"}}],"usage":{{"input_tokens":{input},"output_tokens":{output}}}}}"#)
}

async fn cost(server: &common::Running, model: Option<&str>, max: f64) -> Value {
    let mut args = json!({"provider": "ANTHROPIC", "maxCostUsd": max});
    if let Some(m) = model {
        args["model"] = json!(m);
    }
    call(server, "verify_cost_budget", args).await
}

#[tokio::test(flavor = "multi_thread")]
async fn should_pass_when_cost_within_budget() {
    let server = common::start(&[]).await;
    recorded(&server, &[("", &usage(1_000_000, 1_000_000))]).await;
    let result = cost(&server, Some("claude-sonnet-4"), 20.0).await;
    assert!(result.get("error").is_none(), "{result}");
    assert_eq!(result["checked"], 1);
    assert_eq!(result["totalInputTokens"], 1_000_000);
    assert_eq!(result["totalOutputTokens"], 1_000_000);
    assert_eq!(result["totalCostUsd"].as_f64(), Some(18.0));
    assert_eq!(result["withinBudget"], true);
    assert_eq!(result["budgetCheckAuthoritative"], true);
    server.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_sum_cost_across_multiple_responses() {
    let server = common::start(&[]).await;
    let body = usage(500_000, 500_000);
    recorded(&server, &[("", &body), ("", &body)]).await;
    let result = cost(&server, Some("claude-sonnet-4"), 20.0).await;
    assert_eq!(result["checked"], 2, "{result}");
    assert_eq!(result["totalInputTokens"], 1_000_000);
    assert_eq!(result["totalOutputTokens"], 1_000_000);
    assert_eq!(result["totalCostUsd"].as_f64(), Some(18.0));
    assert_eq!(result["withinBudget"], true);
    assert_eq!(result["budgetCheckAuthoritative"], true);
    server.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_report_partial_total_and_non_authoritative_for_mixed_priceability() {
    let server = common::start(&[]).await;
    let body = usage(1_000_000, 0);
    recorded(&server, &[(r#"{"model":"claude-sonnet-4"}"#, &body), ("", &body)]).await;
    let result = cost(&server, None, 20.0).await;
    assert_eq!(result["checked"], 2, "{result}");
    assert_eq!(result["unpriceable"], 1);
    assert_eq!(result["totalCostUsd"].as_f64(), Some(3.0));
    assert_eq!(result["withinBudget"], true);
    assert_eq!(result["budgetCheckAuthoritative"], false);
    server.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_fail_when_cost_exceeds_budget() {
    let server = common::start(&[]).await;
    recorded(&server, &[("", &usage(1_000_000, 1_000_000))]).await;
    let result = cost(&server, Some("claude-sonnet-4"), 5.0).await;
    assert_eq!(result["totalCostUsd"].as_f64(), Some(18.0), "{result}");
    assert_eq!(result["withinBudget"], false);
    server.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_report_unpriceable_when_model_unknown() {
    let server = common::start(&[]).await;
    recorded(&server, &[("", &usage(100, 100))]).await;
    let result = cost(&server, None, 5.0).await;
    assert_eq!(result["checked"], 1, "{result}");
    assert_eq!(result["unpriceable"], 1);
    assert_eq!(result["totalCostUsd"].as_f64(), Some(0.0));
    assert_eq!(result["withinBudget"], true);
    assert_eq!(result["budgetCheckAuthoritative"], false);
    server.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_not_be_authoritative_when_no_responses() {
    let server = common::start(&[]).await;
    let result = cost(&server, None, 5.0).await;
    assert_eq!(result["checked"], 0);
    assert_eq!(result["withinBudget"], true);
    assert_eq!(result["budgetCheckAuthoritative"], false);
    server.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_generate_mcp_tools_from_mock_expectations() {
    let server = common::start(&[]).await;
    call(&server, "create_expectation", json!({"method": "GET", "path": "/users", "statusCode": 200})).await;
    let result = call(&server, "list_mock_tools", json!({})).await;
    assert_eq!(result["count"], 1, "{result}");
    let tool = &result["tools"][0];
    assert_eq!(tool["name"], "get_users");
    assert_eq!(tool["description"], "Mock for GET /users");
    assert_eq!(tool["_mockserver"]["method"], "GET");
    assert_eq!(tool["_mockserver"]["path"], "/users");
    server.server.shutdown().await;
}

#[test]
fn should_classify_state_mutating_tools_as_mutating() {
    for tool in [
        "create_expectation", "create_forward_expectation", "create_expectation_from_openapi", "create_expectations_from_recorded_traffic",
        "clear_expectations", "reset", "manage_service_chaos", "stop_server", "raw_expectation", "load_expectations_from_file", "record_llm_fixtures",
        "mock_llm_completion", "create_llm_conversation", "mock_llm_failover", "mock_adversarial_llm_response", "set_operating_mode", "promote_recordings",
    ] {
        assert!(mock_server::mcp_tool_is_mutating(tool), "{tool}");
    }
}

#[test]
fn should_classify_read_only_tools_as_non_mutating() {
    for tool in [
        "verify_request", "verify_request_sequence", "verify_tool_call", "verify_structured_output", "verify_cost_budget", "verify_traffic_against_openapi",
        "retrieve_recorded_requests", "retrieve_logs", "retrieve_request_responses", "get_status", "debug_request_mismatch", "explain_unmatched_requests",
        "explain_agent_run", "export_optimisation_report", "diff_agent_runs", "detect_llm_drift", "list_mock_tools", "list_expectations", "raw_retrieve",
        "raw_verify", "run_contract_test", "run_resiliency_test", "run_mcp_contract_test",
    ] {
        assert!(!mock_server::mcp_tool_is_mutating(tool), "{tool}");
    }
}
