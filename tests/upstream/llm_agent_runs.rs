//! `AgentRunAnalyzerTest` and `AgentRunDiffTest` (mockserver-core, in-JVM unit tests of `AgentRunAnalyzer` and
//! `AgentRunDiff`): the same runs recorded by an in-process server, read back through the `explain_agent_run` and
//! `verify_tool_call` tools and `PUT /mockserver/llm/diffRuns`, which is how these classes are reached. A diff over
//! the endpoint always carries the report's totals, so where a unit test builds a side without totals the port
//! checks a zero delta instead of none.

use std::io::{Read, Write};

use serde_json::{Value, json};

use crate::common;

/// A request with its own `Host` header, on its own connection.
async fn post(port: u16, host: &str, path: &str, body: &str) {
    let (host, path, body) = (host.to_string(), path.to_string(), body.to_string());
    tokio::task::spawn_blocking(move || {
        let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        write!(s, "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
        let mut raw = Vec::new();
        s.read_to_end(&mut raw).unwrap();
    })
    .await
    .unwrap();
}

fn tool_use_conversation() -> &'static str {
    r#"{
  "messages": [
    {"role": "user", "content": "What is the weather in Paris?"},
    {"role": "assistant", "content": [
       {"type": "tool_use", "id": "toolu_1", "name": "get_weather", "input": {"city": "Paris"}}
    ]},
    {"role": "user", "content": [
       {"type": "tool_result", "tool_use_id": "toolu_1", "content": "sunny"}
    ]}
  ]
}"#
}

async fn anthropic_run(bodies: &[&str]) -> common::Running {
    let server = common::start(&[]).await;
    for body in bodies {
        post(server.port, "localhost", "/v1/messages", body).await;
    }
    server
}

async fn tool_calls(server: &common::Running, tool: &str, regex: Option<&str>) -> i64 {
    let mut args = json!({"provider": "ANTHROPIC", "toolName": tool});
    if let Some(r) = regex {
        args["argumentsRegex"] = json!(r);
    }
    let result = server.server.call_mcp_tool("verify_tool_call", &args).await;
    result["count"].as_i64().unwrap_or_else(|| panic!("{result}"))
}

async fn explain(server: &common::Running) -> Value {
    server.server.call_mcp_tool("explain_agent_run", &json!({"provider": "ANTHROPIC"})).await
}

#[tokio::test(flavor = "multi_thread")]
async fn counts_matching_tool_calls() {
    let server = anthropic_run(&[tool_use_conversation()]).await;
    assert_eq!(tool_calls(&server, "get_weather", None).await, 1);
    server.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn does_not_count_tool_calls_for_other_names() {
    let server = anthropic_run(&[tool_use_conversation()]).await;
    assert_eq!(tool_calls(&server, "send_email", None).await, 0);
    server.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn filters_tool_calls_by_arguments_regex() {
    let server = anthropic_run(&[tool_use_conversation()]).await;
    assert_eq!(tool_calls(&server, "get_weather", Some("Paris")).await, 1);
    assert_eq!(tool_calls(&server, "get_weather", Some("London")).await, 0);
    server.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn summarises_run_structure() {
    let server = anthropic_run(&[tool_use_conversation()]).await;
    let summary = explain(&server).await;
    assert_eq!(summary["messageCount"], 3, "{summary}");
    assert_eq!(summary["assistantTurnCount"], 1);
    assert_eq!(summary["toolCallSequence"], json!(["get_weather"]));
    assert_eq!(summary["latestMessageRole"], "TOOL");
    server.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn picks_richest_conversation_across_snapshots() {
    let server = anthropic_run(&[r#"{"messages":[{"role":"user","content":"hi"}]}"#, tool_use_conversation()]).await;
    assert_eq!(explain(&server).await["messageCount"], 3);
    assert_eq!(tool_calls(&server, "get_weather", None).await, 1);
    server.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn empty_when_nothing_decodes() {
    let server = anthropic_run(&["not json"]).await;
    let summary = explain(&server).await;
    assert_eq!(summary["messageCount"], 0, "{summary}");
    assert_eq!(summary["message"], "no decodable ANTHROPIC conversation found in recorded requests");
    assert_eq!(tool_calls(&server, "x", None).await, 0);
    server.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn builds_correlated_call_graph() {
    let server = anthropic_run(&[tool_use_conversation()]).await;
    let graph = explain(&server).await["callGraph"].clone();
    let nodes = graph["nodes"].as_array().unwrap();
    let edges = graph["edges"].as_array().unwrap();
    assert_eq!(nodes.len(), 4, "{graph}");
    assert!(nodes.iter().any(|n| n["kind"] == "TOOL_CALL" && n["label"] == "get_weather"));
    assert!(edges.iter().any(|e| e["kind"] == "RESULT"));
    assert_eq!(edges.iter().filter(|e| e["kind"] == "NEXT").count(), 2);
    server.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn empty_call_graph_when_nothing_decodes() {
    let server = anthropic_run(&["not json"]).await;
    let summary = explain(&server).await;
    // `summarise` is empty, so the tool answers before building the (empty) graph.
    assert!(summary.get("callGraph").is_none(), "{summary}");
    server.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn tool_results_for_reports_correlated_tool_names() {
    let server = anthropic_run(&[tool_use_conversation()]).await;
    assert!(explain(&server).await["toolResultsFor"].as_array().unwrap().contains(&json!("toolu_1")));
    server.server.shutdown().await;
}

// ------------------------------------------------------------------ AgentRunDiffTest

fn chat(messages: &str) -> String {
    format!(r#"{{"model":"gpt-4o-2024-08-06","messages":{messages}}}"#)
}

/// A server that answers `/v1/chat/completions` with the given usage per host, and the two runs sent to it.
async fn two_runs(properties: &[(&str, &str)], before: &str, after: &str, usage: [(i64, i64); 2]) -> common::Running {
    let server = common::start(properties).await;
    for (host, (input, output)) in [("before.example", usage[0]), ("after.example", usage[1])] {
        common::expect(
            server.port,
            &json!({
                "httpRequest": {"method": "POST", "path": "/v1/chat/completions", "headers": {"Host": [host]}},
                "httpLlmResponse": {"provider": "OPENAI", "model": "gpt-4o-2024-08-06", "completion": {"text": "ok", "usage": {"inputTokens": input, "outputTokens": output}}}
            }),
        )
        .await;
    }
    post(server.port, "before.example", "/v1/chat/completions", &chat(before)).await;
    post(server.port, "after.example", "/v1/chat/completions", &chat(after)).await;
    server
}

async fn diff_runs(server: &common::Running, normalization: Option<Value>) -> Value {
    let mut body = json!({"before": {"host": "before.example"}, "after": {"host": "after.example"}});
    if let Some(n) = normalization {
        body["normalization"] = n;
    }
    let reply = common::send(server.port, "PUT", "/mockserver/llm/diffRuns", &body.to_string()).await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    serde_json::from_str(&reply.body).unwrap()
}

fn has(diff: &Value, change: &str, role: &str) -> bool {
    diff["messageDiffs"].as_array().unwrap().iter().any(|d| d["changeType"] == change && d["role"] == role)
}

#[tokio::test(flavor = "multi_thread")]
async fn surfaces_changed_prompt_message() {
    let server = two_runs(
        &[],
        r#"[{"role":"system","content":"sys"},{"role":"user","content":"hello"}]"#,
        r#"[{"role":"system","content":"sys"},{"role":"user","content":"hello world"}]"#,
        [(1, 1), (1, 1)],
    )
    .await;
    let diff = diff_runs(&server, None).await;
    assert_eq!(diff["promptChanged"], true);
    assert!(diff["messageDiffs"].as_array().unwrap().iter().any(|d| d["changeType"] == "CHANGED" && d["role"] == "USER" && d["beforeText"] == "hello" && d["afterText"] == "hello world"), "{diff}");
    assert!(has(&diff, "UNCHANGED", "SYSTEM"));
    server.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn identical_runs_report_no_prompt_change() {
    let messages = r#"[{"role":"user","content":"do the thing"}]"#;
    let server = two_runs(&[], messages, messages, [(5, 2), (5, 2)]).await;
    let diff = diff_runs(&server, None).await;
    assert_eq!(diff["promptChanged"], false, "{diff}");
    assert_eq!(diff["toolCallsAdded"], json!([]));
    assert_eq!(diff["toolCallsRemoved"], json!([]));
    assert_eq!(diff["tokenDelta"]["inputTokensDelta"], 0);
    assert_eq!(diff["tokenDelta"]["outputTokensDelta"], 0);
    server.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn surfaces_added_tool_call() {
    let server = two_runs(
        &[],
        r#"[{"role":"user","content":"weather?"}]"#,
        r#"[{"role":"user","content":"weather?"},{"role":"assistant","tool_calls":[{"id":"call_1","type":"function","function":{"name":"get_weather","arguments":"{\"city\":\"london\"}"}}]}]"#,
        [(1, 1), (1, 1)],
    )
    .await;
    let diff = diff_runs(&server, None).await;
    assert!(diff["toolCallsAdded"].as_array().unwrap().iter().any(|f| f.as_str().unwrap().starts_with("get_weather(")), "{diff}");
    assert_eq!(diff["toolCallsRemoved"], json!([]));
    assert_eq!(diff["promptChanged"], true);
    server.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn surfaces_removed_tool_call() {
    let server = two_runs(
        &[],
        r#"[{"role":"assistant","tool_calls":[{"id":"call_1","type":"function","function":{"name":"lookup","arguments":"{}"}}]}]"#,
        r#"[{"role":"user","content":"done"}]"#,
        [(1, 1), (1, 1)],
    )
    .await;
    let diff = diff_runs(&server, None).await;
    assert!(diff["toolCallsRemoved"].as_array().unwrap().iter().any(|f| f.as_str().unwrap().starts_with("lookup(")), "{diff}");
    server.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn computes_token_and_cost_delta_when_both_sides_have_totals() {
    let messages = r#"[{"role":"user","content":"hi"}]"#;
    let server = two_runs(&[], messages, messages, [(100, 10), (200, 25)]).await;
    let delta = diff_runs(&server, None).await["tokenDelta"].clone();
    assert_eq!(delta["inputTokensDelta"], 100, "{delta}");
    assert_eq!(delta["outputTokensDelta"], 15);
    let (before, after, change) = (delta["costUsdBefore"].as_f64().unwrap(), delta["costUsdAfter"].as_f64().unwrap(), delta["costUsdDelta"].as_f64().unwrap());
    assert!(after > before && (change - (after - before)).abs() < 1e-9, "{delta}");
    server.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn normalisation_suppresses_cosmetic_whitespace_change() {
    let server = two_runs(&[], r#"[{"role":"user","content":"hello   world"}]"#, r#"[{"role":"user","content":"hello world"}]"#, [(1, 1), (1, 1)]).await;
    assert_eq!(diff_runs(&server, Some(json!({}))).await["promptChanged"], false);
    server.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn masks_configured_body_field_in_diff_output_when_request_pre_redacted() {
    let messages = r#"[{"role":"user","content":"super secret prompt"}]"#;
    let server = two_runs(&[("fixtureBodyRedactFields", "content")], messages, messages, [(1, 1), (1, 1)]).await;
    let diff = diff_runs(&server, None).await;
    let text = diff["messageDiffs"].to_string();
    assert!(!text.contains("super secret prompt"), "{diff}");
    assert!(text.contains("***REDACTED***"), "{diff}");
    server.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn handles_empty_runs_gracefully() {
    let server = common::start(&[]).await;
    let diff = diff_runs(&server, None).await;
    assert_eq!(diff["promptChanged"], false);
    assert_eq!(diff["messageCountBefore"], 0);
    assert_eq!(diff["messageCountAfter"], 0);
    server.server.shutdown().await;
}
