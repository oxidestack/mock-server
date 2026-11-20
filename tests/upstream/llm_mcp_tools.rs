//! `LlmMcpToolsTest` (mockserver-netty, in-JVM unit test of `McpToolRegistry`'s LLM tools), one to one through
//! `Server::call_mcp_tool`. Where upstream logs a received request into `HttpState`, the port sends that request to
//! the server; where it reads `allMatchingExpectation`, the port retrieves the active expectations.

use serde_json::{Value, json};

use crate::common::{self, Transport};

async fn call(server: &common::Running, tool: &str, args: Value) -> Value {
    server.server.call_mcp_tool(tool, &args).await
}

async fn with_server<F, Fut>(f: F)
where
    F: FnOnce(common::Running) -> Fut,
    Fut: std::future::Future<Output = common::Running>,
{
    let server = common::start(&[]).await;
    let server = f(server).await;
    server.server.shutdown().await;
}

async fn active(server: &common::Running) -> Vec<Value> {
    let body = common::send(server.port, "PUT", "/mockserver/retrieve?type=ACTIVE_EXPECTATIONS&format=JSON", "").await.body;
    serde_json::from_str::<Value>(&body).unwrap().as_array().cloned().unwrap_or_default()
}

fn error_containing(result: &Value, text: &str) {
    assert_eq!(result["error"], true, "{result}");
    assert!(result["message"].as_str().unwrap().contains(text), "{text} in {result}");
}

// ------------------------------------------------------------------ mock_llm_completion

#[tokio::test(flavor = "multi_thread")]
async fn should_create_llm_completion_expectation() {
    with_server(|s| async move {
        let r = call(&s, "mock_llm_completion", json!({"provider": "ANTHROPIC", "path": "/v1/messages", "model": "claude-sonnet-4", "text": "The capital of France is Paris.", "stopReason": "end_turn"})).await;
        assert_eq!(r["status"], "created");
        assert_eq!(r["count"], 1);
        assert!(r.get("id").is_some());
        assert_eq!(r["provider"], "ANTHROPIC");
        s
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_create_llm_completion_with_tool_calls() {
    with_server(|s| async move {
        let r = call(
            &s,
            "mock_llm_completion",
            json!({"provider": "OPENAI", "path": "/v1/chat/completions", "text": "Let me search for that.", "stopReason": "tool_use", "toolCalls": [{"name": "search", "arguments": "{\"query\":\"weather\"}"}]}),
        )
        .await;
        assert_eq!(r["status"], "created");
        assert_eq!(r["count"], 1);
        s
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_create_llm_completion_with_tool_calls_object_arguments() {
    with_server(|s| async move {
        let r = call(&s, "mock_llm_completion", json!({"provider": "OPENAI", "path": "/v1/chat/completions", "toolCalls": [{"name": "get_weather", "arguments": {"city": "Paris", "unit": "celsius"}}]})).await;
        assert_eq!(r["status"], "created");
        s
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_create_llm_completion_with_output_schema_string() {
    with_server(|s| async move {
        let r = call(&s, "mock_llm_completion", json!({"provider": "ANTHROPIC", "path": "/v1/messages", "text": "{\"name\":\"Ada\"}", "outputSchema": "{\"type\":\"object\",\"required\":[\"name\"]}"})).await;
        assert_eq!(r["status"], "created");
        assert_eq!(active(&s).await[0]["httpLlmResponse"]["completion"]["outputSchema"], "{\"type\":\"object\",\"required\":[\"name\"]}");
        s
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_create_llm_completion_with_output_schema_object() {
    with_server(|s| async move {
        let r = call(&s, "mock_llm_completion", json!({"provider": "ANTHROPIC", "path": "/v1/messages", "text": "{\"name\":\"Ada\"}", "outputSchema": {"type": "object", "required": ["name"]}})).await;
        assert_eq!(r["status"], "created");
        assert!(active(&s).await[0]["httpLlmResponse"]["completion"]["outputSchema"].as_str().unwrap().contains("\"type\":\"object\""));
        s
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reject_non_string_non_object_output_schema() {
    with_server(|s| async move {
        error_containing(&call(&s, "mock_llm_completion", json!({"provider": "ANTHROPIC", "path": "/v1/messages", "text": "{}", "outputSchema": 42})).await, "outputSchema");
        s
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_parse_quota_fields_in_chaos_profile() {
    with_server(|s| async move {
        let r = call(
            &s,
            "mock_llm_completion",
            json!({"provider": "ANTHROPIC", "path": "/v1/messages", "text": "hi", "chaos": {"quotaName": "acct-x", "quotaLimit": 5, "quotaWindowMillis": 60000, "quotaErrorStatus": 529}}),
        )
        .await;
        assert_eq!(r["status"], "created");
        let chaos = active(&s).await[0]["httpLlmResponse"]["chaos"].clone();
        assert_eq!(chaos["quotaName"], "acct-x");
        assert_eq!(chaos["quotaLimit"], 5);
        assert_eq!(chaos["quotaWindowMillis"], 60000);
        assert_eq!(chaos["quotaErrorStatus"], 529);
        s
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_create_llm_completion_with_usage() {
    with_server(|s| async move {
        let r = call(&s, "mock_llm_completion", json!({"provider": "ANTHROPIC", "path": "/v1/messages", "text": "Hello", "usage": {"inputTokens": 42, "outputTokens": 8}})).await;
        assert_eq!(r["status"], "created");
        s
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reject_unknown_provider() {
    with_server(|s| async move {
        let r = call(&s, "mock_llm_completion", json!({"provider": "UNKNOWN_PROVIDER", "path": "/v1/messages"})).await;
        error_containing(&r, "unsupported LLM provider");
        error_containing(&r, "UNKNOWN_PROVIDER");
        s
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_accept_gemini_provider_with_codec() {
    with_server(|s| async move {
        let r = call(&s, "mock_llm_completion", json!({"provider": "GEMINI", "path": "/v1/models/gemini/generateContent", "text": "Hello from Gemini"})).await;
        assert_eq!(r["status"], "created");
        assert_eq!(r["count"], 1);
        assert_eq!(r["provider"], "GEMINI");
        s
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reject_missing_provider() {
    with_server(|s| async move {
        error_containing(&call(&s, "mock_llm_completion", json!({"path": "/v1/messages"})).await, "'provider' is required");
        s
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reject_missing_path() {
    with_server(|s| async move {
        error_containing(&call(&s, "mock_llm_completion", json!({"provider": "ANTHROPIC"})).await, "'path' is required");
        s
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reject_tool_call_without_name() {
    with_server(|s| async move {
        error_containing(&call(&s, "mock_llm_completion", json!({"provider": "ANTHROPIC", "path": "/v1/messages", "toolCalls": [{"arguments": "{}"}]})).await, "non-empty 'name'");
        s
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_accept_malformed_json_string_arguments() {
    with_server(|s| async move {
        let r = call(&s, "mock_llm_completion", json!({"provider": "ANTHROPIC", "path": "/v1/messages", "toolCalls": [{"name": "my_tool", "arguments": "{\"unclosed\":"}]})).await;
        assert_eq!(r["status"], "created");
        assert_eq!(r["count"], 1);
        s
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reject_non_string_non_object_arguments() {
    with_server(|s| async move {
        let r = call(&s, "mock_llm_completion", json!({"provider": "OPENAI", "path": "/v1/chat/completions", "toolCalls": [{"name": "my_tool", "arguments": ["invalid"]}]})).await;
        error_containing(&r, "arguments must be a string or object");
        s
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_accept_valid_json_string_arguments() {
    with_server(|s| async move {
        let r = call(&s, "mock_llm_completion", json!({"provider": "ANTHROPIC", "path": "/v1/messages", "toolCalls": [{"name": "my_tool", "arguments": "{\"key\":\"value\"}"}]})).await;
        assert_eq!(r["status"], "created");
        s
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_accept_plain_text_string_arguments() {
    with_server(|s| async move {
        let r = call(&s, "mock_llm_completion", json!({"provider": "OPENAI", "path": "/v1/chat/completions", "toolCalls": [{"name": "my_tool", "arguments": "not_a_json_object"}]})).await;
        assert_eq!(r["status"], "created");
        s
    })
    .await;
}

// ------------------------------------------------------------------ create_llm_conversation

fn states(r: &Value) -> Vec<(String, String)> {
    r["states"].as_array().unwrap().iter().map(|s| (s["scenarioState"].as_str().unwrap().to_string(), s["newScenarioState"].as_str().unwrap().to_string())).collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn should_create_llm_conversation_with_two_turns() {
    with_server(|s| async move {
        let r = call(
            &s,
            "create_llm_conversation",
            json!({"provider": "ANTHROPIC", "path": "/v1/messages", "model": "claude-sonnet-4", "turns": [
                {"match": {"turnIndex": 0}, "response": {"stopReason": "tool_use", "toolCalls": [{"name": "search", "arguments": "{\"query\":\"test\"}"}]}},
                {"match": {"containsToolResultFor": "search"}, "response": {"text": "The answer is 42.", "stopReason": "end_turn"}}
            ]}),
        )
        .await;
        assert_eq!(r["status"], "created");
        assert_eq!(r["count"], 2);
        assert!(r["scenarioName"].as_str().unwrap().contains("__llm_conv_"));
        assert_eq!(states(&r), vec![("Started".into(), "turn_1".into()), ("turn_1".into(), "__done".into())]);
        s
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_create_llm_conversation_with_isolation() {
    with_server(|s| async move {
        let r = call(&s, "create_llm_conversation", json!({"provider": "ANTHROPIC", "path": "/v1/messages", "isolateBy": {"source": "header", "name": "x-session-id"}, "turns": [{"response": {"text": "Hello"}}]})).await;
        assert_eq!(r["status"], "created");
        let name = r["scenarioName"].as_str().unwrap();
        assert!(name.contains("__iso=") && name.contains("header:x-session-id"), "{name}");
        s
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reject_conversation_with_unknown_provider() {
    with_server(|s| async move {
        error_containing(&call(&s, "create_llm_conversation", json!({"provider": "INVALID", "path": "/v1/messages", "turns": [{"response": {"text": "Hello"}}]})).await, "unsupported LLM provider");
        s
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_accept_gemini_conversation_with_codec() {
    with_server(|s| async move {
        let r = call(&s, "create_llm_conversation", json!({"provider": "GEMINI", "path": "/v1/models/gemini/generateContent", "turns": [{"response": {"text": "Hello from Gemini"}}]})).await;
        assert_eq!(r["status"], "created");
        assert_eq!(r["count"], 1);
        s
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reject_conversation_with_empty_turns() {
    with_server(|s| async move {
        error_containing(&call(&s, "create_llm_conversation", json!({"provider": "ANTHROPIC", "path": "/v1/messages", "turns": []})).await, "non-empty array");
        s
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reject_conversation_with_invalid_isolate_by_source() {
    with_server(|s| async move {
        let r = call(&s, "create_llm_conversation", json!({"provider": "ANTHROPIC", "path": "/v1/messages", "isolateBy": {"source": "body", "name": "field"}, "turns": [{"response": {"text": "Hello"}}]})).await;
        error_containing(&r, "header, queryParameter, cookie");
        s
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_create_conversation_with_three_turns() {
    with_server(|s| async move {
        let r = call(
            &s,
            "create_llm_conversation",
            json!({"provider": "OPENAI", "path": "/v1/chat/completions", "turns": [{"response": {"text": "Turn 0"}}, {"response": {"text": "Turn 1"}}, {"response": {"text": "Turn 2"}}]}),
        )
        .await;
        assert_eq!(r["status"], "created");
        assert_eq!(r["count"], 3);
        assert_eq!(states(&r), vec![("Started".into(), "turn_1".into()), ("turn_1".into(), "turn_2".into()), ("turn_2".into(), "__done".into())]);
        s
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_create_llm_conversation_with_per_turn_chaos() {
    with_server(|s| async move {
        let r = call(&s, "create_llm_conversation", json!({"provider": "ANTHROPIC", "path": "/v1/messages", "turns": [{"response": {"text": "Turn 0"}, "chaos": {"truncateMode": "MID_STREAM", "truncateAtFraction": 0.5}}]})).await;
        assert_eq!(r["status"], "created");
        assert_eq!(r["count"], 1);
        s
    })
    .await;
}

// ------------------------------------------------------------------ verify_tool_call / explain_agent_run

const TOOL_USE_CONVERSATION: &str = r#"{
  "messages": [
    {"role": "user", "content": "Weather in Paris?"},
    {"role": "assistant", "content": [{"type": "tool_use", "id": "toolu_1", "name": "get_weather", "input": {"city": "Paris"}}]},
    {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "toolu_1", "content": "sunny"}]}
  ]
}"#;

/// `logToolUseConversation`: the conversation received on `/v1/messages`.
async fn tool_use_conversation(s: &common::Running) {
    common::exchange(s.port, Transport::Http, "POST", "/v1/messages", &[], TOOL_USE_CONVERSATION).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_verify_tool_call_was_made() {
    with_server(|s| async move {
        tool_use_conversation(&s).await;
        let r = call(&s, "verify_tool_call", json!({"provider": "ANTHROPIC", "path": "/v1/messages", "toolName": "get_weather"})).await;
        assert_eq!(r["satisfied"], true, "{r}");
        assert_eq!(r["count"], 1);
        s
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_not_verify_tool_call_that_was_not_made() {
    with_server(|s| async move {
        tool_use_conversation(&s).await;
        let r = call(&s, "verify_tool_call", json!({"provider": "ANTHROPIC", "path": "/v1/messages", "toolName": "send_email"})).await;
        assert_eq!(r["satisfied"], false);
        assert_eq!(r["count"], 0);
        assert!(r.get("message").is_some());
        s
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_filter_verify_tool_call_by_arguments_regex() {
    with_server(|s| async move {
        tool_use_conversation(&s).await;
        let r = call(&s, "verify_tool_call", json!({"provider": "ANTHROPIC", "toolName": "get_weather", "argumentsRegex": "London"})).await;
        assert_eq!(r["satisfied"], false, "{r}");
        s
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_error_when_verify_tool_call_missing_tool_name() {
    with_server(|s| async move {
        assert_eq!(call(&s, "verify_tool_call", json!({"provider": "ANTHROPIC"})).await["error"], true);
        s
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_explain_agent_run() {
    with_server(|s| async move {
        tool_use_conversation(&s).await;
        let r = call(&s, "explain_agent_run", json!({"provider": "ANTHROPIC", "path": "/v1/messages"})).await;
        assert_eq!(r["messageCount"], 3, "{r}");
        assert_eq!(r["assistantTurnCount"], 1);
        assert_eq!(r["toolCallSequence"][0], "get_weather");
        assert_eq!(r["latestMessageRole"], "TOOL");
        assert_eq!(r["callGraph"]["nodes"].as_array().unwrap().len(), 4);
        assert!(r["callGraph"]["edges"].as_array().unwrap().len() >= 3);
        s
    })
    .await;
}

/// `shouldExplainAgentRunWithNoRecordedConversation`: upstream's in-JVM `HttpState` has never logged anything, so
/// its retrieve answers an empty body. A running server answers `[]`, which the tool fails to deserialize, as the
/// oracle does (scenario `w2_mcp_agent_runs`, "explain with nothing recorded"); with a request that decodes to
/// nothing the tool answers `messageCount` 0 with a message, which is what the test checks.
#[tokio::test(flavor = "multi_thread")]
async fn should_explain_agent_run_with_no_recorded_conversation() {
    with_server(|s| async move {
        assert_eq!(call(&s, "explain_agent_run", json!({"provider": "ANTHROPIC"})).await, json!({"error": true, "message": "Failed to explain agent run"}));
        common::exchange(s.port, Transport::Http, "GET", "/api/health", &[], "").await;
        let r = call(&s, "explain_agent_run", json!({"provider": "ANTHROPIC"})).await;
        assert_eq!(r["messageCount"], 0, "{r}");
        assert!(r.get("message").is_some());
        s
    })
    .await;
}

async fn isolated_conversation(s: &common::Running, agent: &str, message: &str) {
    let body = format!(r#"{{"messages": [{{"role": "user", "content": "{message}"}}]}}"#);
    common::exchange(s.port, Transport::Http, "POST", "/v1/messages", &[("x-agent-id", agent)], &body).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_scope_explain_agent_run_to_session_by_isolation_header() {
    with_server(|s| async move {
        isolated_conversation(&s, "agent-001", "Weather in Paris?").await;
        isolated_conversation(&s, "agent-002", "Weather in Tokyo?").await;
        let explain = |value: Option<&'static str>| {
            let mut args = json!({"provider": "ANTHROPIC", "path": "/v1/messages"});
            if let Some(v) = value {
                args["isolationType"] = json!("header");
                args["isolationKey"] = json!("x-agent-id");
                args["isolationValue"] = json!(v);
            }
            args
        };
        let one = call(&s, "explain_agent_run", explain(Some("agent-001"))).await;
        assert_eq!(one["messageCount"], 1);
        let labels = one["callGraph"]["nodes"].to_string();
        assert!(labels.contains("Paris") && !labels.contains("Tokyo"), "{labels}");
        let two = call(&s, "explain_agent_run", explain(Some("agent-002"))).await;
        assert_eq!(two["messageCount"], 1);
        let labels = two["callGraph"]["nodes"].to_string();
        assert!(labels.contains("Tokyo") && !labels.contains("Paris"), "{labels}");
        assert_eq!(call(&s, "explain_agent_run", explain(None)).await["messageCount"], 1);
        // No request carries agent-999: the retrieve is empty (`[]`), which fails the tool on a running server, as
        // the oracle does (checked by hand); upstream's in-JVM state answers 0 messages here.
        let none = call(&s, "explain_agent_run", explain(Some("agent-999"))).await;
        assert_eq!(none, json!({"error": true, "message": "Failed to explain agent run"}));
        s
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_auto_detect_provider_for_verify_tool_call() {
    with_server(|s| async move {
        tool_use_conversation(&s).await;
        let r = call(&s, "verify_tool_call", json!({"provider": "AUTO", "toolName": "get_weather"})).await;
        assert_eq!(r["satisfied"], true, "{r}");
        assert_eq!(r["count"], 1);
        assert_eq!(r["provider"], "ANTHROPIC");
        s
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_auto_detect_provider_for_explain_agent_run() {
    with_server(|s| async move {
        tool_use_conversation(&s).await;
        let r = call(&s, "explain_agent_run", json!({"provider": "AUTO"})).await;
        assert_eq!(r["messageCount"], 3, "{r}");
        assert_eq!(r["provider"], "ANTHROPIC");
        s
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_error_when_auto_detect_fails_with_no_recorded_requests() {
    with_server(|s| async move {
        common::exchange(s.port, Transport::Http, "GET", "/api/health", &[], "").await;
        error_containing(&call(&s, "verify_tool_call", json!({"provider": "AUTO", "toolName": "get_weather"})).await, "auto-detect");
        s
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_error_when_auto_detect_fails_for_explain_agent_run() {
    with_server(|s| async move {
        common::exchange(s.port, Transport::Http, "GET", "/api/health", &[], "").await;
        error_containing(&call(&s, "explain_agent_run", json!({"provider": "AUTO"})).await, "auto-detect");
        s
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_create_llm_completion_with_chaos_profile() {
    with_server(|s| async move {
        let r = call(&s, "mock_llm_completion", json!({"provider": "OPENAI", "path": "/v1/chat/completions", "text": "ok", "chaos": {"errorStatus": 429, "retryAfter": "30", "errorProbability": 1.0}})).await;
        assert_eq!(r["status"], "created");
        assert_eq!(r["count"], 1);
        s
    })
    .await;
}

// ------------------------------------------------------------------ load_expectations_from_file (VCR)

fn fixture(json: &str) -> std::path::PathBuf {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let file = std::env::temp_dir().join(format!("llm-fixture-{}-{n}.json", std::process::id()));
    std::fs::write(&file, json).unwrap();
    file
}

#[tokio::test(flavor = "multi_thread")]
async fn should_load_fixtures_in_strict_mode() {
    with_server(|s| async move {
        let file = fixture(r#"[{"httpRequest":{"method":"POST","path":"/v1/messages"},"httpResponse":{"statusCode":200,"body":"ok"}}]"#);
        let r = call(&s, "load_expectations_from_file", json!({"path": file.to_string_lossy(), "strict": true})).await;
        let _ = std::fs::remove_file(file);
        assert_eq!(r["status"], "loaded", "{r}");
        assert_eq!(r["strict"], true);
        assert_eq!(r["strictGuards"], 1);
        s
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_load_fixtures_with_request_body_normalization() {
    with_server(|s| async move {
        let file = fixture(
            r#"[{"httpRequest":{"method":"POST","path":"/v1/messages","body":{"type":"STRING","string":"{\"Request_ID\":\"req_123\",\"q\":\"hi\"}"}},"httpResponse":{"statusCode":200,"body":"ok"}}]"#,
        );
        let r = call(&s, "load_expectations_from_file", json!({"path": file.to_string_lossy(), "normalizeRequestBodyFields": ["request_id"]})).await;
        let _ = std::fs::remove_file(file);
        assert_eq!(r["status"], "loaded", "{r}");
        assert_eq!(r["count"], 1);
        let json = Value::Array(active(&s).await).to_string();
        assert!(!json.to_lowercase().contains("request_id"), "{json}");
        assert!(json.contains("\\\"q\\\"") || json.contains("\"q\""), "{json}");
        s
    })
    .await;
}

// ------------------------------------------------------------------ mock_adversarial_llm_response

#[tokio::test(flavor = "multi_thread")]
async fn should_mock_adversarial_llm_response() {
    with_server(|s| async move {
        let r = call(&s, "mock_adversarial_llm_response", json!({"provider": "ANTHROPIC", "path": "/v1/messages", "payload": "prompt_injection_ignore_instructions"})).await;
        assert_eq!(r["status"], "created");
        assert_eq!(r["count"], 1);
        assert!(r.get("id").is_some());
        assert_eq!(r["category"], "prompt_injection");
        s
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_error_when_adversarial_payload_missing() {
    with_server(|s| async move {
        assert_eq!(call(&s, "mock_adversarial_llm_response", json!({"provider": "ANTHROPIC", "path": "/v1/messages"})).await["error"], true);
        s
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_error_on_unknown_adversarial_payload() {
    with_server(|s| async move {
        assert_eq!(call(&s, "mock_adversarial_llm_response", json!({"provider": "OPENAI", "path": "/v1/chat/completions", "payload": "not_a_real_payload"})).await["error"], true);
        s
    })
    .await;
}

// ------------------------------------------------------------------ detect_llm_drift

#[tokio::test(flavor = "multi_thread")]
async fn should_error_when_detect_drift_missing_cassette() {
    with_server(|s| async move {
        assert_eq!(call(&s, "detect_llm_drift", json!({"provider": "ANTHROPIC"})).await["error"], true);
        s
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_error_when_detect_drift_cassette_file_missing() {
    with_server(|s| async move {
        let file = std::env::temp_dir().join(format!("missing-cassette-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&file);
        assert_eq!(call(&s, "detect_llm_drift", json!({"provider": "ANTHROPIC", "cassettePath": file.to_string_lossy()})).await["error"], true);
        s
    })
    .await;
}

// ------------------------------------------------------------------ mock_llm_failover

#[tokio::test(flavor = "multi_thread")]
async fn should_create_llm_failover_scenario() {
    with_server(|s| async move {
        let r = call(&s, "mock_llm_failover", json!({"provider": "OPENAI", "path": "/v1/chat/completions", "model": "gpt-4o", "failStatuses": [503, 503], "text": "The answer is 42.", "stopReason": "stop"})).await;
        assert_eq!(r["status"], "created");
        assert_eq!(r["count"], 2);
        assert_eq!(r["failureAttempts"], 2);
        assert_eq!(r["provider"], "OPENAI");
        assert_eq!(r["ids"].as_array().unwrap().len(), 2);
        s
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_create_llm_failover_with_mixed_statuses() {
    with_server(|s| async move {
        let r = call(&s, "mock_llm_failover", json!({"provider": "ANTHROPIC", "path": "/v1/messages", "failStatuses": [503, 429, 500], "text": "Hello"})).await;
        assert_eq!(r["status"], "created");
        assert_eq!(r["count"], 4);
        assert_eq!(r["failureAttempts"], 3);
        s
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_verify_failover_expectations_are_registered() {
    with_server(|s| async move {
        let r = call(&s, "mock_llm_failover", json!({"provider": "OPENAI", "path": "/v1/chat/completions", "failStatuses": [503], "text": "Success response"})).await;
        assert_eq!(r["status"], "created");
        let expectations = active(&s).await;
        assert_eq!(expectations.len(), 2);
        assert_eq!(expectations[0]["httpResponse"]["statusCode"], 503);
        assert_eq!(expectations[1]["httpLlmResponse"]["completion"]["text"], "Success response");
        s
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_create_llm_failover_with_tool_calls() {
    with_server(|s| async move {
        let r = call(
            &s,
            "mock_llm_failover",
            json!({"provider": "OPENAI", "path": "/v1/chat/completions", "failStatuses": [429], "text": "Let me search", "stopReason": "tool_use", "toolCalls": [{"name": "search", "arguments": "{\"query\":\"test\"}"}]}),
        )
        .await;
        assert_eq!(r["status"], "created");
        assert_eq!(r["count"], 2);
        s
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reject_failover_with_unknown_provider() {
    with_server(|s| async move {
        error_containing(&call(&s, "mock_llm_failover", json!({"provider": "INVALID", "path": "/v1/chat/completions", "failStatuses": [503], "text": "ok"})).await, "unsupported LLM provider");
        s
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reject_failover_with_missing_provider() {
    with_server(|s| async move {
        error_containing(&call(&s, "mock_llm_failover", json!({"path": "/v1/chat/completions", "failStatuses": [503]})).await, "'provider' is required");
        s
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reject_failover_with_missing_path() {
    with_server(|s| async move {
        error_containing(&call(&s, "mock_llm_failover", json!({"provider": "OPENAI", "failStatuses": [503]})).await, "'path' is required");
        s
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reject_failover_with_empty_fail_statuses() {
    with_server(|s| async move {
        error_containing(&call(&s, "mock_llm_failover", json!({"provider": "OPENAI", "path": "/v1/chat/completions", "failStatuses": []})).await, "non-empty array");
        s
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reject_failover_with_non_integer_status() {
    with_server(|s| async move {
        error_containing(&call(&s, "mock_llm_failover", json!({"provider": "OPENAI", "path": "/v1/chat/completions", "failStatuses": ["not_a_number"], "text": "ok"})).await, "must be an integer");
        s
    })
    .await;
}
