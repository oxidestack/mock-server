//! `CassetteReplayIntegrationTest`: cassettes loaded with the `load_expectations_from_file` MCP tool, called on the
//! server object as upstream calls its `McpToolRegistry`, then replayed to real requests.
//!
//! `RecordLlmFixturesIntegrationTest`: upstream logs a `FORWARDED_REQUEST` directly onto a mocked `HttpState`; a
//! real server has no such seam, so each port here drives an actual `httpOverrideForwardedRequest` through the
//! server to produce the same `RECORDED_EXPECTATIONS` entry, then calls `record_llm_fixtures` exactly as upstream
//! calls `McpToolRegistry.callTool`.

use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::{Value, json};

use crate::common::{self, Transport};

/// `loadCassette`: the cassette written to a temp file and loaded with strict mode off.
async fn load_cassette(server: &common::Running, cassette: &str, normalize: &[&str]) -> Value {
    let file = std::env::temp_dir().join(format!("cassette-replay-{}-{}.json", std::process::id(), NEXT.fetch_add(1, Ordering::SeqCst)));
    std::fs::write(&file, cassette).unwrap();
    let mut args = json!({"path": file.to_string_lossy(), "strict": false});
    if !normalize.is_empty() {
        args["normalizeRequestBodyFields"] = json!(normalize);
    }
    let result = server.server.call_mcp_tool("load_expectations_from_file", &args).await;
    let _ = std::fs::remove_file(&file);
    assert_eq!(result["status"], "loaded", "cassette must load: {result}");
    result
}

/// Cassette files are named per load: a clock-based name (microseconds on macOS) let the two tests, run in
/// parallel, write and remove the same file.
static NEXT: AtomicUsize = AtomicUsize::new(0);

#[tokio::test(flavor = "multi_thread")]
async fn should_serve_recorded_response_body_for_matching_live_request() {
    let server = common::start(&[]).await;
    load_cassette(&server, r#"[{"httpRequest":{"method":"POST","path":"/replay/hello"},"httpResponse":{"statusCode":200,"body":"the recorded reply"}}]"#, &[]).await;
    let response = common::send(server.port, "POST", "/replay/hello", "").await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, "the recorded reply");
    server.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_serve_recorded_body_when_volatile_field_differs_after_normalization() {
    let server = common::start(&[]).await;
    load_cassette(
        &server,
        r#"[{"httpRequest":{"method":"POST","path":"/v1/messages","body":{"type":"STRING","string":"{\"request_id\":\"req_ORIGINAL\",\"q\":\"weather\"}"}},"httpResponse":{"statusCode":200,"body":"it is sunny"}}]"#,
        &["request_id"],
    )
    .await;
    let matching = common::send(server.port, "POST", "/v1/messages", r#"{"request_id":"req_COMPLETELY_DIFFERENT","q":"weather"}"#).await;
    assert_eq!(matching.status, 200);
    assert_eq!(matching.body, "it is sunny");
    let non_matching = common::send(server.port, "POST", "/v1/messages", r#"{"request_id":"req_X","q":"stocks"}"#).await;
    assert_eq!(non_matching.status, 404, "normalisation must not collapse into matching every body");
    server.server.shutdown().await;
}

// ------------------------------------------------------------------ record_llm_fixtures (RecordLlmFixturesIntegrationTest)

/// A target expectation plus a same-server `httpOverrideForwardedRequest` that relays `proxy_path` to it: the
/// forward's `FORWARDED_REQUEST` is what `record_llm_fixtures` reads back as `RECORDED_EXPECTATIONS`, replacing
/// upstream's direct `httpState.log(new LogEntry()...)` onto a mocked `HttpState`.
async fn forward_through(server: &common::Running, proxy_path: &str, target: &Value) {
    common::expect(server.port, target).await;
    let target_path = target["httpRequest"]["path"].as_str().expect("target httpRequest.path");
    common::expect(
        server.port,
        &json!({
            "httpRequest": {"path": proxy_path},
            "httpOverrideForwardedRequest": {"requestOverride": {"path": target_path, "headers": {"Host": [format!("127.0.0.1:{}", server.port)]}}},
        }),
    )
    .await;
}

fn fixture_file(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("record-llm-fixtures-{name}-{}-{}.json", std::process::id(), NEXT.fetch_add(1, Ordering::SeqCst)))
}

/// `shouldRecordAndReplayNonStreamingTraffic`: a secret `Authorization` header must be redacted in the written
/// fixture, and the recorded traffic is written as one expectation.
#[tokio::test(flavor = "multi_thread")]
async fn should_record_and_replay_non_streaming_traffic() {
    let server = common::start(&[]).await;
    forward_through(
        &server,
        "/replay/hello",
        &json!({
            "httpRequest": {"method": "POST", "path": "/v1/chat/completions"},
            "httpResponse": {"statusCode": 200, "headers": {"Content-Type": ["application/json"]}, "body": "{\"id\":\"chatcmpl-1\",\"choices\":[{\"message\":{\"content\":\"Hello!\"}}]}"},
        }),
    )
    .await;
    common::exchange(server.port, Transport::Http, "POST", "/replay/hello", &[("Authorization", "Bearer sk-secret-key-12345"), ("Content-Type", "application/json")], "").await;

    let file = fixture_file("secrets");
    let result = server.server.call_mcp_tool("record_llm_fixtures", &json!({"path": file.to_string_lossy()})).await;
    assert_eq!(result["status"], "written", "{result}");
    assert_eq!(result["count"], 1);
    assert!(file.exists());

    let content = std::fs::read_to_string(&file).unwrap();
    let _ = std::fs::remove_file(&file);
    assert!(content.contains("***REDACTED***"), "Authorization should be redacted: {content}");
    assert!(!content.contains("sk-secret-key-12345"), "secret key must not appear: {content}");
    server.server.shutdown().await;
}

/// `shouldRecordAndReplaySseStreamingTraffic`: a secret `x-api-key` request header is redacted, and an
/// untruncated SSE capture is written back as `httpSseResponse` with its events, not a static body.
#[tokio::test(flavor = "multi_thread")]
async fn should_record_and_replay_sse_streaming_traffic() {
    let server = common::start(&[]).await;
    let sse_body = "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_01\",\"model\":\"claude-3-opus\"}}\n\n\
event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"Hello\"}}\n\n\
event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\" world!\"}}\n\n\
event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n";
    forward_through(
        &server,
        "/proxy/sse",
        &json!({
            "httpRequest": {"path": "/sse-target"},
            "httpResponse": {"statusCode": 200, "headers": {"Content-Type": ["text/event-stream"]}, "body": sse_body},
        }),
    )
    .await;
    let response = common::exchange(server.port, Transport::Http, "POST", "/proxy/sse", &[("x-api-key", "ant-api-key-secret-456"), ("Content-Type", "application/json")], "").await;
    assert_eq!(response.status, 200);

    let file = fixture_file("sse");
    let result = server.server.call_mcp_tool("record_llm_fixtures", &json!({"path": file.to_string_lossy()})).await;
    assert_eq!(result["status"], "written", "{result}");
    assert_eq!(result["count"], 1);

    let content = std::fs::read_to_string(&file).unwrap();
    let _ = std::fs::remove_file(&file);
    assert!(content.contains("***REDACTED***"), "API key should be redacted: {content}");
    assert!(!content.contains("ant-api-key-secret-456"), "secret key must not appear: {content}");
    assert!(content.contains("httpSseResponse"), "should have an SSE response action: {content}");
    assert!(content.contains("message_start") && content.contains("content_block_delta") && content.contains("message_stop"), "should keep the SSE events: {content}");
    server.server.shutdown().await;
}

/// `shouldFilterByRequestPath`: `requestPath` selects only the matching recorded traffic.
#[tokio::test(flavor = "multi_thread")]
async fn should_filter_by_request_path() {
    let server = common::start(&[]).await;
    forward_through(&server, "/proxy/messages", &json!({"httpRequest": {"method": "POST", "path": "/v1/messages"}, "httpResponse": {"statusCode": 200, "body": "{\"reply\":\"hi\"}"}})).await;
    forward_through(&server, "/proxy/models", &json!({"httpRequest": {"method": "GET", "path": "/v1/models"}, "httpResponse": {"statusCode": 200, "body": "{\"models\":[]}"}})).await;
    common::exchange(server.port, Transport::Http, "POST", "/proxy/messages", &[], "").await;
    common::exchange(server.port, Transport::Http, "GET", "/proxy/models", &[], "").await;

    let file = fixture_file("filtered");
    let result = server.server.call_mcp_tool("record_llm_fixtures", &json!({"path": file.to_string_lossy(), "requestPath": "/proxy/messages"})).await;
    assert_eq!(result["status"], "written", "{result}");
    assert_eq!(result["count"], 1, "{result}");
    let _ = std::fs::remove_file(&file);
    server.server.shutdown().await;
}

/// `shouldHandleTruncatedSseGracefully`: a capture that hits `maxStreamingCaptureBytes` is written as a static
/// `httpResponse` (not `httpSseResponse`) carrying a truncation warning, rather than a malformed SSE replay.
/// Upstream simulates truncation by logging a response already flagged `x-mockserver-stream-truncated`; there is
/// no such seam over the wire, so this pins `maxStreamingCaptureBytes` to the exact body length, which the
/// `Capture`'s `>=` check flags truncated once filled — exercising the same fallback path with the full text intact.
#[tokio::test(flavor = "multi_thread")]
async fn should_handle_truncated_sse_gracefully() {
    let body = "event: partial\ndata: {\"incomplete\":";
    let server = common::start(&[("maxStreamingCaptureBytes", &body.len().to_string())]).await;
    forward_through(&server, "/proxy/messages", &json!({"httpRequest": {"path": "/sse-target"}, "httpResponse": {"statusCode": 200, "headers": {"Content-Type": ["text/event-stream"]}, "body": body}})).await;
    let response = common::exchange(server.port, Transport::Http, "POST", "/proxy/messages", &[], "").await;
    assert_eq!(response.status, 200);

    let file = fixture_file("truncated");
    let result = server.server.call_mcp_tool("record_llm_fixtures", &json!({"path": file.to_string_lossy()})).await;
    assert_eq!(result["status"], "written", "{result}");
    assert_eq!(result["count"], 1);

    let content = std::fs::read_to_string(&file).unwrap();
    let _ = std::fs::remove_file(&file);
    assert!(content.contains("truncated"), "should contain a truncation warning: {content}");
    assert!(content.contains("httpResponse") && !content.contains("httpSseResponse"), "should be a static response: {content}");
    server.server.shutdown().await;
}

/// `shouldRedactSensitiveQueryStringCredentialsInRecordedFixture`: Gemini's `?key=` and an AWS SigV4
/// `X-Amz-Signature` are masked by default, while a non-sensitive `alt=sse` parameter survives.
#[tokio::test(flavor = "multi_thread")]
async fn should_redact_sensitive_query_string_credentials_in_recorded_fixture() {
    let server = common::start(&[]).await;
    forward_through(
        &server,
        "/proxy/gemini",
        &json!({
            "httpRequest": {"method": "POST", "path": "/v1beta/models/gemini-pro:streamGenerateContent"},
            "httpResponse": {"statusCode": 200, "headers": {"Content-Type": ["application/json"]}, "body": "{\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"hi\"}]}}]}"},
        }),
    )
    .await;
    common::exchange(server.port, Transport::Http, "POST", "/proxy/gemini?key=AIza-SUPER-SECRET&X-Amz-Signature=deadbeefSECRET&alt=sse", &[("Content-Type", "application/json")], "").await;

    let file = fixture_file("query-creds");
    let result = server.server.call_mcp_tool("record_llm_fixtures", &json!({"path": file.to_string_lossy()})).await;
    assert_eq!(result["status"], "written", "{result}");
    assert_eq!(result["count"], 1);

    let content = std::fs::read_to_string(&file).unwrap();
    let _ = std::fs::remove_file(&file);
    assert!(content.contains("***REDACTED***"), "sensitive query params should be redacted: {content}");
    assert!(!content.contains("AIza-SUPER-SECRET"), "Gemini API key must not appear: {content}");
    assert!(!content.contains("deadbeefSECRET"), "SigV4 signature must not appear: {content}");
    assert!(content.contains("alt") && content.contains("sse"), "non-sensitive query param should be preserved: {content}");
    server.server.shutdown().await;
}

/// `shouldRedactConfiguredFieldInsideRecordedSseDataPayload`: a configured `redactBodyFields` entry is masked
/// inside each SSE `data:` JSON payload, preserving the rest of the structure (the `[DONE]` marker included).
/// The SSE-body string path only fires for a static body, so this reuses the truncated-capture technique above.
#[tokio::test(flavor = "multi_thread")]
async fn should_redact_configured_field_inside_recorded_sse_data_payload() {
    let sse_body = "event: message\ndata: {\"api_key\":\"sk-LEAK-1234\",\"text\":\"hi\"}\n\n\
event: message\ndata: {\"api_key\":\"sk-LEAK-1234\",\"text\":\" there\"}\n\n\
data: [DONE]\n\n";
    let server = common::start(&[("maxStreamingCaptureBytes", &sse_body.len().to_string())]).await;
    forward_through(&server, "/proxy/messages", &json!({"httpRequest": {"path": "/sse-target"}, "httpResponse": {"statusCode": 200, "headers": {"Content-Type": ["text/event-stream"]}, "body": sse_body}}))
        .await;
    let response = common::exchange(server.port, Transport::Http, "POST", "/proxy/messages", &[], "").await;
    assert_eq!(response.status, 200);

    let file = fixture_file("sse-field");
    let result = server.server.call_mcp_tool("record_llm_fixtures", &json!({"path": file.to_string_lossy(), "redactBodyFields": ["api_key"]})).await;
    assert_eq!(result["status"], "written", "{result}");
    assert_eq!(result["count"], 1);

    let content = std::fs::read_to_string(&file).unwrap();
    let _ = std::fs::remove_file(&file);
    assert!(content.contains("***REDACTED***"), "api_key value should be redacted: {content}");
    assert!(!content.contains("sk-LEAK-1234"), "leaked api_key must not appear: {content}");
    assert!(content.contains("hi"), "non-sensitive text content should be preserved: {content}");
    assert!(content.contains("[DONE]"), "DONE marker should be preserved: {content}");
    server.server.shutdown().await;
}
