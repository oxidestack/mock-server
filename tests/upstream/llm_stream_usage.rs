//! `HttpActionHandlerStreamedLlmUsageTest` cases that an oracle scenario cannot replay: the missing-usage warning's
//! rate limiter needs 258 forwarded streams under a pinned clock (the other stream cases are the
//! `llm_forwarded_stream_*` scenarios).

use crate::common;

/// Upstream's `ProviderStreamFixtures.OPENAI_CHAT_WITHOUT_USAGE`, the model a placeholder.
fn openai_chat_without_usage(model: &str) -> String {
    let fixtures: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/files/llm/provider_stream_fixtures.json")).unwrap()).unwrap();
    fixtures["OPENAI_CHAT_WITHOUT_USAGE"].as_str().unwrap().replace("gpt-4o-2024-08-06", model)
}

/// A stream relayed from this server's own mock for `model`, forwarded from `/client/<model>`.
async fn expect_stream(port: u16, model: &str) {
    common::expect(port, &serde_json::json!([
        {
            "priority": 10,
            "httpRequest": {"method": "POST", "path": "/v1/chat/completions", "headers": {"x-case": [model]}},
            "httpResponse": {"statusCode": 200, "headers": {"content-type": ["text/event-stream"]}, "body": openai_chat_without_usage(model)},
        },
        {
            "httpRequest": {"method": "POST", "path": format!("/client/{model}")},
            "httpOverrideForwardedRequest": {"requestOverride": {"path": "/v1/chat/completions", "headers": {"Host": [format!("localhost:{port}")], "x-case": [model]}}},
        },
    ]))
    .await;
}

async fn forward_stream(port: u16, model: &str) {
    let response = common::send(port, "POST", &format!("/client/{model}"), r#"{"stream":true}"#).await;
    assert_eq!(response.status, 200, "the stream is relayed: {}", response.body);
}

/// The missing-usage lines logged so far, in order, as the model each names.
async fn usage_log_models(port: u16) -> Vec<String> {
    let logs = common::logs(port).await;
    let mut models = Vec::new();
    for entry in logs.split("------------------------------------") {
        // each argument is printed on lines of its own: `model \n\n  model-0\n\n , so the call`
        if let Some((_, rest)) = entry.contains(" - no token usage in the streamed ").then(|| entry.split_once("response for model")).flatten() {
            models.push(rest.split_whitespace().next().unwrap().to_string());
        }
    }
    models
}

/// The line is due once a minute per provider and model, and its keys are bounded: a 257th key clears the 256 kept.
/// The server's `nanoTime` is pinned, as upstream's `FixedTime` rule pins it, so no key's minute ends however long the
/// forwards take (under load they outlived it).
#[tokio::test(flavor = "multi_thread")]
async fn should_repeat_a_missing_usage_warning_once_its_key_is_cleared_to_bound_the_rate_limiter() {
    let properties = [("llmProvider", "OPENAI"), ("metricsEnabled", "true"), ("llmMetricsEnabled", "true")];
    let running = common::start_with(mock_server::Config::for_tests().with_fixed_nano_time(), &properties).await;
    let port = running.port;
    for model in (0..=256).map(|m| format!("model-{m}")) {
        expect_stream(port, &model).await;
    }
    for model in (0..256).map(|m| format!("model-{m}")) {
        forward_stream(port, &model).await;
    }
    // the line follows the stream's forwarded entry, written once the relay has ended
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while usage_log_models(port).await.len() < 256 && std::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(usage_log_models(port).await.len(), 256);

    // the clock does not move, so a repeat is held back while its key is still kept
    forward_stream(port, "model-0").await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(usage_log_models(port).await.len(), 256);

    // a 257th key clears the 256 kept, so the first model's warning can be given again
    forward_stream(port, "model-256").await;
    forward_stream(port, "model-0").await;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while usage_log_models(port).await.len() < 258 && std::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let models = usage_log_models(port).await;
    assert_eq!(models.len(), 258);
    assert_eq!(models[256], "model-256");
    assert_eq!(models[257], "model-0");
    running.server.shutdown().await;
}
