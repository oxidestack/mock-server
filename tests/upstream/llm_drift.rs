//! `DriftDetectorTest` and `StructuralShapeDiffTest` (mockserver-core, in-JVM unit tests): the same recorded
//! exchanges replayed by `detect_llm_drift` against a live provider, here a second in-process server named as the
//! backend in `llmBackendsConfig`, answering with the "live" body. `StructuralShapeDiffTest.nullNodesTreatedAsEmptyShape`
//! diffs two absent trees, which the tool never does (a non-JSON body is could-not-check, checked below).

use serde_json::{Value, json};

use crate::common;

const RECORDED_REQUEST: &str = r#"{"messages":[{"role":"user","content":"hi"}]}"#;
const RECORDED_RESPONSE: &str = r#"{"content":[{"type":"text","text":"hello"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}"#;

fn temp_file(name: &str, content: &str) -> std::path::PathBuf {
    // Unique across the tests running in parallel (the clock alone can repeat).
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let file = std::env::temp_dir().join(format!("{name}-{}-{nanos}-{n}.json", std::process::id()));
    std::fs::write(&file, content).unwrap();
    file
}

/// The live provider answering `/v1/messages` with `status` and `body`, and a server whose named backend `live`
/// points at it.
async fn setup(status: u16, body: &str) -> (common::Running, common::Running, std::path::PathBuf) {
    let live = common::start(&[]).await;
    common::expect(live.port, &json!({"httpRequest": {"method": "POST", "path": "/v1/messages"}, "httpResponse": {"statusCode": status, "body": body}})).await;
    let config = temp_file("llmBackends", &json!([{"name": "live", "provider": "anthropic", "baseUrl": format!("http://127.0.0.1:{}", live.port), "apiKey": "ak-test"}]).to_string());
    let server = common::start(&[("llmBackendsConfig", &config.to_string_lossy())]).await;
    (live, server, config)
}

async fn detect(server: &common::Running, provider: &str, recorded_request: &str, recorded_response: &str) -> Value {
    let cassette = temp_file("cassette", &json!([{"httpRequest": {"method": "POST", "path": "/v1/messages", "body": recorded_request}, "httpResponse": {"body": recorded_response}}]).to_string());
    let result = server.server.call_mcp_tool("detect_llm_drift", &json!({"provider": provider, "cassettePath": cassette.to_string_lossy(), "backendName": "live"})).await;
    let _ = std::fs::remove_file(cassette);
    result
}

async fn finish(live: common::Running, server: common::Running, config: std::path::PathBuf) {
    live.server.shutdown().await;
    server.server.shutdown().await;
    let _ = std::fs::remove_file(config);
}

#[tokio::test(flavor = "multi_thread")]
async fn reports_no_drift_when_live_shape_matches_recorded() {
    let (live, server, config) = setup(200, r#"{"content":[{"type":"text","text":"different words"}],"stop_reason":"end_turn","usage":{"input_tokens":9,"output_tokens":9}}"#).await;
    let report = detect(&server, "ANTHROPIC", RECORDED_REQUEST, RECORDED_RESPONSE).await;
    assert_eq!(report["drifted"], 0, "{report}");
    assert_eq!(report["checked"], 1);
    assert_eq!(report["details"][0]["status"], "NO_DRIFT");
    finish(live, server, config).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn reports_drift_when_live_has_new_field() {
    let (live, server, config) =
        setup(200, r#"{"content":[{"type":"text","text":"hi"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1},"cache_creation_input_tokens":5}"#).await;
    let report = detect(&server, "ANTHROPIC", RECORDED_REQUEST, RECORDED_RESPONSE).await;
    assert_eq!(report["drifted"], 1, "{report}");
    assert!(report["details"][0]["addedPaths"].as_array().unwrap().contains(&json!("$.cache_creation_input_tokens")));
    finish(live, server, config).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn fails_closed_on_transport_exception() {
    // A backend on a port nothing listens on (port 1), rather than a stopped server whose port a parallel test
    // could take over.
    let config = temp_file("llmBackends", &json!([{"name": "live", "provider": "anthropic", "baseUrl": "http://127.0.0.1:1", "apiKey": "ak-test"}]).to_string());
    let server = common::start(&[("llmBackendsConfig", &config.to_string_lossy())]).await;
    let report = detect(&server, "ANTHROPIC", RECORDED_REQUEST, RECORDED_RESPONSE).await;
    assert_eq!(report["couldNotCheck"], 1, "{report}");
    assert_eq!(report["drifted"], 0);
    server.server.shutdown().await;
    let _ = std::fs::remove_file(config);
}

#[tokio::test(flavor = "multi_thread")]
async fn fails_closed_on_non2xx() {
    let (live, server, config) = setup(500, "err").await;
    let report = detect(&server, "ANTHROPIC", RECORDED_REQUEST, RECORDED_RESPONSE).await;
    assert_eq!(report["couldNotCheck"], 1, "{report}");
    assert_eq!(report["details"][0]["note"], "live provider call returned 500");
    finish(live, server, config).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn could_not_check_when_no_client_for_provider() {
    // Cohere has a codec but no runtime client. Since 9.2.0 (#70) the tool refuses a cassette whose provider is not
    // the backend's, so the backend is a Cohere one here.
    let live = common::start(&[]).await;
    let config = temp_file("llmBackends", &json!([{"name": "live", "provider": "cohere", "baseUrl": format!("http://127.0.0.1:{}", live.port), "apiKey": "ak-test"}]).to_string());
    let server = common::start(&[("llmBackendsConfig", &config.to_string_lossy())]).await;
    let report = detect(&server, "COHERE", RECORDED_REQUEST, RECORDED_RESPONSE).await;
    assert_eq!(report["couldNotCheck"], 1, "{report}");
    finish(live, server, config).await;
}

/// `StructuralShapeDiff.diff(recorded, live)` as the drift report shows it for one exchange.
async fn shape_diff(recorded: &str, live_body: &str) -> Value {
    let (live, server, config) = setup(200, live_body).await;
    let report = detect(&server, "ANTHROPIC", RECORDED_REQUEST, recorded).await;
    finish(live, server, config).await;
    report["details"][0].clone()
}

fn paths(detail: &Value, key: &str) -> Vec<String> {
    detail.get(key).and_then(Value::as_array).map(|a| a.iter().map(|p| p.as_str().unwrap().to_string()).collect()).unwrap_or_default()
}

#[tokio::test(flavor = "multi_thread")]
async fn identical_shapes_have_no_drift() {
    assert_eq!(shape_diff(r#"{"a":1,"b":"x"}"#, r#"{"a":99,"b":"completely different"}"#).await["status"], "NO_DRIFT");
}

#[tokio::test(flavor = "multi_thread")]
async fn detects_added_field() {
    let d = shape_diff(r#"{"a":1}"#, r#"{"a":1,"b":2}"#).await;
    assert_eq!(d["status"], "DRIFT", "{d}");
    assert!(paths(&d, "addedPaths").contains(&"$.b".to_string()));
    assert!(paths(&d, "removedPaths").is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn detects_removed_field() {
    assert!(paths(&shape_diff(r#"{"a":1,"b":2}"#, r#"{"a":1}"#).await, "removedPaths").contains(&"$.b".to_string()));
}

#[tokio::test(flavor = "multi_thread")]
async fn detects_type_change() {
    assert_eq!(paths(&shape_diff(r#"{"a":1}"#, r#"{"a":"now a string"}"#).await, "typeChangedPaths"), vec!["$.a".to_string()]);
}

#[tokio::test(flavor = "multi_thread")]
async fn walks_nested_objects_and_arrays() {
    let d = shape_diff(r#"{"content":[{"type":"text","text":"hi"}]}"#, r#"{"content":[{"type":"text","text":"hi","annotations":[]}]}"#).await;
    assert!(paths(&d, "addedPaths").contains(&"$.content[].annotations".to_string()), "{d}");
}

#[tokio::test(flavor = "multi_thread")]
async fn null_nodes_treated_as_empty_shape() {
    // Bodies that are not JSON never reach the diff: the exchange could not be checked, and nothing drifted.
    let d = shape_diff("not json", "not json either").await;
    assert_eq!(d["status"], "COULD_NOT_CHECK", "{d}");
}

#[tokio::test(flavor = "multi_thread")]
async fn handles_top_level_array_root() {
    assert_eq!(shape_diff("[1,2]", "[1,2,3]").await["status"], "NO_DRIFT");
}

#[tokio::test(flavor = "multi_thread")]
async fn detects_type_change_in_array_first_element() {
    assert!(paths(&shape_diff("[1]", r#"["text"]"#).await, "typeChangedPaths").contains(&"$[]".to_string()));
}

#[tokio::test(flavor = "multi_thread")]
async fn primitive_roots_of_same_type_have_no_drift() {
    assert_eq!(shape_diff(r#""hello""#, r#""world""#).await["status"], "NO_DRIFT");
}

#[tokio::test(flavor = "multi_thread")]
async fn primitive_root_type_change_is_drift() {
    assert!(paths(&shape_diff(r#""hello""#, "42").await, "typeChangedPaths").contains(&"$".to_string()));
}

// ------------------------------------------------------------------ review checks (not upstream tests)

/// A test configuration (`Config::for_tests`) never lets a backend without `baseUrl` fall back to the provider's
/// public URL: the exchange is could-not-check and nothing is sent.
#[tokio::test(flavor = "multi_thread")]
async fn no_default_provider_url_is_used_with_a_test_configuration() {
    let server = common::start(&[("llmProvider", "OPENAI"), ("llmApiKey", "sk-test")]).await;
    let cassette = temp_file("cassette", &json!([{"httpRequest": {"method": "POST", "path": "/v1/chat/completions", "body": r#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}"#}, "httpResponse": {"body": "{}"}}]).to_string());
    let report = server.server.call_mcp_tool("detect_llm_drift", &json!({"provider": "OPENAI", "cassettePath": cassette.to_string_lossy()})).await;
    let _ = std::fs::remove_file(cassette);
    assert_eq!(report["couldNotCheck"], 1, "{report}");
    assert!(report["details"][0]["note"].as_str().unwrap().starts_with("no baseUrl configured for the OPENAI backend"), "{report}");
    server.server.shutdown().await;
}

async fn detect_cassette(server: &common::Running, cassette: &str) -> Value {
    let file = temp_file("cassette", cassette);
    let result = server.server.call_mcp_tool("detect_llm_drift", &json!({"provider": "ANTHROPIC", "cassettePath": file.to_string_lossy(), "backendName": "live"})).await;
    let _ = std::fs::remove_file(file);
    result
}

/// `ExpectationSerializer.deserializeArray(json, false)`: an empty array or an invalid expectation fails the tool;
/// an OpenAPI expectation expands into expectations whose requests are OpenAPI definitions, so nothing is checked.
#[tokio::test(flavor = "multi_thread")]
async fn cassettes_are_read_as_expectation_arrays() {
    let (live, server, config) = setup(200, "{}").await;
    assert_eq!(detect_cassette(&server, "[]").await, json!({"error": true, "message": "Failed to detect LLM drift"}));
    assert_eq!(detect_cassette(&server, r#"[{"httpResponse":{"statusCode":"x"}}]"#).await["message"], "Failed to detect LLM drift");
    let spec = json!({"openapi": "3.0.0", "info": {"title": "t", "version": "1"}, "paths": {"/a": {"get": {"responses": {"200": {"description": "ok"}}}}}});
    let report = detect_cassette(&server, &json!({"specUrlOrPayload": spec.to_string()}).to_string()).await;
    assert_eq!(report["status"], "no_exchanges", "{report}");
    finish(live, server, config).await;
}

/// `NettyHttpClient.sendRequest(request, timeout, unit)`: a live call slower than the backend's timeout.
#[tokio::test(flavor = "multi_thread")]
async fn a_slow_live_call_times_out_with_upstreams_text() {
    let live = common::start(&[]).await;
    common::expect(live.port, &json!({"httpRequest": {"path": "/v1/messages"}, "httpResponse": {"body": "{}", "delay": {"timeUnit": "SECONDS", "value": 5}}})).await;
    let config = temp_file("llmBackends", &json!([{"name": "live", "provider": "ANTHROPIC", "baseUrl": format!("http://127.0.0.1:{}", live.port), "timeoutMillis": 200}]).to_string());
    let server = common::start(&[("llmBackendsConfig", &config.to_string_lossy())]).await;
    let report = detect(&server, "ANTHROPIC", RECORDED_REQUEST, RECORDED_RESPONSE).await;
    assert_eq!(
        report["details"][0]["note"],
        "Response was not received from MockServer after 20000 milliseconds, to wait longer please use \"mockserver.maxSocketTimeout\" system property or ConfigurationProperties.maxSocketTimeout(long milliseconds)",
        "{report}"
    );
    finish(live, server, config).await;
}

/// `BedrockLlmClient`: an `accessKeyId:secretAccessKey` API key signs the live request with SigV4.
#[tokio::test(flavor = "multi_thread")]
async fn bedrock_live_calls_are_sigv4_signed() {
    let live = common::start(&[]).await;
    common::expect(live.port, &json!({"httpRequest": {"method": "POST", "path": "/model/.*/invoke"}, "httpResponse": {"body": RECORDED_RESPONSE}})).await;
    let config = temp_file("llmBackends", &json!([{"name": "live", "provider": "BEDROCK", "baseUrl": format!("http://127.0.0.1:{}", live.port), "apiKey": "AKID:SECRET:TOKEN"}]).to_string());
    let server = common::start(&[("llmBackendsConfig", &config.to_string_lossy())]).await;
    let report = detect(&server, "BEDROCK", RECORDED_REQUEST, RECORDED_RESPONSE).await;
    assert_eq!(report["details"][0]["status"], "NO_DRIFT", "{report}");
    let received = common::send(live.port, "PUT", "/mockserver/retrieve?type=REQUESTS&format=JSON", "").await.body;
    for expected in ["AWS4-HMAC-SHA256 Credential=AKID/", "/us-east-1/bedrock/aws4_request", "SignedHeaders=content-type;host;x-amz-date;x-amz-security-token", "X-Amz-Security-Token", "TOKEN"] {
        assert!(received.contains(expected), "{expected} in {received}");
    }
    finish(live, server, config).await;
}
