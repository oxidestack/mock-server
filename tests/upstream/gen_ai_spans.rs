//! `ForwardPathGenAiSpanEmissionTest` and `ServePathGenAiSpanEmissionTest`: GenAI spans read from the servers' span
//! capture, as upstream reads them from an in-memory exporter wired into the process-wide tracer.

use std::time::{Duration, Instant};

use mock_server::{Span, SpanCapture};

use crate::common;

const CHAT: &str = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"hello"}]}"#;

/// `awaitSingleGenAiSpan`: up to 5 s for exactly one span carrying `gen_ai.system` (request spans carry none).
async fn await_single_gen_ai_span(captures: &[&SpanCapture]) -> Span {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let spans: Vec<Span> = captures.iter().flat_map(|c| c.spans()).filter(|s| s.string("gen_ai.system").is_some()).collect();
        if spans.len() == 1 {
            return spans.into_iter().next().unwrap();
        }
        if spans.len() > 1 || Instant::now() > deadline {
            panic!("exactly one GenAI span must be emitted, got {spans:?}");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn should_emit_gen_ai_span_from_production_forward_path_for_open_ai_upstream() {
    let upstream = common::start(&[("llmProvider", "OPENAI")]).await;
    let forward_server = common::start(&[("llmProvider", "OPENAI")]).await;
    let captures = [upstream.server.capture_spans(), forward_server.server.capture_spans()];
    let upstream_body = r#"{"id":"chatcmpl-123","object":"chat.completion","model":"gpt-4o-2024-08-06","choices":[{"index":0,"message":{"role":"assistant","content":"Hello! How can I help?"},"finish_reason":"stop"}],"usage":{"prompt_tokens":12,"completion_tokens":8,"total_tokens":20}}"#;
    let stub = serde_json::json!({
        "httpRequest": {"method": "POST", "path": "/v1/chat/completions"},
        "httpResponse": {"statusCode": 200, "headers": {"Content-Type": ["application/json"]}, "body": upstream_body},
    });
    assert_eq!(common::send(upstream.port, "PUT", "/mockserver/expectation", &stub.to_string()).await.status, 201);
    let forward = serde_json::json!({
        "httpRequest": {"method": "POST", "path": "/v1/chat/completions"},
        "httpForward": {"host": "127.0.0.1", "port": upstream.port},
    });
    assert_eq!(common::send(forward_server.port, "PUT", "/mockserver/expectation", &forward.to_string()).await.status, 201);

    let response = common::send(forward_server.port, "POST", "/v1/chat/completions", CHAT).await;
    assert_eq!(response.status, 200, "forwarded request must succeed");

    let span = await_single_gen_ai_span(&[&captures[0], &captures[1]]).await;
    assert_eq!(span.name, "chat gpt-4o-2024-08-06");
    assert_eq!(span.string("gen_ai.system"), Some("openai"));
    assert_eq!(span.string("gen_ai.request.model"), Some("gpt-4o-2024-08-06"));
    assert_eq!(span.long("gen_ai.usage.input_tokens"), Some(12));
    assert_eq!(span.long("gen_ai.usage.output_tokens"), Some(8));
    forward_server.server.shutdown().await;
    upstream.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_emit_gen_ai_span_from_production_serve_path_for_served_completion() {
    let server = common::start(&[]).await;
    let capture = server.server.capture_spans();
    let stub = serde_json::json!({
        "httpRequest": {"method": "POST", "path": "/v1/chat/completions"},
        "httpLlmResponse": {
            "provider": "OPENAI",
            "model": "gpt-4o",
            "completion": {"text": "Hello! How can I help?", "stopReason": "stop", "usage": {"inputTokens": 12, "outputTokens": 8}},
        },
    });
    assert_eq!(common::send(server.port, "PUT", "/mockserver/expectation", &stub.to_string()).await.status, 201);

    let response = common::send(server.port, "POST", "/v1/chat/completions", CHAT).await;
    assert_eq!(response.status, 200, "served LLM request must succeed");

    let span = await_single_gen_ai_span(&[&capture]).await;
    assert_eq!(span.name, "chat gpt-4o");
    assert_eq!(span.string("gen_ai.system"), Some("openai"));
    assert_eq!(span.string("gen_ai.request.model"), Some("gpt-4o"));
    assert_eq!(span.long("gen_ai.usage.input_tokens"), Some(12));
    assert_eq!(span.long("gen_ai.usage.output_tokens"), Some(8));
    server.server.shutdown().await;
}

/// Up to 300ms (spans are recorded synchronously within request handling, well before the response returns) for
/// zero GenAI spans, i.e. the negative counterpart of `await_single_gen_ai_span`.
async fn assert_no_gen_ai_span(captures: &[&SpanCapture]) {
    tokio::time::sleep(Duration::from_millis(300)).await;
    let spans: Vec<Span> = captures.iter().flat_map(|c| c.spans()).filter(|s| s.string("gen_ai.system").is_some()).collect();
    assert!(spans.is_empty(), "no GenAI span expected, got {spans:?}");
}

/// `ForwardPathGenAiSpansTest.emitsGenAiSpanForAnthropicForwardedResponse`, ported at the production forward path
/// (the Java test calls `LlmProviderSniffer.sniff`/`GenAiSpans.recordCompletion` directly; here the only public
/// seam is the dataplane forward itself). The forward target is loopback, not `api.anthropic.com`, so — exactly as
/// the already-ported OpenAI case does — `llmProvider` selects the provider instead of host sniffing.
#[tokio::test(flavor = "multi_thread")]
async fn should_emit_gen_ai_span_from_production_forward_path_for_anthropic_upstream() {
    let upstream = common::start(&[("llmProvider", "ANTHROPIC")]).await;
    let forward_server = common::start(&[("llmProvider", "ANTHROPIC")]).await;
    let captures = [upstream.server.capture_spans(), forward_server.server.capture_spans()];
    let upstream_body = r#"{"id":"msg_123","type":"message","role":"assistant","model":"claude-3-5-sonnet-20241022","content":[{"type":"text","text":"Hello!"}],"stop_reason":"end_turn","usage":{"input_tokens":5,"output_tokens":3}}"#;
    let stub = serde_json::json!({
        "httpRequest": {"method": "POST", "path": "/v1/messages"},
        "httpResponse": {"statusCode": 200, "headers": {"Content-Type": ["application/json"]}, "body": upstream_body},
    });
    assert_eq!(common::send(upstream.port, "PUT", "/mockserver/expectation", &stub.to_string()).await.status, 201);
    let forward = serde_json::json!({
        "httpRequest": {"method": "POST", "path": "/v1/messages"},
        "httpForward": {"host": "127.0.0.1", "port": upstream.port},
    });
    assert_eq!(common::send(forward_server.port, "PUT", "/mockserver/expectation", &forward.to_string()).await.status, 201);

    let body = r#"{"model":"claude-3-5-sonnet-20241022","messages":[{"role":"user","content":"hi"}]}"#;
    let response = common::send(forward_server.port, "POST", "/v1/messages", body).await;
    assert_eq!(response.status, 200, "forwarded request must succeed");

    let span = await_single_gen_ai_span(&[&captures[0], &captures[1]]).await;
    assert_eq!(span.name, "chat claude-3-5-sonnet-20241022");
    assert_eq!(span.string("gen_ai.system"), Some("anthropic"));
    assert_eq!(span.string("gen_ai.request.model"), Some("claude-3-5-sonnet-20241022"));
    assert_eq!(span.long("gen_ai.usage.input_tokens"), Some(5));
    assert_eq!(span.long("gen_ai.usage.output_tokens"), Some(3));
    forward_server.server.shutdown().await;
    upstream.server.shutdown().await;
}

/// `ForwardPathGenAiSpansTest.noSpanEmittedForNonLlmForwardedRequest`: a forwarded path that matches none of
/// `LlmProviderSniffer`'s LLM-looking fragments, with no `llmProvider` override, emits no GenAI span.
#[tokio::test(flavor = "multi_thread")]
async fn should_emit_no_gen_ai_span_for_non_llm_forwarded_request() {
    let upstream = common::start(&[]).await;
    let forward_server = common::start(&[]).await;
    let captures = [upstream.server.capture_spans(), forward_server.server.capture_spans()];
    let stub = serde_json::json!({
        "httpRequest": {"method": "GET", "path": "/api/users"},
        "httpResponse": {"statusCode": 200, "body": "ok"},
    });
    assert_eq!(common::send(upstream.port, "PUT", "/mockserver/expectation", &stub.to_string()).await.status, 201);
    let forward = serde_json::json!({
        "httpRequest": {"method": "GET", "path": "/api/users"},
        "httpForward": {"host": "127.0.0.1", "port": upstream.port},
    });
    assert_eq!(common::send(forward_server.port, "PUT", "/mockserver/expectation", &forward.to_string()).await.status, 201);

    let response = common::send(forward_server.port, "GET", "/api/users", "").await;
    assert_eq!(response.status, 200, "forwarded request must succeed");

    assert_no_gen_ai_span(&[&captures[0], &captures[1]]).await;
    forward_server.server.shutdown().await;
    upstream.server.shutdown().await;
}

/// `ForwardPathGenAiSpansTest.noSpanEmittedWhenTracingDisabled`: recording is a safe no-op once telemetry has been
/// stopped again — mirrors `GenAiSpanExporterTest.afterStopRecordedCompletionIsANoOp`, at the production forward
/// path instead of the unit call.
#[tokio::test(flavor = "multi_thread")]
async fn should_emit_no_gen_ai_span_when_tracing_disabled() {
    let upstream = common::start(&[("llmProvider", "OPENAI")]).await;
    let forward_server = common::start(&[("llmProvider", "OPENAI")]).await;
    let captures = [upstream.server.capture_spans(), forward_server.server.capture_spans()];
    upstream.server.stop_spans();
    forward_server.server.stop_spans();
    let upstream_body = r#"{"id":"chatcmpl-123","object":"chat.completion","model":"gpt-4o-2024-08-06","choices":[{"index":0,"message":{"role":"assistant","content":"Hello! How can I help?"},"finish_reason":"stop"}],"usage":{"prompt_tokens":12,"completion_tokens":8,"total_tokens":20}}"#;
    let stub = serde_json::json!({
        "httpRequest": {"method": "POST", "path": "/v1/chat/completions"},
        "httpResponse": {"statusCode": 200, "headers": {"Content-Type": ["application/json"]}, "body": upstream_body},
    });
    assert_eq!(common::send(upstream.port, "PUT", "/mockserver/expectation", &stub.to_string()).await.status, 201);
    let forward = serde_json::json!({
        "httpRequest": {"method": "POST", "path": "/v1/chat/completions"},
        "httpForward": {"host": "127.0.0.1", "port": upstream.port},
    });
    assert_eq!(common::send(forward_server.port, "PUT", "/mockserver/expectation", &forward.to_string()).await.status, 201);

    let response = common::send(forward_server.port, "POST", "/v1/chat/completions", CHAT).await;
    assert_eq!(response.status, 200, "forwarding must still work with tracing disabled");

    assert_no_gen_ai_span(&[&captures[0], &captures[1]]).await;
    forward_server.server.shutdown().await;
    upstream.server.shutdown().await;
}

/// `ForwardPathGenAiSpansTest.fallsBackToModelFromRequestWhenResponseHasNone`.
#[tokio::test(flavor = "multi_thread")]
async fn should_fall_back_to_model_from_request_when_response_has_none() {
    let upstream = common::start(&[("llmProvider", "OPENAI")]).await;
    let forward_server = common::start(&[("llmProvider", "OPENAI")]).await;
    let captures = [upstream.server.capture_spans(), forward_server.server.capture_spans()];
    // no top-level "model" field in the response
    let upstream_body = r#"{"id":"chatcmpl-456","choices":[{"index":0,"message":{"content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":1,"total_tokens":6}}"#;
    let stub = serde_json::json!({
        "httpRequest": {"method": "POST", "path": "/v1/chat/completions"},
        "httpResponse": {"statusCode": 200, "headers": {"Content-Type": ["application/json"]}, "body": upstream_body},
    });
    assert_eq!(common::send(upstream.port, "PUT", "/mockserver/expectation", &stub.to_string()).await.status, 201);
    let forward = serde_json::json!({
        "httpRequest": {"method": "POST", "path": "/v1/chat/completions"},
        "httpForward": {"host": "127.0.0.1", "port": upstream.port},
    });
    assert_eq!(common::send(forward_server.port, "PUT", "/mockserver/expectation", &forward.to_string()).await.status, 201);

    let body = r#"{"model":"gpt-4o-mini","messages":[{"role":"user","content":"test"}]}"#;
    let response = common::send(forward_server.port, "POST", "/v1/chat/completions", body).await;
    assert_eq!(response.status, 200, "forwarded request must succeed");

    let span = await_single_gen_ai_span(&[&captures[0], &captures[1]]).await;
    assert_eq!(span.string("gen_ai.request.model"), Some("gpt-4o-mini"), "must fall back to the request body's model");
    forward_server.server.shutdown().await;
    upstream.server.shutdown().await;
}

/// `ForwardPathGenAiSpansTest.emitsGenAiSpanForAzureOpenAiForwardedResponse`. Azure OpenAI is normally recognised
/// by host suffix (`*.openai.azure.com`); the forward target here is loopback, so — as with the Anthropic and
/// OpenAI cases above — `llmProvider` selects the provider (`AZURE_OPENAI` is a valid `Provider` value, so the
/// property fallback path recognises it the same way it recognises `OPENAI`).
#[tokio::test(flavor = "multi_thread")]
async fn should_emit_gen_ai_span_from_production_forward_path_for_azure_openai_upstream() {
    let upstream = common::start(&[("llmProvider", "AZURE_OPENAI")]).await;
    let forward_server = common::start(&[("llmProvider", "AZURE_OPENAI")]).await;
    let captures = [upstream.server.capture_spans(), forward_server.server.capture_spans()];
    let upstream_body = r#"{"id":"chatcmpl-789","model":"gpt-4o","choices":[{"index":0,"message":{"content":"Hello!"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5}}"#;
    let path = "/openai/deployments/gpt-4o/chat/completions";
    let stub = serde_json::json!({
        "httpRequest": {"method": "POST", "path": path},
        "httpResponse": {"statusCode": 200, "headers": {"Content-Type": ["application/json"]}, "body": upstream_body},
    });
    assert_eq!(common::send(upstream.port, "PUT", "/mockserver/expectation", &stub.to_string()).await.status, 201);
    let forward = serde_json::json!({
        "httpRequest": {"method": "POST", "path": path},
        "httpForward": {"host": "127.0.0.1", "port": upstream.port},
    });
    assert_eq!(common::send(forward_server.port, "PUT", "/mockserver/expectation", &forward.to_string()).await.status, 201);

    let body = r#"{"messages":[{"role":"user","content":"hi"}]}"#;
    let response = common::send(forward_server.port, "POST", path, body).await;
    assert_eq!(response.status, 200, "forwarded request must succeed");

    let span = await_single_gen_ai_span(&[&captures[0], &captures[1]]).await;
    assert_eq!(span.string("gen_ai.system"), Some("az.ai.openai"));
    assert_eq!(span.string("gen_ai.request.model"), Some("gpt-4o"));
    forward_server.server.shutdown().await;
    upstream.server.shutdown().await;
}

// ---------------------------------------------------------------------------------------------------------------
// HttpActionHandlerStreamedLlmUsageTest (9.1.0): the operation each whole forwarded response is accounted as
// (`LlmProviderSniffer.accountableOperation`, `Operation.genAiOperationName`). The upstream test forwards to the
// provider's host; the target here is loopback, so `llmProvider` names the provider. Counts and models are replayed
// against the oracle in tests/scenarios/llm_forwarded_whole_usage*.json; what only a span shows is the operation.
// ---------------------------------------------------------------------------------------------------------------

/// Forwards `POST path` to a mock answering `response` (with `headers`) and returns the one GenAI span it emits.
async fn forwarded_span(provider: &str, path: &str, body: &str, response: &str, headers: &[(&str, &str)]) -> Span {
    let upstream = common::start(&[]).await;
    let forward_server = common::start(&[("llmProvider", provider)]).await;
    let captures = [upstream.server.capture_spans(), forward_server.server.capture_spans()];
    let mut response_headers = serde_json::json!({"Content-Type": ["application/json"]});
    for (name, value) in headers {
        response_headers[*name] = serde_json::json!([value]);
    }
    let stub = serde_json::json!({
        "httpRequest": {"method": "POST", "path": path},
        "httpResponse": {"statusCode": 200, "headers": response_headers, "body": response},
    });
    assert_eq!(common::send(upstream.port, "PUT", "/mockserver/expectation", &stub.to_string()).await.status, 201);
    let forward = serde_json::json!({
        "httpRequest": {"method": "POST", "path": path},
        "httpForward": {"host": "127.0.0.1", "port": upstream.port},
    });
    assert_eq!(common::send(forward_server.port, "PUT", "/mockserver/expectation", &forward.to_string()).await.status, 201);
    assert_eq!(common::send(forward_server.port, "POST", path, body).await.status, 200, "forwarded request must succeed");
    let span = await_single_gen_ai_span(&[&captures[0], &captures[1]]).await;
    forward_server.server.shutdown().await;
    upstream.server.shutdown().await;
    span
}

fn assert_operation(span: &Span, operation: &str, name: &str) {
    assert_eq!(span.string("gen_ai.operation.name"), Some(operation));
    assert_eq!(span.name, name);
}

/// `shouldCountAnOpenAiEmbeddingsResponseAsAnEmbeddingsCall`.
#[tokio::test(flavor = "multi_thread")]
async fn should_count_an_open_ai_embeddings_response_as_an_embeddings_call() {
    let span = forwarded_span(
        "OPENAI",
        "/v1/embeddings",
        r#"{"model":"text-embedding-3-small","input":"The food was delicious"}"#,
        r#"{"object":"list","data":[{"object":"embedding","embedding":[0.0023064255,-0.009327292],"index":0}],"model":"text-embedding-3-small","usage":{"prompt_tokens":8,"total_tokens":8}}"#,
        &[],
    )
    .await;
    assert_operation(&span, "embeddings", "embeddings text-embedding-3-small");
    assert_eq!(span.long("gen_ai.usage.input_tokens"), Some(8));
    assert_eq!(span.long("gen_ai.usage.output_tokens"), None);
}

/// `shouldNameABedrockEmbeddingOrRerankModelInvocationByItsOperation` (the InvokeModel cases; the Agent Runtime
/// `/rerank` is not an LLM-looking path for a configured provider, so it needs the real host).
#[tokio::test(flavor = "multi_thread")]
async fn should_name_a_bedrock_embedding_or_rerank_model_invocation_by_its_operation() {
    let span = forwarded_span("BEDROCK", "/model/amazon.titan-embed-text-v2:0/invoke", r#"{"inputText":"Hello"}"#, r#"{"embedding":[0.1,0.2],"inputTextTokenCount":2}"#, &[]).await;
    assert_operation(&span, "embeddings", "embeddings amazon.titan-embed-text-v2:0");
    assert_eq!((span.long("gen_ai.usage.input_tokens"), span.long("gen_ai.usage.output_tokens")), (Some(2), None));
    let tokens = [("X-Amzn-Bedrock-Input-Token-Count", "14"), ("X-Amzn-Bedrock-Output-Token-Count", "0")];
    let span = forwarded_span(
        "BEDROCK",
        "/model/cohere.rerank-v3-5:0/invoke",
        r#"{"query":"What is the capital?","documents":["Paris","Berlin"],"api_version":2}"#,
        r#"{"id":"5ee5c1c8-b3e0-4b1c-9b1a-1c2f3e4d5a6b","results":[{"index":0,"relevance_score":0.9}]}"#,
        &tokens,
    )
    .await;
    assert_operation(&span, "rerank", "rerank cohere.rerank-v3-5:0");
    assert_eq!((span.long("gen_ai.usage.input_tokens"), span.long("gen_ai.usage.output_tokens")), (Some(14), Some(0)));
}

/// `shouldNameAGeminiGenerateContentCallGenerateContent`.
#[tokio::test(flavor = "multi_thread")]
async fn should_name_a_gemini_generate_content_call_generate_content() {
    let span = forwarded_span(
        "GEMINI",
        "/v1/models/gemini-2.5-flash:generateContent",
        r#"{"contents":[]}"#,
        r#"{"candidates":[{"content":{"parts":[{"text":"Hello"}],"role":"model"},"finishReason":"STOP","index":0}],"usageMetadata":{"promptTokenCount":8,"candidatesTokenCount":12,"totalTokenCount":20},"modelVersion":"gemini-2.5-flash"}"#,
        &[],
    )
    .await;
    assert_operation(&span, "generate_content", "generate_content gemini-2.5-flash");
}

/// `shouldNameALegacyOpenAiCompletionTextCompletion` and `shouldNameAMistralFillInTheMiddleCompletionTextCompletion`.
#[tokio::test(flavor = "multi_thread")]
async fn should_name_a_legacy_or_fill_in_the_middle_completion_text_completion() {
    let span = forwarded_span(
        "OPENAI",
        "/v1/completions",
        r#"{"model":"gpt-3.5-turbo-instruct","prompt":"Say this is a test"}"#,
        r#"{"id":"cmpl-1","object":"text_completion","model":"gpt-3.5-turbo-instruct","choices":[{"text":"This is a test","index":0,"finish_reason":"length"}],"usage":{"prompt_tokens":5,"completion_tokens":7,"total_tokens":12}}"#,
        &[],
    )
    .await;
    assert_operation(&span, "text_completion", "text_completion gpt-3.5-turbo-instruct");
    let span = forwarded_span(
        "MISTRAL",
        "/v1/fim/completions",
        r#"{"model":"codestral-2508","prompt":"def f(","suffix":"return a + b"}"#,
        r#"{"id":"447e","object":"chat.completion","model":"codestral-2508","usage":{"prompt_tokens":8,"completion_tokens":91,"total_tokens":99},"choices":[{"index":0,"message":{"content":"a, b):","role":"assistant"},"finish_reason":"stop"}]}"#,
        &[],
    )
    .await;
    assert_operation(&span, "text_completion", "text_completion codestral-2508");
}

/// `shouldCountVoyageEmbeddingsAndRerankByTheirTotalTokens` (rerank).
#[tokio::test(flavor = "multi_thread")]
async fn should_name_a_voyage_rerank_rerank() {
    let span = forwarded_span(
        "VOYAGE",
        "/v1/rerank",
        r#"{"model":"rerank-2.5","query":"Sample query","documents":["Sample document 1","Sample document 2"]}"#,
        r#"{"object":"list","data":[{"relevance_score":0.4375,"index":0}],"model":"rerank-2.5","usage":{"total_tokens":26}}"#,
        &[],
    )
    .await;
    assert_operation(&span, "rerank", "rerank rerank-2.5");
    assert_eq!(span.long("gen_ai.usage.input_tokens"), Some(26));
}
