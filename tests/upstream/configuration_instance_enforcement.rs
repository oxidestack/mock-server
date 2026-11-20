//! `ConfigurationInstanceEnforcementTest` (23 `@Test`, verdict R): upstream proves that enforcement
//! sites honour a value set on a `Configuration` *instance*, because a bug class let `PUT /mockserver/configuration`
//! round-trip a property perfectly while a static-store read silently ignored it. That bug class cannot recur here:
//! `mock_server::Config` (`src/config.rs`) has no static store — `property`/`bool_property`/`int_property`/
//! `startup_property` always resolve against one instance (its own `system_properties`, `file_properties`, `env`
//! and `runtime` map), never a process-wide global. What upstream tests defensively, this crate's architecture
//! rules out structurally.
//!
//! What is left to prove is that the *underlying capability* behind each of the 23 methods is
//! genuinely reachable through a distinct `Config` instance and the embedding API — not that the instance/static
//! duality bug is absent (already true by construction). Checked against the actual implementation, not assumed:
//!
//! - **Already reachable, already proven elsewhere — cited, not duplicated here** (overlaps are noted instead of
//!   duplicating assertions):
//!   - `otelMetricsEnabled`/`otelEndpoint` (`OtelMetricsExporter.startIfEnabled`) —
//!     `src/telemetry.rs::tests::exports_metrics_as_otlp_protobuf` starts a `Server` from a `Config::for_tests()`
//!     instance with `otelMetricsEnabled`/`otelEndpoint` set and receives the OTLP export.
//!   - `otelTracesEnabled` (`GenAiSpanExporter.startIfEnabled`) —
//!     `src/telemetry.rs::tests::exports_spans_as_otlp_protobuf`, same pattern.
//!   - `llmBackendsConfig` named-backend resolution (`LlmBackendResolver.namedBackends`) —
//!     `tests/upstream/llm_drift.rs` (`setup`, `fails_closed_on_transport_exception`, the SigV4 and timeout
//!     tests): every one of them resolves a named backend from a `Config` instance's `llmBackendsConfig` file.
//!   - `llmProvider` sniffer fallback (`LlmProviderSniffer`, the "configured provider" branch) —
//!     `tests/upstream/gen_ai_spans.rs::should_emit_gen_ai_span_from_production_forward_path_for_open_ai_upstream`
//!     forwards to a plain `127.0.0.1` target (an unrecognised host) with `llmProvider=OPENAI` on the instance and
//!     gets an OpenAI-shaped GenAI span back, which only the configured-provider fallback can produce.
//!   - `fixtureBodyRedactFields` (`LlmOptimisationReportService`/agent-run diff redaction) —
//!     `tests/upstream/llm_agent_runs.rs::masks_configured_body_field_in_diff_output_when_request_pre_redacted`
//!     sets it on one server's `Config` instance and shows the named field masked in `diff_agent_runs` output.
//!
//! - **Already reachable, not yet proven via the embedding API — new tests below**: `rateLimitMaxNamedQuotas`
//!   (`RateLimitRegistry.tryAcquire`'s counter cap), unnamed LLM backend resolution from
//!   `llmProvider`/`llmBaseUrl`/`llmModel`/`llmApiKey` (`LlmBackendResolver.resolveDefault`),
//!   `llmRequestTimeoutMillis` (the same resolver, its default backend's transport timeout), and two branches of
//!   the sniffer (`LlmProviderSniffer`) that `gen_ai_spans.rs` does not exercise: matching a configured
//!   `llmBaseUrl` host (the Ollama case) and classifying nothing when no provider is configured anywhere.
//!
//! - **`llmCostBudgetUsd`** (`LlmCostBudgetMonitor`, `src/llm/budget.rs`): the three
//!   `shouldEnforce…`/`shouldNotBlock…`/`shouldFallBack…LlmCostBudget…` methods, ported below over the wire: a mock
//!   completion priced at $2 (800 000 gpt-4o input tokens) is the recorded cost, and a forward to an LLM path is the
//!   enforcement site. The oracle's behaviour is `tests/scenarios/llm_cost_budget.json`.
//!
//! - **Real gaps — the capability itself does not exist yet, so it cannot be proven "reachable"; not implemented
//!   here** (this file only ports tests, and each of these is materially larger than that):
//!   - `maxLlmConversationBodySize` (`LlmConversationMatcher.matches`'s size gate): `src/store.rs:365` hardcodes
//!     `MAX_LLM_CONVERSATION_BODY = 1_048_576` and never reads the configuration property at all — a real gap,
//!     and `MaxLlmConversationBodySizeTest` is still to be ported end to end (default/override/clamp via an oracle
//!     scenario extending `configuration_api.json`). Fixing `src/store.rs` is not this file's job, so this is
//!     reported, not fixed.
//!   - `prometheusRemoteWriteEnabled`/`prometheusRemoteWriteUrl` (`PrometheusRemoteWriteExporter.startIfEnabled`):
//!     nothing beyond the schema defaults exists in `src/`. The Prometheus remote-write exporter is an
//!     open item of the metrics work, not of this file.
//!   - `redactSecretsInLog` + `fixtureBodyRedactFields` gating the *event log* (`LogEntry.getRedactedHttpRequest`,
//!     distinct from the LLM-report redaction above): neither `src/log_entry.rs` nor `src/recorded.rs` reads
//!     either property, so a logged request/response body is never redacted regardless of configuration. A real
//!     gap, still open.
//!
//! - **Out of port scope, not a gap**: `customJsonUnitMatchersClass` (`CustomJsonUnitMatcherLoader.load`) loads a
//!   user-supplied Java class by name off the classpath via reflection. This is exactly the class of feature
//!   the project's scope excludes ("JVM-only features (classpath/jar/JDBC/URL loaders, class
//!   loaders) stay unported"). Documented as a divergence rather than tested.

use std::time::{Duration, Instant};

use serde_json::json;

use crate::common;

async fn expect_rate_limited(port: u16, path: &str, clause_name: &str) {
    let body = json!({
        "httpRequest": {"path": path},
        "httpResponse": {"statusCode": 200, "body": "ok"},
        "rateLimit": {"name": clause_name, "limit": 1, "windowMillis": 60_000},
    });
    assert_eq!(common::send(port, "PUT", "/mockserver/expectation", &body.to_string()).await.status, 201);
}

/// A name unique to this test run. Each server keeps its own rate-limit counters (`State::rate_limits`,
/// `src/rate_limit.rs`, cleared by a reset), so distinct names are not needed for isolation; they keep each clause
/// distinguishable in a failure message.
fn unique(tag: &str) -> String {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    format!("{tag}-{}-{nanos}-{n}", std::process::id())
}

/// `shouldEnforceRateLimitMaxNamedQuotasFromConfigurationInstance`: `rateLimitMaxNamedQuotas` read per request from
/// `state.config` (`src/rate_limit.rs::rejection`), proven two ways at once — the cap itself (a first clause is
/// enforced normally, a second distinct clause beyond the cap of 1 fails open rather than being created) and that
/// two servers in one process each enforce their *own* instance's cap over their own counters: a server whose
/// `rateLimitMaxNamedQuotas` is 1 fails open on its second clause while a plain-default server (10 000) does not.
#[tokio::test(flavor = "multi_thread")]
async fn rate_limit_max_named_quotas_caps_distinct_counters_per_instance() {
    let capped = common::start(&[("rateLimitMaxNamedQuotas", "1")]).await;
    let uncapped = common::start(&[]).await; // default 10 000, configuration_defaults.json

    let (a1, a2) = (unique("a1"), unique("a2"));
    expect_rate_limited(capped.port, "/a1", &a1).await;
    expect_rate_limited(capped.port, "/a2", &a2).await;

    // The first clause behaves normally: allowed once, then over its own window limit.
    assert_eq!(common::send(capped.port, "GET", "/a1", "").await.status, 200, "first hit on a named clause must be served");
    assert_eq!(common::send(capped.port, "GET", "/a1", "").await.status, 429, "second hit over the window limit must be rejected");

    // The cap of 1 distinct counter is now reached (by a1), so a brand-new clause must fail open — repeatedly —
    // rather than allocate a counter beyond the instance's own cap.
    assert_eq!(common::send(capped.port, "GET", "/a2", "").await.status, 200, "a new counter beyond the instance cap must fail open");
    assert_eq!(common::send(capped.port, "GET", "/a2", "").await.status, 200, "and must still fail open on repeat, proving no counter was allocated");

    // A second server in the same process, with its own counters and the (much higher) default cap, is unaffected
    // by the first server's cap: two of its own distinct clauses are both enforced normally.
    let (b1, b2) = (unique("b1"), unique("b2"));
    expect_rate_limited(uncapped.port, "/b1", &b1).await;
    expect_rate_limited(uncapped.port, "/b2", &b2).await;
    for path in ["/b1", "/b2"] {
        assert_eq!(common::send(uncapped.port, "GET", path, "").await.status, 200, "first hit on {path}");
        assert_eq!(common::send(uncapped.port, "GET", path, "").await.status, 429, "second hit on {path} must be rate-limited, not failed open");
    }

    capped.server.shutdown().await;
    uncapped.server.shutdown().await;
}

/// `shouldResolveLlmBackendFromConfigurationInstance`: `llmProvider`/`llmBaseUrl`/`llmModel`/`llmApiKey` set on one
/// server's `Config` instance are read by `LlmBackendResolver.resolveDefault` (`src/llm/client.rs::resolve_default`,
/// via `state.config.startup_property`) — reached here through the `detect_llm_drift` MCP tool, the only public
/// embedding-API caller of that resolver. The backend resolves to an actual live-call attempt (refused instantly
/// by an unbound loopback port, so the test stays fast and needs no network), distinguishing "a backend was
/// resolved and used" from `shouldResolveNoLlmBackendWhenNeitherInstanceNorStaticStoreConfiguresOne` below, which
/// gets the tool's explicit "no backend configured" message instead.
#[tokio::test(flavor = "multi_thread")]
async fn llm_backend_resolves_from_configuration_instance_properties() {
    let server = common::start(&[
        ("llmProvider", "ANTHROPIC"),
        ("llmBaseUrl", "http://127.0.0.1:1"), // nothing listens on port 1: an instant refusal, not a real call
        ("llmModel", "claude-instance-model"),
        ("llmApiKey", "instance-key"),
    ])
    .await;
    let cassette = temp_cassette();
    let report = server
        .server
        .call_mcp_tool("detect_llm_drift", &json!({"provider": "ANTHROPIC", "cassettePath": cassette.to_string_lossy()}))
        .await;
    let _ = std::fs::remove_file(&cassette);

    assert!(report.get("disabled").is_none(), "a backend resolved from the instance must not report 'disabled': {report}");
    assert_eq!(report["couldNotCheck"], 1, "the resolved backend's live call must have been attempted (and refused): {report}");
    server.server.shutdown().await;
}

/// `shouldResolveNoLlmBackendWhenNeitherInstanceNorStaticStoreConfiguresOne`: with no `llm*` property set anywhere
/// (and no `OPENAI_API_KEY`/`ANTHROPIC_API_KEY`/`GEMINI_API_KEY`/`OLLAMA_HOST` in `Config::for_tests()`'s empty
/// environment), `resolve_default` returns `None` and the tool reports drift detection as disabled.
#[tokio::test(flavor = "multi_thread")]
async fn no_llm_backend_resolves_without_any_configuration() {
    let server = common::start(&[]).await;
    let cassette = temp_cassette();
    let report = server.server.call_mcp_tool("detect_llm_drift", &json!({"provider": "ANTHROPIC", "cassettePath": cassette.to_string_lossy()})).await;
    let _ = std::fs::remove_file(&cassette);

    assert_eq!(report["disabled"], true, "{report}");
    server.server.shutdown().await;
}

/// `shouldApplyLlmRequestTimeoutFromConfigurationInstance`: the resolved default backend's timeout comes from the
/// instance's `llmRequestTimeoutMillis` (`resolve_default`'s `timeout_millis`), not the ~20-30 s defaults used
/// elsewhere in this file's sibling `llm_drift.rs` tests. A live call answering slower than the configured timeout
/// must fail fast; bounding the whole test at a wall-clock deadline well under the untimed default proves the
/// configured value — not a hardcoded one — gated the wait.
#[tokio::test(flavor = "multi_thread")]
async fn llm_request_timeout_millis_is_read_from_configuration_instance() {
    let live = common::start(&[]).await;
    common::expect(live.port, &json!({"httpRequest": {"path": "/v1/messages"}, "httpResponse": {"body": "{}", "delay": {"timeUnit": "SECONDS", "value": 30}}})).await;
    let server = common::start(&[
        ("llmProvider", "ANTHROPIC"),
        ("llmBaseUrl", &format!("http://127.0.0.1:{}", live.port)),
        ("llmApiKey", "instance-key"),
        ("llmRequestTimeoutMillis", "300"),
    ])
    .await;
    let cassette = temp_cassette();
    let deadline = Duration::from_secs(10); // far below the live expectation's 30 s delay
    let start = Instant::now();
    let report = tokio::time::timeout(
        deadline,
        server.server.call_mcp_tool("detect_llm_drift", &json!({"provider": "ANTHROPIC", "cassettePath": cassette.to_string_lossy()})),
    )
    .await
    .expect("detect_llm_drift must return well within the 30s live delay when llmRequestTimeoutMillis=300 is honoured");
    let _ = std::fs::remove_file(&cassette);

    assert_eq!(report["couldNotCheck"], 1, "a call over its configured timeout must be could-not-check, not a fabricated success: {report}");
    assert!(start.elapsed() < Duration::from_secs(10), "the instance's short timeout, not the untimed default, must have bounded the wait");
    live.server.shutdown().await;
    server.server.shutdown().await;
}

/// `shouldMatchConfiguredOllamaBaseUrlHostFromConfigurationInstance`: `sniff` (`src/telemetry.rs`) falls back to
/// matching the instance's `llmBaseUrl` host against the forwarded target's host when no hardcoded provider host
/// matches, classifying the exchange as Ollama. Forwarded to a real loopback listener (so the exchange actually
/// completes and a GenAI span is emitted) whose host — `127.0.0.1`, deliberately not any of `sniff`'s known
/// hostnames — matches the *host* of a `llmBaseUrl` that names a different, unreachable port: only the host is
/// compared, so this cannot be mistaken for an accidental default-URL match.
#[tokio::test(flavor = "multi_thread")]
async fn llm_provider_sniffer_matches_configured_ollama_base_url_host() {
    let upstream = common::start(&[]).await;
    let forward_server = common::start(&[("llmBaseUrl", "http://127.0.0.1:1")]).await; // 127.0.0.1: matches the forward target's host; :1: never dialled
    let capture = forward_server.server.capture_spans();
    let ollama_body = json!({"model": "llama3", "done_reason": "stop", "message": {"content": "hi"}, "prompt_eval_count": 3, "eval_count": 5});
    common::expect(upstream.port, &json!({"httpRequest": {"method": "POST", "path": "/api/chat"}, "httpResponse": {"statusCode": 200, "body": ollama_body.to_string()}})).await;
    common::expect(forward_server.port, &json!({"httpRequest": {"method": "POST", "path": "/api/chat"}, "httpForward": {"host": "127.0.0.1", "port": upstream.port}})).await;

    let response = common::send(forward_server.port, "POST", "/api/chat", r#"{"model":"llama3","messages":[{"role":"user","content":"hi"}]}"#).await;
    assert_eq!(response.status, 200, "forwarded request must succeed");

    let span = await_gen_ai_span(&capture).await;
    assert_eq!(span.string("gen_ai.system"), Some("ollama"), "the llmBaseUrl host match must classify the exchange as Ollama");
    forward_server.server.shutdown().await;
    upstream.server.shutdown().await;
}

/// `shouldNotClassifyUnknownHostWhenNoProviderConfiguredAnywhere`: with neither a known provider host, nor
/// `llmProvider`, nor a matching `llmBaseUrl` configured, `sniff` returns `None` and no GenAI span is ever built
/// for the exchange — proven by forwarding a genuinely LLM-shaped request/response to an unrecognised host and
/// confirming nothing carrying `gen_ai.system` appears in the capture.
#[tokio::test(flavor = "multi_thread")]
async fn llm_provider_sniffer_does_not_classify_unknown_host_without_any_provider_configured() {
    let upstream = common::start(&[]).await;
    let forward_server = common::start(&[]).await; // no llmProvider, no llmBaseUrl
    let capture = forward_server.server.capture_spans();
    let openai_body = json!({"id": "chatcmpl-1", "object": "chat.completion", "model": "gpt-4o", "choices": [{"index": 0, "message": {"role": "assistant", "content": "hi"}, "finish_reason": "stop"}]});
    common::expect(upstream.port, &json!({"httpRequest": {"method": "POST", "path": "/v1/chat/completions"}, "httpResponse": {"statusCode": 200, "body": openai_body.to_string()}})).await;
    common::expect(forward_server.port, &json!({"httpRequest": {"method": "POST", "path": "/v1/chat/completions"}, "httpForward": {"host": "127.0.0.1", "port": upstream.port}})).await;

    let response = common::send(forward_server.port, "POST", "/v1/chat/completions", r#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}"#).await;
    assert_eq!(response.status, 200, "forwarded request must succeed");

    // A generous but bounded wait: if a span were going to appear it would already have, since span emission
    // happens synchronously within request handling (see the sibling `gen_ai_spans.rs` tests, which poll only to
    // absorb minor scheduling jitter on the *positive* case).
    tokio::time::sleep(Duration::from_millis(500)).await;
    let gen_ai_spans: Vec<_> = capture.spans().into_iter().filter(|s| s.string("gen_ai.system").is_some()).collect();
    assert!(gen_ai_spans.is_empty(), "no provider configured anywhere must mean no GenAI span at all, got {gen_ai_spans:?}");

    forward_server.server.shutdown().await;
    upstream.server.shutdown().await;
}

async fn await_gen_ai_span(capture: &mock_server::SpanCapture) -> mock_server::Span {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let spans: Vec<mock_server::Span> = capture.spans().into_iter().filter(|s| s.string("gen_ai.system").is_some()).collect();
        if spans.len() == 1 {
            return spans.into_iter().next().unwrap();
        }
        if spans.len() > 1 || Instant::now() > deadline {
            panic!("exactly one GenAI span must be emitted, got {spans:?}");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// A one-exchange cassette (`detect_llm_drift`'s minimum viable input) so the tool progresses past cassette
/// parsing into backend resolution — its actual purpose here.
fn temp_cassette() -> std::path::PathBuf {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let file = std::env::temp_dir().join(format!("configuration-instance-enforcement-cassette-{}-{nanos}-{n}.json", std::process::id()));
    let cassette = json!([{"httpRequest": {"method": "POST", "path": "/v1/messages", "body": r#"{"messages":[{"role":"user","content":"hi"}]}"#}, "httpResponse": {"body": r#"{"content":[{"type":"text","text":"hello"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}"#}}]);
    std::fs::write(&file, cassette.to_string()).unwrap();
    file
}

// ---- Server::set_property reported as a system property ----
//
// Upstream's `ConfigurationProperties.<name>(value)` writes a system property, so `effectiveConfiguration` reports it
// with source `system-property`, while `PUT /mockserver/configuration` writes a `Configuration` instance that the
// diagnostic never reads. The oracle cannot be embedded, so this is a Rust port rather than an oracle scenario.

fn effective_row(rows: &serde_json::Value, name: &str) -> serde_json::Value {
    rows.as_array().unwrap().iter().find(|r| r["name"] == name).cloned().unwrap_or_else(|| panic!("no row {name}"))
}

#[tokio::test(flavor = "multi_thread")]
async fn set_property_is_reported_as_a_system_property() {
    let server = crate::common::start(&[]).await;
    let name = "mockserver.maxFutureTimeout";
    let before: serde_json::Value = serde_json::from_str(&crate::common::send(server.port, "GET", "/mockserver/config", "").await.body).unwrap();
    assert_eq!(effective_row(&before, name)["source"], "default");

    server.server.set_property("maxFutureTimeout", "123");
    let after: serde_json::Value = serde_json::from_str(&crate::common::send(server.port, "GET", "/mockserver/config", "").await.body).unwrap();
    let row = effective_row(&after, name);
    assert_eq!(row["value"], "123");
    assert_eq!(row["source"], "system-property");

    // A later PUT /configuration value is the instance's: the diagnostic reads the system property, not the instance.
    let put = crate::common::send(server.port, "PUT", "/mockserver/configuration", r#"{"maxFutureTimeout":456}"#).await;
    assert_eq!(put.status, 200, "{}", put.body);
    let last: serde_json::Value = serde_json::from_str(&crate::common::send(server.port, "GET", "/mockserver/config", "").await.body).unwrap();
    assert_eq!(effective_row(&last, name)["value"], "123");
    assert_eq!(effective_row(&last, name)["source"], "system-property");
    server.server.shutdown().await;
}

// ----- llmCostBudgetUsd -------------------------------------------------------------------------------

/// A server whose instance names `budget` (none when `None`), with `llmProvider=OPENAI` so a forward to an LLM path
/// on this server counts as LLM traffic, a $2 mock completion at `/v1/chat/completions` and a forward to it at
/// `/v1/proxy-llm`.
async fn budgeted(budget: Option<&str>) -> common::Running {
    let mut properties = vec![("llmProvider", "OPENAI")];
    if let Some(budget) = budget {
        properties.push(("llmCostBudgetUsd", budget));
    }
    let server = common::start(&properties).await;
    common::expect(
        server.port,
        &json!({
            "httpRequest": {"path": "/v1/chat/completions"},
            "httpLlmResponse": {"provider": "OPENAI", "model": "gpt-4o", "completion": {"text": "hi", "usage": {"inputTokens": 800_000, "outputTokens": 0}}}
        }),
    )
    .await;
    common::expect(
        server.port,
        &json!({
            "httpRequest": {"path": "/v1/proxy-llm"},
            "httpOverrideForwardedRequest": {"requestOverride": {"path": "/v1/chat/completions", "headers": {"Host": [format!("localhost:{}", server.port)]}}}
        }),
    )
    .await;
    server
}

/// `shouldEnforceLlmCostBudgetFromConfigurationInstance`: a budget of $1 on the instance, $2 recorded — the budget
/// is exceeded and the forward is answered with the blocking 429.
#[tokio::test(flavor = "multi_thread")]
async fn llm_cost_budget_from_configuration_instance_is_enforced() {
    let server = budgeted(Some("1.0")).await;
    assert_eq!(common::send(server.port, "POST", "/v1/chat/completions", "{}").await.status, 200, "a mock completion is never blocked");
    let blocked = common::send(server.port, "POST", "/v1/proxy-llm", "{}").await;
    assert_eq!(blocked.status, 429, "exceeding the instance budget must produce a blocking response: {}", blocked.body);
    assert_eq!(
        blocked.body,
        r#"{"error":{"type":"cost_budget_exceeded","message":"LLM cost budget exceeded (cumulative $2.0000 >= budget $1.0000)","cumulative_cost_usd":2.000000,"budget_usd":1.000000}}"#
    );
    server.server.shutdown().await;
}

/// `shouldNotBlockWhenUnderLlmCostBudgetFromConfigurationInstance`: a budget of $10, $2 recorded — not exceeded.
#[tokio::test(flavor = "multi_thread")]
async fn llm_cost_budget_from_configuration_instance_does_not_block_under_it() {
    let server = budgeted(Some("10.0")).await;
    assert_eq!(common::send(server.port, "POST", "/v1/chat/completions", "{}").await.status, 200);
    let forwarded = common::send(server.port, "POST", "/v1/proxy-llm", "{}").await;
    assert_eq!(forwarded.status, 200, "{}", forwarded.body);
    assert!(forwarded.body.contains("chat.completion"), "{}", forwarded.body);
    server.server.shutdown().await;
}

/// `shouldFallBackToStaticStoreForLlmCostBudgetWhenNoConfiguration`: with no budget configured anywhere the monitor
/// fails open — however much is recorded, nothing is blocked.
#[tokio::test(flavor = "multi_thread")]
async fn llm_cost_budget_unset_never_blocks() {
    let server = budgeted(None).await;
    for _ in 0..3 {
        assert_eq!(common::send(server.port, "POST", "/v1/chat/completions", "{}").await.status, 200);
        assert_eq!(common::send(server.port, "POST", "/v1/proxy-llm", "{}").await.status, 200);
    }
    server.server.shutdown().await;
}
