//! OpenTelemetry tracing: `GenAiSpans` (a CLIENT span per LLM completion served or forwarded), `RequestSpans` (a
//! SERVER span per served request), the span processor they report to (`GenAiSpanExporter`: OTLP/HTTP protobuf
//! batches under `otelTracesEnabled`, or an in-process capture for embedders), the forward-path provider sniffing
//! and completion parsing they need (`LlmProviderSniffer`, `LlmClient.parseCompletionResponse`), and W3C trace
//! context (`W3CTraceContext`, `TraceContextHandler`).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use serde_json::Value;

use crate::metrics::{Attributes, OtelValue};
use crate::state::State;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Server,
    Client,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Attribute {
    Str(String),
    Long(i64),
    StrArray(Vec<String>),
}

/// A finished span, as a span processor receives it (`SpanData`).
#[derive(Debug, Clone)]
pub struct Span {
    pub name: String,
    pub kind: Kind,
    /// 32 lowercase hex digits.
    pub trace_id: String,
    /// 16 lowercase hex digits.
    pub span_id: String,
    /// The remote parent's span id, when the span continues an inbound trace.
    pub parent_span_id: Option<String>,
    pub trace_state: Option<String>,
    pub sampled: bool,
    pub attributes: Vec<(String, Attribute)>,
    pub start_nanos: u64,
    pub end_nanos: u64,
}

impl Span {
    pub fn attribute(&self, key: &str) -> Option<&Attribute> {
        self.attributes.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    pub fn string(&self, key: &str) -> Option<&str> {
        match self.attribute(key) {
            Some(Attribute::Str(s)) => Some(s),
            _ => None,
        }
    }

    pub fn long(&self, key: &str) -> Option<i64> {
        match self.attribute(key) {
            Some(Attribute::Long(n)) => Some(*n),
            _ => None,
        }
    }
}

/// The spans an embedder captured (`InMemorySpanExporter` behind a `SimpleSpanProcessor`).
#[derive(Clone, Default)]
pub struct SpanCapture(Arc<Mutex<Vec<Span>>>);

impl SpanCapture {
    /// `getFinishedSpanItems`.
    pub fn spans(&self) -> Vec<Span> {
        self.0.lock().clone()
    }
}

enum Processor {
    Capture(SpanCapture),
    Otlp(tokio::sync::mpsc::UnboundedSender<Span>),
}

/// The installed tracer: none (spans are not built), a capture, or the OTLP batch exporter.
#[derive(Default)]
pub struct Telemetry {
    processor: crate::watched::WatchedRwLock<Option<Processor>>,
}

impl Telemetry {
    /// `GenAiSpans.isEnabled` / `RequestSpans.isEnabled`.
    pub fn enabled(&self) -> bool {
        // asked by every request: read without the lock
        !self.processor.is_empty()
    }

    /// `GenAiSpanExporter.startWithProcessor(SimpleSpanProcessor.create(InMemorySpanExporter))`.
    pub fn capture(&self) -> SpanCapture {
        let capture = SpanCapture::default();
        *self.processor.write() = Some(Processor::Capture(capture.clone()));
        capture
    }

    /// `GenAiSpanExporter.stop`.
    pub fn stop(&self) {
        *self.processor.write() = None;
    }

    fn end(&self, span: Span) {
        match &*self.processor.read() {
            Some(Processor::Capture(capture)) => capture.0.lock().push(span),
            Some(Processor::Otlp(tx)) => {
                let _ = tx.send(span);
            }
            None => {}
        }
    }
}

/// `GenAiSpanExporter.startIfEnabled`: with `otelTracesEnabled`, spans are batched (`BatchSpanProcessor`: every 5 s,
/// at most 512 a request) and posted as OTLP protobuf to `otelEndpoint` + `/v1/traces`, else to the exporter's
/// default `http://localhost:4318/v1/traces`.
pub fn start(state: &Arc<State>) {
    if !state.config.bool_property("otelTracesEnabled", false) {
        return;
    }
    let endpoint = traces_endpoint(Some(&otel_endpoint(&state.config))).unwrap_or_else(|| "http://localhost:4318/v1/traces".into());
    let Some(target) = Target::parse(&endpoint) else {
        crate::log::warn(state, &format!("failed to start OpenTelemetry GenAI span export (invalid endpoint {endpoint}); continuing without it"));
        return;
    };
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Span>();
    *state.telemetry.processor.write() = Some(Processor::Otlp(tx));
    let config = state.config.clone();
    tokio::spawn(async move {
        let mut batch = Vec::new();
        let mut tick = tokio::time::interval(Duration::from_secs(5));
        tick.tick().await;
        loop {
            let open = tokio::select! {
                span = rx.recv() => match span {
                    Some(span) => {
                        batch.push(span);
                        batch.len() < 512
                    }
                    None => false,
                },
                _ = tick.tick() => false,
            };
            if !open && !batch.is_empty() {
                // Export failures are dropped, as `OtlpHttpSpanExporter` drops a failed batch.
                target.post(&config, otlp::encode(&std::mem::take(&mut batch))).await;
            }
            if rx.is_closed() && rx.is_empty() {
                return;
            }
        }
    });
}

/// `OtelMetricsExporter.startIfEnabled`: with `otelMetricsEnabled`, a `PeriodicMetricReader` collects the
/// instruments of [`crate::metrics::otel_points`] every `otelMetricsExportIntervalSeconds` and posts them as OTLP
/// protobuf to `otelEndpoint` + `/v1/metrics`, else to the exporter's default `http://localhost:4318/v1/metrics`.
/// `otelMetricsTemporality` `delta` (trimmed, any case) makes the counters delta; anything else keeps cumulative.
pub fn start_metrics(state: &Arc<State>) {
    if !state.config.bool_property("otelMetricsEnabled", false) {
        return;
    }
    let endpoint = metrics_endpoint(Some(&otel_endpoint(&state.config))).unwrap_or_else(|| "http://localhost:4318/v1/metrics".into());
    let Some(target) = Target::parse(&endpoint) else {
        crate::log::warn(state, &format!("failed to start OpenTelemetry metrics export (invalid endpoint {endpoint}); continuing without it"));
        return;
    };
    let delta = is_delta_temporality(state.config.property("otelMetricsTemporality").as_deref());
    let interval = Duration::from_secs(state.config.int_property("otelMetricsExportIntervalSeconds", 60).max(1) as u64);
    crate::log::info(
        state,
        &format!("OpenTelemetry metrics export enabled (endpoint {endpoint}, interval {}s, temporality {})", interval.as_secs(), if delta { "delta" } else { "cumulative" }),
    );
    let weak = Arc::downgrade(state);
    let metrics = state.config.metrics.clone();
    metrics.otel_histograms_registered(true);
    tokio::spawn(async move {
        let start = now_nanos();
        // delta temporality: each counter series' last value and when it was read
        let mut previous: HashMap<(String, Attributes), (OtelValue, u64)> = HashMap::new();
        let mut tick = tokio::time::interval(interval);
        tick.tick().await;
        loop {
            tick.tick().await;
            let Some(state) = weak.upgrade().filter(|s| s.is_running()) else {
                // `OtelMetricsExporter.stop`: the histograms record no more.
                metrics.otel_histograms_registered(false);
                return;
            };
            let now = now_nanos();
            let points = crate::metrics::otel_points(&state);
            let histograms = state.config.metrics.collect_otel_histograms(delta, now);
            let config = state.config.clone();
            drop(state);
            let mut exported = Vec::with_capacity(points.len());
            for mut p in points {
                let mut from = start;
                if delta && p.monotonic {
                    let key = (p.name.clone(), p.attributes.clone());
                    let zero = if matches!(p.value, OtelValue::Double(_)) { OtelValue::Double(0.0) } else { OtelValue::Long(0) };
                    let (last, since) = previous.insert(key, (p.value, now)).unwrap_or((zero, start));
                    from = since;
                    match (p.value, last) {
                        (OtelValue::Long(cur), OtelValue::Long(old)) => p.value = OtelValue::Long(cur - old),
                        (OtelValue::Double(cur), OtelValue::Double(old)) => p.value = OtelValue::Double(cur - old),
                        (OtelValue::Double(_), OtelValue::Long(_)) | (OtelValue::Long(_), OtelValue::Double(_)) => {}
                    }
                }
                exported.push((p, from));
            }
            // A failed export is dropped, as `OtlpHttpMetricExporter` drops it.
            target.post(&config, otlp::encode_metrics(&exported, &histograms, now, delta)).await;
        }
    });
}

/// `ConfigurationProperties.otelEndpoint`: the MockServer property when set, else the OpenTelemetry-standard
/// `OTEL_EXPORTER_OTLP_ENDPOINT` environment variable ([`otel_endpoint_fallback_default`]).
pub fn otel_endpoint(config: &crate::Config) -> String {
    resolve_otel_endpoint(config.property("otelEndpoint").as_deref(), std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok().as_deref())
}

fn resolve_otel_endpoint(specific: Option<&str>, standard_env: Option<&str>) -> String {
    match specific.filter(|v| !v.is_empty()) {
        Some(v) => v.to_string(),
        None => otel_endpoint_fallback_default(standard_env),
    }
}

/// `ConfigurationProperties.otelEndpointFallbackDefault`: the standard variable's value unless blank, else empty.
pub fn otel_endpoint_fallback_default(standard_env: Option<&str>) -> String {
    standard_env.filter(|v| !v.trim().is_empty()).unwrap_or_default().to_string()
}

/// `OtelMetricsExporter.isDeltaTemporality`: only `delta` (trimmed, any case) opts in; anything else, blank or unset
/// keeps cumulative.
pub fn is_delta_temporality(value: Option<&str>) -> bool {
    value.is_some_and(|t| t.trim().to_lowercase() == "delta")
}

/// `OtelEndpoints.traces`: the base with any trailing slashes and signal path removed, plus `/v1/traces`.
pub fn traces_endpoint(base: Option<&str>) -> Option<String> {
    signal_endpoint(base, "/v1/traces")
}

/// `OtelEndpoints.metrics`: the same with `/v1/metrics`.
pub fn metrics_endpoint(base: Option<&str>) -> Option<String> {
    signal_endpoint(base, "/v1/metrics")
}

fn signal_endpoint(base: Option<&str>, signal: &str) -> Option<String> {
    let base = base?.trim();
    if base.is_empty() {
        return None;
    }
    let mut b = base.trim_end_matches('/');
    b = b.strip_suffix("/v1/metrics").or_else(|| b.strip_suffix("/v1/traces")).unwrap_or(b);
    Some(format!("{}{signal}", b.trim_end_matches('/')))
}

pub(crate) struct Target {
    secure: bool,
    host: String,
    port: u16,
    path: String,
}

impl Target {
    pub(crate) fn parse(url: &str) -> Option<Target> {
        let (secure, rest) = match url.split_once("://")? {
            ("http", rest) => (false, rest),
            ("https", rest) => (true, rest),
            _ => return None,
        };
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], rest[i..].to_string()),
            None => (rest, "/".to_string()),
        };
        let (host, port) = match authority.rsplit_once(':').filter(|(h, _)| !h.ends_with(']') || authority.starts_with('[')) {
            Some((h, p)) if !p.contains(']') => (h.to_string(), p.parse().ok()?),
            _ => (authority.to_string(), if secure { 443 } else { 80 }),
        };
        Some(Target { secure, host: host.trim_start_matches('[').trim_end_matches(']').to_string(), port, path })
    }

    /// An OTLP/HTTP protobuf export: the body POSTed to the endpoint; the answer is not read.
    async fn post(&self, config: &crate::Config, body: Vec<u8>) {
        let request = crate::client::Outbound {
            method: "POST".into(),
            target: self.path.clone(),
            headers: vec![
                ("host".into(), self.authority()),
                ("content-type".into(), "application/x-protobuf".into()),
                ("content-length".into(), body.len().to_string()),
            ],
            body: body.into(),
            http2: false,
            may_stream: false,
            decoded_body: None,
        };
        let _ = crate::client::send(config, &self.host, self.port, self.secure, &request, None, crate::client::CONNECT_TIMEOUT).await;
    }

    /// A POST of `body` with `headers` after `host` and `content-length`, connecting within `connect_timeout` and
    /// answered within `timeout`: the answer's status and body, or why there was none.
    pub(crate) async fn send(
        &self,
        config: &crate::Config,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
        connect_timeout: Duration,
        timeout: Duration,
    ) -> Result<(u32, Vec<u8>), String> {
        let mut all = vec![("host".to_string(), self.authority()), ("content-length".to_string(), body.len().to_string())];
        all.extend(headers);
        let request = crate::client::Outbound {
            method: "POST".into(),
            target: self.path.clone(),
            headers: all,
            body: body.into(),
            http2: false,
            may_stream: false,
            decoded_body: None,
        };
        let sent = crate::client::send(config, &self.host, self.port, self.secure, &request, None, connect_timeout);
        match tokio::time::timeout(timeout, sent).await {
            Ok(Ok(answer)) => Ok((answer.status, answer.body.to_vec())),
            Ok(Err(e)) => Err(e.exception_message().unwrap_or_else(|| "null".into())),
            Err(_) => Err("request timed out".into()),
        }
    }

    fn authority(&self) -> String {
        match self.host.contains(':') {
            true => format!("[{}]:{}", self.host, self.port),
            false => format!("{}:{}", self.host, self.port),
        }
    }
}

fn now_nanos() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(0)
}

/// `TraceContextHandler.randomHexString`: hex digits from random UUIDs.
fn random_hex(length: usize) -> String {
    let mut s = String::new();
    while s.len() < length {
        s.push_str(&uuid::Uuid::new_v4().simple().to_string());
    }
    s.truncate(length);
    s
}

/// A random, valid (not all-zero) span id.
fn span_id() -> String {
    loop {
        let id = random_hex(16);
        if id.bytes().any(|b| b != b'0') {
            return id;
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------
// W3C trace context
// ---------------------------------------------------------------------------------------------------------------

/// `W3CTraceContext`: a parsed `traceparent` (and its `tracestate`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceContext {
    pub version: String,
    pub trace_id: String,
    pub parent_id: String,
    pub flags: String,
    pub trace_state: Option<String>,
}

impl TraceContext {
    /// `W3CTraceContext.parse`: at least four `-`-separated parts.
    pub fn parse(traceparent: &str, trace_state: Option<&str>) -> Option<TraceContext> {
        if traceparent.is_empty() {
            return None;
        }
        let parts = crate::java_text::split(traceparent.trim(), "-");
        if parts.len() < 4 {
            return None;
        }
        Some(TraceContext {
            version: parts[0].to_string(),
            trace_id: parts[1].to_string(),
            parent_id: parts[2].to_string(),
            flags: parts[3].to_string(),
            trace_state: trace_state.map(str::to_string),
        })
    }

    /// `isValid`: a 32-character trace id and a 16-character parent id.
    pub fn is_valid(&self) -> bool {
        self.trace_id.chars().count() == 32 && self.parent_id.chars().count() == 16
    }

    pub fn traceparent(&self) -> String {
        format!("{}-{}-{}-{}", self.version, self.trace_id, self.parent_id, self.flags)
    }

    fn generated() -> TraceContext {
        TraceContext { version: "00".into(), trace_id: random_hex(32), parent_id: random_hex(16), flags: "01".into(), trace_state: None }
    }
}

/// `TraceContextHandler.channelRead`: the context a request sets on its channel, replacing or clearing whatever an
/// earlier request on the same HTTP/1.1 keep-alive connection left there. On 8.0.0 the channel kept the previous
/// context when a request brought neither a valid `traceparent` nor (under `otelGenerateTraceId`) a generated one;
/// upstream a48d37181 sets it on every request, adopted here (`docs/divergences.md`).
pub fn inbound(state: &State, request: &crate::request::HttpRequest, channel: &Mutex<Option<TraceContext>>) {
    *channel.lock() = match request.first_header("traceparent").filter(|t| !t.is_empty()) {
        Some(traceparent) => TraceContext::parse(traceparent, request.first_header("tracestate")).filter(TraceContext::is_valid),
        None if state.config.hot_bool(crate::config::Hot::OtelGenerateTraceId, false) => Some(TraceContext::generated()),
        None => None,
    };
}

/// `TraceContextHandler.write`: under `otelPropagateTraceContext`, the channel's context goes back on the response.
/// The handler writes ahead of the codec, so the headers land before the `content-length` the codec computes.
pub fn outbound(state: &State, reply: &mut crate::reply::Reply, channel: &Mutex<Option<TraceContext>>) {
    if !state.config.hot_bool(crate::config::Hot::OtelPropagateTraceContext, false) {
        return;
    }
    if let Some(context) = channel.lock().as_ref().filter(|c| c.is_valid()) {
        let mut added = vec![("traceparent".to_string(), context.traceparent())];
        if let Some(trace_state) = context.trace_state.as_deref().filter(|s| !s.is_empty()) {
            added.push(("tracestate".into(), trace_state.to_string()));
        }
        // a computed `content-length` is the last header `Reply::finalize` adds; a user-supplied one stays in place
        let at = match reply.headers.last() {
            Some((name, _)) if name.eq_ignore_ascii_case("content-length") => reply.headers.len() - 1,
            _ => reply.headers.len(),
        };
        reply.headers.splice(at..at, added);
    }
}

tokio::task_local! {
    /// The trace context of the channel the current request arrived on.
    static CHANNEL: Option<TraceContext>;
}

/// Runs `f` with `context` as the current channel's trace context, for the [`request_span`]s it records.
pub fn with_channel<F: std::future::Future>(context: Option<TraceContext>, f: F) -> impl std::future::Future<Output = F::Output> {
    CHANNEL.scope(context, f)
}

fn channel_context() -> Option<TraceContext> {
    CHANNEL.try_with(Clone::clone).ok().flatten()
}

// ---------------------------------------------------------------------------------------------------------------
// RequestSpans
// ---------------------------------------------------------------------------------------------------------------

/// What a served request's span reports (`RequestSpans.recordRequest`).
pub struct Served<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub status: Option<u32>,
    pub expectation_id: Option<&'a str>,
    pub response_time_ms: i64,
    /// Whether the span is parented to the channel's trace context (the proxy-pass path has none).
    pub parented: bool,
    pub server_address: Option<&'a str>,
    pub server_port: Option<u16>,
}

/// `RequestSpans.recordRequest`: a SERVER span named `METHOD path`, a child of the inbound trace when there is one.
pub fn request_span(state: &State, served: Served<'_>) {
    if !state.telemetry.enabled() {
        return;
    }
    let method = if served.method.is_empty() { "HTTP" } else { served.method };
    let name = format!("{method} {}", if served.path.is_empty() { "/" } else { served.path });
    let parent = if served.parented { channel_context().filter(TraceContext::is_valid) } else { None };
    let sampled = parent.as_ref().is_none_or(|p| p.flags == "01");
    if parent.is_some() && !sampled {
        // `RequestSpansTest.respectsUnsampledRemoteParentDecision`: the default `parentBased(alwaysOn)` sampler
        // drops a child span of an unsampled remote parent entirely, rather than exporting it flagged unsampled.
        return;
    }
    let mut attributes = vec![("http.request.method".to_string(), Attribute::Str(method.into()))];
    if !served.path.is_empty() {
        attributes.push(("http.route".into(), Attribute::Str(served.path.into())));
    }
    if let Some(status) = served.status {
        attributes.push(("http.response.status_code".into(), Attribute::Long(status.into())));
    }
    if let Some(id) = served.expectation_id.filter(|i| !i.is_empty()) {
        attributes.push(("mockserver.expectation_id".into(), Attribute::Str(id.into())));
    }
    if served.response_time_ms > 0 {
        attributes.push(("mockserver.response_time_ms".into(), Attribute::Long(served.response_time_ms)));
    }
    if let Some(address) = served.server_address.filter(|a| !a.is_empty()) {
        attributes.push(("server.address".into(), Attribute::Str(address.into())));
    }
    if let Some(port) = served.server_port.filter(|p| *p > 0) {
        attributes.push(("server.port".into(), Attribute::Long(port.into())));
    }
    let now = now_nanos();
    state.telemetry.end(Span {
        name,
        kind: Kind::Server,
        trace_id: parent.as_ref().map(|p| p.trace_id.to_ascii_lowercase()).unwrap_or_else(|| random_hex(32)),
        span_id: span_id(),
        parent_span_id: parent.as_ref().map(|p| p.parent_id.to_ascii_lowercase()),
        trace_state: None,
        sampled,
        attributes,
        start_nanos: now,
        end_nanos: now,
    });
}

// ---------------------------------------------------------------------------------------------------------------
// GenAiSpans
// ---------------------------------------------------------------------------------------------------------------

/// The parts of a `Completion` a GenAI span reports.
#[derive(Debug, Default, Clone)]
pub struct Completion {
    pub model: Option<String>,
    pub stop_reason: Option<String>,
    pub input_tokens: Option<i64>,
    pub output_tokens: Option<i64>,
    pub cached_input_tokens: Option<i64>,
    pub cache_creation_tokens: Option<i64>,
    pub reasoning_tokens: Option<i64>,
    pub tool_calls: usize,
    /// The completion text (`Completion.text`).
    pub text: Option<String>,
    /// A usage was set (`Completion.getUsage() != null`), even one with no count.
    pub has_usage: bool,
}

/// `GenAiSpans.recordCompletion`: a CLIENT span `chat <model>`.
pub fn completion_span(state: &State, provider: &str, model: Option<&str>, completion: &Completion) {
    operation_span(state, "chat", provider, model, completion);
}

/// `GenAiSpans.record`: a CLIENT span `<operation> <model>`.
pub fn operation_span(state: &State, operation: &str, provider: &str, model: Option<&str>, completion: &Completion) {
    if !state.telemetry.enabled() {
        return;
    }
    let model = model.filter(|m| !m.is_empty()).unwrap_or("unknown");
    let mut attributes = vec![
        ("gen_ai.operation.name".to_string(), Attribute::Str(operation.into())),
        ("gen_ai.system".into(), Attribute::Str(gen_ai_system(provider))),
        ("gen_ai.request.model".into(), Attribute::Str(model.into())),
    ];
    if let Some(stop) = &completion.stop_reason {
        attributes.push(("gen_ai.response.finish_reasons".into(), Attribute::StrArray(vec![stop.clone()])));
    }
    for (key, value) in [
        ("gen_ai.usage.input_tokens", completion.input_tokens),
        ("gen_ai.usage.output_tokens", completion.output_tokens),
        ("mockserver.gen_ai.usage.cached_input_tokens", completion.cached_input_tokens),
        ("mockserver.gen_ai.usage.cache_creation_tokens", completion.cache_creation_tokens),
        ("mockserver.gen_ai.usage.reasoning_tokens", completion.reasoning_tokens),
    ] {
        if let Some(value) = value {
            attributes.push((key.into(), Attribute::Long(value)));
        }
    }
    if completion.tool_calls > 0 {
        attributes.push(("mockserver.gen_ai.tool_call_count".into(), Attribute::Long(completion.tool_calls as i64)));
    }
    let now = now_nanos();
    state.telemetry.end(Span {
        name: format!("{operation} {model}"),
        kind: Kind::Client,
        trace_id: random_hex(32),
        span_id: span_id(),
        parent_span_id: None,
        trace_state: None,
        sampled: true,
        attributes,
        start_nanos: now,
        end_nanos: now,
    });
}

/// `GenAiSpans.genAiSystem`: the semantic-convention name of a `Provider`.
fn gen_ai_system(provider: &str) -> String {
    match provider {
        "OPENAI" | "OPENAI_RESPONSES" => "openai".into(),
        "ANTHROPIC" => "anthropic".into(),
        "AZURE_OPENAI" => "az.ai.openai".into(),
        "BEDROCK" => "aws.bedrock".into(),
        "GEMINI" => "gcp.gemini".into(),
        "OLLAMA" => "ollama".into(),
        other => other.to_ascii_lowercase(),
    }
}

/// The span for a served `httpLlmResponse` completion (`HttpLlmResponseActionHandler`).
pub fn served_completion(state: &State, llm: &crate::llm::Llm) {
    if !state.telemetry.enabled() {
        return;
    }
    let c = &llm.completion;
    let tokens = |k: &str| c.usage.as_ref().and_then(|u| u.get(k)).and_then(Value::as_i64);
    let completion = Completion {
        model: llm.model.clone(),
        stop_reason: c.stop_reason.clone(),
        input_tokens: tokens("inputTokens"),
        output_tokens: tokens("outputTokens"),
        cached_input_tokens: tokens("cachedInputTokens"),
        cache_creation_tokens: tokens("cacheCreationTokens"),
        reasoning_tokens: tokens("reasoningTokens"),
        tool_calls: c.tool_calls.len(),
        text: c.text.clone(),
        has_usage: c.usage.is_some(),
    };
    completion_span(state, llm.provider.as_deref().unwrap_or("OPENAI"), llm.model.as_deref(), &completion);
}

/// `LlmProviderSniffer.sniffByHostAndPath`.
pub fn sniff(state: &State, host: Option<&str>, path: &str) -> Option<String> {
    let Some(host) = host.map(strip_port).filter(|h| !h.is_empty()) else {
        return configured_provider(state, path);
    };
    let host = host.to_ascii_lowercase();
    let lower_path = path.to_ascii_lowercase();
    let known = match host.as_str() {
        "api.openai.com" if lower_path.contains("/responses") => Some("OPENAI_RESPONSES"),
        "api.openai.com" => Some("OPENAI"),
        // `isAzureOpenAiHost`; Azure also serves the Responses API
        h if h.ends_with(".openai.azure.com") || (h.ends_with(".services.ai.azure.com") && lower_path.starts_with("/openai/")) => {
            Some(if openai_responses_path(&lower_path) { "OPENAI_RESPONSES" } else { "AZURE_OPENAI" })
        }
        "api.anthropic.com" => Some("ANTHROPIC"),
        h if (h == "chatgpt.com" || h.ends_with(".chatgpt.com")) && openai_responses_path(&lower_path) => Some("OPENAI_RESPONSES"),
        "generativelanguage.googleapis.com" => Some("GEMINI"),
        // Vertex AI: the provider is the wire API the path speaks, Gemini's unless the path says otherwise. Its
        // OpenAI-compatible APIs (`endpoints/openapi` for Model Garden and partner models, `endpoints/{id}` for a
        // self-deployed model); Claude speaks the Anthropic Messages API, Mistral models Mistral's chat API, AI21
        // Jamba OpenAI's chat shape.
        h if vertex_host(h) => Some(match VERTEX_OPENAI_COMPATIBLE_PATH.captures(&lower_path) {
            Some(c) if &c[1] == "responses" => "OPENAI_RESPONSES",
            Some(_) => "OPENAI",
            None if lower_path.contains("/publishers/anthropic/") => "ANTHROPIC",
            None if lower_path.contains("/publishers/mistralai/") => "MISTRAL",
            None if lower_path.contains("/publishers/ai21/") => "OPENAI",
            None => "GEMINI",
        }),
        "api.cohere.com" => Some("COHERE"),
        "api.voyageai.com" => Some("VOYAGE"),
        "api.mistral.ai" => Some("MISTRAL"),
        "api.x.ai" => Some("XAI"),
        "api.deepseek.com" => Some("DEEPSEEK"),
        "api.groq.com" => Some("GROQ"),
        "openrouter.ai" => Some("OPENROUTER"),
        "api.orcarouter.ai" => Some("ORCAROUTER"),
        h if h.ends_with(".amazonaws.com") && (h.starts_with("bedrock") || h.contains(".bedrock")) => Some("BEDROCK"),
        _ => None,
    };
    if let Some(provider) = known {
        return Some(provider.into());
    }
    let base = state.config.property("llmBaseUrl").unwrap_or_default();
    if !base.is_empty() && url_host(&base).is_some_and(|h| h.eq_ignore_ascii_case(&host)) {
        return Some("OLLAMA".into());
    }
    configured_provider(state, path)
}

/// `/v1/responses|(^|/)(codex|openai)/responses(?:[/?]|$)`.
fn openai_responses_path(lower: &str) -> bool {
    lower.contains("/v1/responses")
        || ["codex/responses", "openai/responses"].iter().any(|needle| {
            lower.match_indices(needle).any(|(i, m)| {
                (i == 0 || lower.as_bytes()[i - 1] == b'/') && matches!(lower.as_bytes().get(i + m.len()), None | Some(b'/') | Some(b'?'))
            })
        })
}

/// `VERTEX_HOST_PATTERN`, whole (lower-cased) host: global `aiplatform.googleapis.com`, regional
/// `<region>-aiplatform.googleapis.com` or multi-region `aiplatform.<us|eu>.rep.googleapis.com`.
pub(crate) fn vertex_host(host: &str) -> bool {
    let label = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if let Some(region) = host.strip_prefix("aiplatform.").and_then(|r| r.strip_suffix(".rep.googleapis.com")) {
        return label(region);
    }
    match host.strip_suffix("aiplatform.googleapis.com") {
        Some("") => true,
        Some(prefix) => prefix.len() > 1 && prefix.ends_with('-') && label(&prefix[..prefix.len() - 1]),
        None => false,
    }
}

/// `VERTEX_OPENAI_COMPATIBLE_PATH_PATTERN`, found in the lower-cased path.
static VERTEX_OPENAI_COMPATIBLE_PATH: std::sync::LazyLock<regex::Regex> =
    std::sync::LazyLock::new(|| regex::Regex::new(r"/endpoints/[^/]+/(chat/completions|responses)(?:[/?]|$)").expect("Vertex AI OpenAI-compatible path"));
/// `GEMINI_MODEL_PATH_PATTERN`.
static GEMINI_MODEL_PATH: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| regex::Regex::new(r"/models/([^/:]+):[A-Za-z]+$").expect("Gemini model path"));
/// `BEDROCK_MODEL_PATH_PATTERN`, `BEDROCK_INVOKE_PATH_PATTERN` and `BEDROCK_TEXT_COMPLETION_MODEL_PATTERN`: the
/// models whose native InvokeModel request is a prompt string, not chat messages (Titan Text, AI21 Jurassic-2, Cohere
/// Command and Command Light, Meta Llama, Mistral 7B, Mixtral and Mistral Small 24.02, DeepSeek-R1).
static BEDROCK_MODEL_PATH: std::sync::LazyLock<regex::Regex> =
    std::sync::LazyLock::new(|| regex::Regex::new(r"/model/([^/]+)/(?:invoke|invoke-with-response-stream|converse|converse-stream)(?:[/?]|$)").expect("Bedrock model path"));
static BEDROCK_INVOKE_PATH: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| regex::Regex::new(r"/invoke(?:-with-response-stream)?/?$").expect("Bedrock invoke path"));
static BEDROCK_TEXT_COMPLETION_MODEL: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    regex::Regex::new(r"^(?:amazon\.titan-(?:text|tg1)-|ai21\.j2-|cohere\.command-(?:light-)?text-|meta\.llama|mistral\.(?:mistral-7b-instruct|mixtral-8x7b-instruct|mistral-small-2402)|deepseek\.r1)")
        .expect("Bedrock text-completion models")
});

/// `LlmProviderSniffer.extractGeminiModelFromPath`: the model a `/models/{model}:{method}` path names (before any
/// query).
pub(crate) fn gemini_model_from_path(path: &str) -> Option<String> {
    let path = path.split_once('?').map_or(path, |(p, _)| p);
    GEMINI_MODEL_PATH.captures(path).map(|c| c[1].to_string())
}

/// `extractBedrockModelFromPath` (URL-decoded) reduced by `bedrockModelId`: an ARN to its foundation-model or
/// inference-profile id, a cross-Region inference profile id to the foundation model id.
fn bedrock_model_from_path(path: &str) -> Option<String> {
    let raw = BEDROCK_MODEL_PATH.captures(path)?.get(1)?.as_str();
    bedrock_model_id(crate::java_text::url_decode(&raw.replace('+', "%2B"), crate::java_text::UrlCharset::Utf8).unwrap_or_else(|_| raw.to_string()))
}

/// `bedrockModelId`: an ARN to its foundation-model or inference-profile id, a cross-Region inference profile id to the
/// foundation model id; any other id as given.
fn bedrock_model_id(mut model: String) -> Option<String> {
    if model.is_empty() {
        return None;
    }
    if model.starts_with("arn:") {
        let slash = model.rfind('/').filter(|&s| s > 0);
        let resource = slash.map(|s| &model[model[..s].rfind(':').map_or(0, |c| c + 1)..s]).unwrap_or_default();
        if resource != "foundation-model" && resource != "inference-profile" {
            return Some(model);
        }
        model = model[slash.unwrap_or(0) + 1..].to_string();
    }
    let before_version = model.split_once(':').map_or(model.as_str(), |(b, _)| b);
    if let Some(first) = before_version.find('.').filter(|&d| d > 0) && before_version[first + 1..].contains('.') {
        model = model[first + 1..].to_string();
    }
    Some(model)
}

/// `emitForwardGenAiSpan`'s model: the completion's, else for Bedrock the one its path names (a Converse response
/// names none), else the one a native Gemini path (or an AI21 call on Vertex AI) names, else the request body's.
/// A Bedrock Agent Runtime `/rerank` names its model only in its body.
pub(crate) fn forwarded_model(provider: &str, operation: Operation, completion: &Completion, path: &str, request_body: &[u8]) -> Option<String> {
    completion
        .model
        .clone()
        .or_else(|| (provider == "BEDROCK").then(|| bedrock_model_from_path(path).or_else(|| (operation == Operation::Rerank).then(|| bedrock_rerank_model(request_body)).flatten())).flatten())
        .or_else(|| gemini_model_from_path(path))
        .or_else(|| model_from(request_body))
}

/// `LlmProviderSniffer.extractBedrockRerankModelFromRequest`:
/// `rerankingConfiguration.bedrockRerankingConfiguration.modelConfiguration.modelArn`, reduced as a path's model id.
fn bedrock_rerank_model(body: &[u8]) -> Option<String> {
    let root: Value = serde_json::from_slice(body).ok()?;
    let arn = root.pointer("/rerankingConfiguration/bedrockRerankingConfiguration/modelConfiguration/modelArn")?.as_str()?;
    bedrock_model_id(arn.to_string())
}

/// `LlmProviderSniffer.Operation`: the kind of LLM call a response is accounted as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Operation {
    Chat,
    GenerateContent,
    TextCompletion,
    Embeddings,
    Rerank,
}

impl Operation {
    /// `genAiOperationName`: the OpenTelemetry `gen_ai.operation.name`, a well-known value where one applies; rerank
    /// has none, so it uses a custom one.
    pub(crate) fn gen_ai_name(self) -> &'static str {
        match self {
            Operation::Chat => "chat",
            Operation::GenerateContent => "generate_content",
            Operation::TextCompletion => "text_completion",
            Operation::Embeddings => "embeddings",
            Operation::Rerank => "rerank",
        }
    }

    /// `isCompletion`: whether this operation generates a completion, so its response may be a stream.
    pub(crate) fn is_completion(self) -> bool {
        matches!(self, Operation::Chat | Operation::GenerateContent | Operation::TextCompletion)
    }
}

/// `CHAT_PATH_PATTERN`, found in the lower-cased path without its query.
static CHAT_PATH: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    regex::Regex::new(
        r"(?:/completions|/responses(?:/compact)?|/messages|:generatecontent|:streamgeneratecontent|/api/generate|/api/chat|/v[12]/chat|/model/([^/]+)/(?:invoke|invoke-with-response-stream|converse|converse-stream)|/models/([^/:]+):(?:rawpredict|streamrawpredict))/?$",
    )
    .expect("chat path")
});
/// `EMBEDDINGS_PATH_PATTERN`.
static EMBEDDINGS_PATH: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    regex::Regex::new(r"(?:/embeddings|/multimodalembeddings|/contextualizedembeddings|/api/embed|/v[12]/embed|:embedcontent|:batchembedcontents|/publishers/google/models/[^/:]*embedding[^/:]*:predict)/?$")
        .expect("embeddings path")
});
/// `MISTRAL_CONVERSATION_PATH_PATTERN`.
static MISTRAL_CONVERSATION_PATH: std::sync::LazyLock<regex::Regex> =
    std::sync::LazyLock::new(|| regex::Regex::new(r"/v1/conversations(?:/[^/]+(?:/restart)?)?/?$").expect("Mistral conversation path"));

/// `LlmProviderSniffer.accountableOperation`: the LLM call a forwarded request makes, if its response is accounted:
/// a `POST` to a completion, embeddings or rerank endpoint, or a `GET` of a completion that ran in the background
/// (`isPolledCompletion`). Every other endpoint, such as `GET /v1/models`, a token count, a batch or Ollama's
/// `/api/pull`, is not a model call.
pub(crate) fn accountable_operation(provider: &str, method: &str, path: &str) -> Option<Operation> {
    if path.is_empty() {
        return None;
    }
    let lower = path.to_ascii_lowercase();
    let lower = lower.split_once('?').map_or(lower.as_str(), |(p, _)| p);
    if !method.is_empty() && !method.eq_ignore_ascii_case("POST") {
        return is_polled_completion(provider, method, path).then_some(Operation::Chat);
    }
    if let Some(chat) = CHAT_PATH.captures(lower) {
        if let Some(bedrock_model) = chat.get(1).map(|m| m.as_str()) {
            // Bedrock invokes embedding and rerank models on the same path as chat models
            if bedrock_model.contains("rerank") {
                return Some(Operation::Rerank);
            }
            if bedrock_model.contains("embed") {
                return Some(Operation::Embeddings);
            }
            if BEDROCK_INVOKE_PATH.is_match(lower) && bedrock_model_from_path(lower).is_some_and(|m| BEDROCK_TEXT_COMPLETION_MODEL.is_match(&m)) {
                return Some(Operation::TextCompletion);
            }
        }
        // Claude on Vertex AI counts tokens through a model named count-tokens
        if chat.get(2).is_some_and(|m| m.as_str() == "count-tokens") {
            return None;
        }
        // the deprecated Assistants API adds a message to a thread without calling a model
        return (!lower.contains("/threads/")).then(|| completion_operation(lower));
    }
    if EMBEDDINGS_PATH.is_match(lower) {
        return Some(Operation::Embeddings);
    }
    if lower.ends_with("/rerank") || lower.ends_with("/rerank/") {
        return Some(Operation::Rerank);
    }
    if provider == "MISTRAL" && MISTRAL_CONVERSATION_PATH.is_match(lower) {
        return Some(Operation::Chat);
    }
    None
}

/// `LlmProviderSniffer.isPolledCompletion`: a `GET` of the result of a completion that ran in the background, whose
/// usage is reported only there: an OpenAI Responses API response (`/responses/{id}`, not `input_tokens` or
/// `compact`) or an xAI deferred chat completion (`/v1/chat/deferred-completion/{id}`). The same path also retrieves
/// ordinary stored responses, so the response is checked with [`polled_completion_id`].
pub(crate) fn is_polled_completion(provider: &str, method: &str, path: &str) -> bool {
    if !method.eq_ignore_ascii_case("GET") {
        return false;
    }
    let lower = path.to_ascii_lowercase();
    let lower = lower.split_once('?').map_or(lower.as_str(), |(p, _)| p);
    let trimmed = lower.strip_suffix('/').unwrap_or(lower);
    // the last segment, when it is not empty and follows `prefix`
    let id_after = |prefix: &str| trimmed.rsplit_once('/').filter(|(parent, id)| !id.is_empty() && parent.ends_with(prefix)).map(|(_, id)| id);
    match provider {
        "OPENAI_RESPONSES" => id_after("/responses").is_some_and(|id| id != "input_tokens" && id != "compact"),
        "XAI" => id_after("/v1/chat/deferred-completion").is_some(),
        _ => false,
    }
}

/// `TERMINAL_RESPONSE_STATUSES`.
const TERMINAL_RESPONSE_STATUSES: &[&str] = &["completed", "incomplete", "failed", "cancelled"];

/// `LlmProviderSniffer.polledCompletionId`: the id of a polled completion whose usage is to be counted: an OpenAI
/// response created in the background that has finished, or an xAI deferred completion, carrying a usage object. A
/// response not created in the background was counted when it was created.
pub(crate) fn polled_completion_id(provider: &str, body: &[u8]) -> Option<String> {
    let root: Value = serde_json::from_slice(body).ok()?;
    let id = root.get("id").and_then(Value::as_str).filter(|id| !id.is_empty())?;
    if !root.get("usage").is_some_and(Value::is_object) {
        return None;
    }
    match provider {
        "OPENAI_RESPONSES" => {
            // `JsonNode.asBoolean(false)`
            let background = match root.get("background") {
                Some(Value::Bool(b)) => *b,
                Some(Value::String(s)) => s.trim() == "true",
                Some(Value::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0),
                _ => false,
            };
            let status = root.get("status").and_then(Value::as_str).unwrap_or("");
            (background && TERMINAL_RESPONSE_STATUSES.contains(&status)).then(|| id.to_string())
        }
        "XAI" => Some(id.to_string()),
        _ => None,
    }
}

/// `completionOperation`: `GENERATE_CONTENT_PATH_PATTERN` (`(?::generatecontent|:streamgeneratecontent)/?$`), else
/// `TEXT_COMPLETION_PATH_PATTERN` (`(?:(?<!/chat|/agents)/completions|/api/generate)/?$`), else chat.
fn completion_operation(lower: &str) -> Operation {
    let trimmed = lower.strip_suffix('/').unwrap_or(lower);
    if trimmed.ends_with(":generatecontent") || trimmed.ends_with(":streamgeneratecontent") {
        return Operation::GenerateContent;
    }
    let text_completion = trimmed.ends_with("/api/generate")
        || trimmed.strip_suffix("/completions").is_some_and(|before| !before.ends_with("/chat") && !before.ends_with("/agents"));
    if text_completion { Operation::TextCompletion } else { Operation::Chat }
}

/// `LlmProviderSniffer.isVertexAiHost`: a forward sent to a Vertex AI host, billed at its own list prices.
pub(crate) fn is_vertex_ai_host(host: Option<&str>) -> bool {
    host.map(strip_port).is_some_and(|h| vertex_host(&h.to_lowercase()))
}

/// `fallbackToConfiguredProvider`: on an LLM-looking path, the `llmProvider` property names the provider.
fn configured_provider(state: &State, path: &str) -> Option<String> {
    const FRAGMENTS: &[&str] = &["/chat/completions", "/messages", "/completions", "/responses", "/embeddings", "/v1/", ":generatecontent", ":streamgeneratecontent", "/api/generate", "/api/chat"];
    let lower = path.to_ascii_lowercase();
    // `looksLikeLlmPath`: a fragment, or `BEDROCK_PATH_PATTERN` (a private Bedrock endpoint)
    if path.is_empty() || !(FRAGMENTS.iter().any(|f| lower.contains(f)) || BEDROCK_PATH.is_match(&lower)) {
        return None;
    }
    let configured = state.config.property("llmProvider").unwrap_or_default().to_ascii_uppercase();
    PROVIDERS.contains(&configured.as_str()).then_some(configured)
}

/// `BEDROCK_PATH_PATTERN`.
static BEDROCK_PATH: std::sync::LazyLock<regex::Regex> =
    std::sync::LazyLock::new(|| regex::Regex::new(r"/model/[^/]+/(invoke|invoke-with-response-stream|converse|converse-stream)").expect("Bedrock path"));

/// `Provider` values.
const PROVIDERS: &[&str] = &[
    "OPENAI", "OPENAI_RESPONSES", "ANTHROPIC", "AZURE_OPENAI", "BEDROCK", "GEMINI", "OLLAMA", "COHERE", "VOYAGE", "MISTRAL", "XAI", "DEEPSEEK", "GROQ", "OPENROUTER",
    "ORCAROUTER",
];

/// `stripPort`.
pub(crate) fn strip_port(host: &str) -> &str {
    if let Some(rest) = host.strip_prefix('[') && let Some(close) = rest.find(']') {
        return &rest[..close];
    }
    match host.rfind(':') {
        Some(colon) if colon > 0 => &host[..colon],
        _ => host,
    }
}

/// `URI.getHost`.
fn url_host(url: &str) -> Option<String> {
    let rest = url.split_once("://")?.1;
    let authority = rest.split(['/', '?', '#']).next()?;
    let authority = authority.rsplit_once('@').map_or(authority, |(_, a)| a);
    let host = strip_port(authority);
    (!host.is_empty()).then(|| host.to_string())
}

/// `LlmProviderSniffer.extractModelFromRequest`.
pub(crate) fn model_from(body: &[u8]) -> Option<String> {
    let root: Value = serde_json::from_slice(body).ok()?;
    root.get("model").map(as_text).filter(|m| !m.is_empty())
}

/// `JsonNode.asText`.
fn as_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "null".into(),
        Value::Object(_) | Value::Array(_) => String::new(),
        other => other.to_string(),
    }
}

/// `JsonNode.asInt`.
fn as_int(v: &Value) -> i64 {
    match v {
        Value::Number(n) => n.as_i64().unwrap_or_else(|| n.as_f64().map_or(0, |f| f as i32 as i64)) as i32 as i64,
        Value::String(s) => parse_as_int(s),
        Value::Bool(b) => *b as i64,
        _ => 0,
    }
}

/// The token counts of a `Usage`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Usage {
    pub input_tokens: Option<i64>,
    pub output_tokens: Option<i64>,
    pub cached_input_tokens: Option<i64>,
    pub cache_creation_tokens: Option<i64>,
    pub reasoning_tokens: Option<i64>,
}

impl Usage {
    /// `hasTokenCounts`.
    pub fn has_token_counts(&self) -> bool {
        self.input_tokens.is_some() || self.output_tokens.is_some()
    }
}

impl Completion {
    /// `Completion.withUsage`.
    pub(crate) fn set_usage(&mut self, usage: Option<Usage>) {
        self.has_usage = usage.is_some();
        let usage = usage.unwrap_or_default();
        self.input_tokens = usage.input_tokens;
        self.output_tokens = usage.output_tokens;
        self.cached_input_tokens = usage.cached_input_tokens;
        self.cache_creation_tokens = usage.cache_creation_tokens;
        self.reasoning_tokens = usage.reasoning_tokens;
    }

    /// `Completion.getUsage`'s counts.
    pub(crate) fn usage(&self) -> Usage {
        Usage {
            input_tokens: self.input_tokens,
            output_tokens: self.output_tokens,
            cached_input_tokens: self.cached_input_tokens,
            cache_creation_tokens: self.cache_creation_tokens,
            reasoning_tokens: self.reasoning_tokens,
        }
    }
}

/// Jackson's `NumberInput.parseAsInt(text, 0)` (`TextNode.asInt`): whole digits as an `int` (0 past its range), any
/// other text as `(int) Double.parseDouble`, 0 when it is not a number.
fn parse_as_int(text: &str) -> i64 {
    let s = text.trim();
    let unsigned = s.strip_prefix('+').unwrap_or(s);
    let digits = unsigned.strip_prefix('-').unwrap_or(unsigned);
    if s.is_empty() || digits.is_empty() {
        return 0;
    }
    if digits.bytes().all(|b| b.is_ascii_digit()) {
        return unsigned.parse::<i32>().map_or(0, i64::from);
    }
    unsigned.parse::<f64>().map_or(0, |d| d as i32 as i64)
}

/// `LlmClient.parseUsage` of the client registered for `provider`: a usage object in the provider's own field names
/// (as a whole response or a stream's usage events give it), or `None` when it is not one.
pub(crate) fn parse_usage(provider: &str, usage: Option<&Value>) -> Option<Usage> {
    let node = usage?;
    let int = |k: &str| node.get(k).map(as_int);
    let detail = |d: &str, k: &str| node.get(d).filter(|d| d.is_object()).and_then(|d| d.get(k)).map(as_int);
    let openai = || Usage {
        input_tokens: int("prompt_tokens"),
        output_tokens: int("completion_tokens"),
        cached_input_tokens: detail("prompt_tokens_details", "cached_tokens"),
        reasoning_tokens: detail("completion_tokens_details", "reasoning_tokens"),
        ..Usage::default()
    };
    let anthropic = || Usage {
        input_tokens: int("input_tokens"),
        output_tokens: int("output_tokens"),
        cached_input_tokens: int("cache_read_input_tokens"),
        cache_creation_tokens: int("cache_creation_input_tokens"),
        ..Usage::default()
    };
    let camel = |input: &str, output: &str, read: &str, write: &str| Usage {
        input_tokens: int(input),
        output_tokens: int(output),
        cached_input_tokens: int(read),
        cache_creation_tokens: int(write),
        ..Usage::default()
    };
    let has = |k: &str| node.get(k).is_some();
    match provider {
        "OPENAI" | "AZURE_OPENAI" | "MISTRAL" | "DEEPSEEK" | "GROQ" | "OPENROUTER" | "ORCAROUTER" => node.is_object().then(openai),
        // `XaiLlmClient`: reasoning tokens are billed as output
        "XAI" => node.is_object().then(openai).map(|mut u| {
            if let Some(reasoning) = u.reasoning_tokens {
                u.output_tokens = Some((u.output_tokens.unwrap_or(0) as i32).wrapping_add(reasoning as i32) as i64);
            }
            u
        }),
        "OPENAI_RESPONSES" => node.is_object().then(|| Usage {
            input_tokens: int("input_tokens"),
            output_tokens: int("output_tokens"),
            cached_input_tokens: detail("input_tokens_details", "cached_tokens"),
            cache_creation_tokens: detail("input_tokens_details", "cache_write_tokens"),
            reasoning_tokens: detail("output_tokens_details", "reasoning_tokens"),
        }),
        "ANTHROPIC" => node.is_object().then(anthropic),
        // `BedrockLlmClient.parseUsage`: Converse counts, an OpenAI usage object, InvokeModelWithResponseStream's
        // invocation metrics, else Anthropic's
        "BEDROCK" if has("inputTokens") || has("outputTokens") => {
            node.is_object().then(|| camel("inputTokens", "outputTokens", "cacheReadInputTokens", "cacheWriteInputTokens"))
        }
        "BEDROCK" if (has("prompt_tokens") || has("completion_tokens")) && !has("input_tokens") && !has("output_tokens") => node.is_object().then(openai),
        "BEDROCK" if has("inputTokenCount") || has("outputTokenCount") => {
            node.is_object().then(|| camel("inputTokenCount", "outputTokenCount", "cacheReadInputTokenCount", "cacheWriteInputTokenCount"))
        }
        "BEDROCK" => node.is_object().then(anthropic),
        "GEMINI" => node.is_object().then(|| {
            // candidatesTokenCount excludes thoughts, which Gemini bills as output
            let (candidates, thoughts) = (node.get("candidatesTokenCount"), node.get("thoughtsTokenCount"));
            let output = (candidates.is_some() || thoughts.is_some()).then(|| {
                let sum = candidates.map_or(0, as_int) + thoughts.map_or(0, as_int);
                sum.min(i32::MAX as i64)
            });
            Usage { input_tokens: int("promptTokenCount"), output_tokens: output, cached_input_tokens: int("cachedContentTokenCount"), reasoning_tokens: thoughts.map(as_int), ..Usage::default() }
        }),
        "OLLAMA" => (has("prompt_eval_count") || has("eval_count")).then(|| Usage { input_tokens: int("prompt_eval_count"), output_tokens: int("eval_count"), ..Usage::default() }),
        "COHERE" => {
            let count = |field: &str| {
                let present = |v: Option<&Value>| v.filter(|x| !x.is_null()).map(as_int);
                present(node.get("billed_units").and_then(|b| b.get(field))).or_else(|| present(node.get("tokens").and_then(|t| t.get(field))))
            };
            let (input, output) = (count("input_tokens"), count("output_tokens"));
            (node.is_object() && (input.is_some() || output.is_some()))
                .then(|| Usage { input_tokens: input, output_tokens: output, cached_input_tokens: node.get("cached_tokens").filter(|x| !x.is_null()).map(as_int), ..Usage::default() })
        }
        "VOYAGE" => node.get("total_tokens").filter(|t| !t.is_null()).map(|t| Usage { input_tokens: Some(as_int(t)), ..Usage::default() }),
        _ => None,
    }
}

/// `LlmClient.parseCompletionResponse` of the client registered for `provider`, from the body alone.
pub(crate) fn parse_completion(provider: &str, body: &[u8]) -> Option<Completion> {
    parse_completion_response(provider, body, &|_| None)
}

/// `LlmClient.parseCompletionResponse` of a response with its headers (`header` looks one up by name, ignoring case):
/// a Bedrock body whose usage has no token counts, such as an embedding, rerank or non-Anthropic model's, is counted
/// from the token-count headers InvokeModel returns for every model, or without them from a Titan body's counts.
pub(crate) fn parse_completion_response(provider: &str, body: &[u8], header: &dyn Fn(&str) -> Option<String>) -> Option<Completion> {
    let mut c = parse_body(provider, body)?;
    if provider == "BEDROCK" && !c.usage().has_token_counts() {
        let root: Value = serde_json::from_slice(body).unwrap_or_default();
        if let Some(usage) = bedrock_header_usage(header).or_else(|| titan_usage(&root)) {
            c.set_usage(Some(usage));
        }
    }
    Some(c)
}

/// `BedrockLlmClient.usageFromHeaders`: the `X-Amzn-Bedrock-*-Token-Count` headers, each a non-negative `int`.
fn bedrock_header_usage(header: &dyn Fn(&str) -> Option<String>) -> Option<Usage> {
    let count = |name: &str| header(name).filter(|v| !v.is_empty()).and_then(|v| v.trim().parse::<i32>().ok()).filter(|n| *n >= 0).map(i64::from);
    let (input, output) = (count("x-amzn-bedrock-input-token-count"), count("x-amzn-bedrock-output-token-count"));
    if input.is_none() && output.is_none() {
        return None;
    }
    Some(Usage {
        input_tokens: input,
        output_tokens: output,
        cached_input_tokens: count("x-amzn-bedrock-cache-read-input-token-count"),
        cache_creation_tokens: count("x-amzn-bedrock-cache-write-input-token-count"),
        ..Usage::default()
    })
}

/// `BedrockLlmClient.titanUsage`: `inputTextTokenCount`, and a Titan Text model's output tokens of each result in
/// `results[].tokenCount`.
fn titan_usage(root: &Value) -> Option<Usage> {
    let input = root.get("inputTextTokenCount").filter(|v| !v.is_null())?;
    let output = summed_counts(root.get("results").and_then(Value::as_array).into_iter().flatten().map(|r| r.get("tokenCount")));
    Some(Usage { input_tokens: Some(as_int(input).max(0)), output_tokens: output, ..Usage::default() })
}

/// The sum of the counts that are non-negative integral numbers fitting a `long`, saturating at `Integer.MAX_VALUE`;
/// `None` when none is.
fn summed_counts<'a>(counts: impl Iterator<Item = Option<&'a Value>>) -> Option<i64> {
    let max = i32::MAX as i64;
    let mut sum = None;
    for count in counts.flatten() {
        let Some(n) = count.as_i64() else { continue };
        if n >= 0 {
            sum = Some((sum.unwrap_or(0) + n.min(max)).min(max));
        }
    }
    sum
}

/// `BedrockLlmClient.parseConverseUsage`: the camelCase counts of a usage object.
fn converse_usage(usage: Option<&Value>) -> Option<Usage> {
    let node = usage.filter(|u| u.is_object())?;
    let int = |k: &str| node.get(k).map(as_int);
    Some(Usage {
        input_tokens: int("inputTokens"),
        output_tokens: int("outputTokens"),
        cached_input_tokens: int("cacheReadInputTokens"),
        cache_creation_tokens: int("cacheWriteInputTokens"),
        ..Usage::default()
    })
}

/// [`parse_completion_response`] before the Bedrock header and Titan fallbacks.
fn parse_body(provider: &str, body: &[u8]) -> Option<Completion> {
    let root: Value = serde_json::from_slice(body).ok()?;
    let text = |v: &Value, k: &str| v.get(k).filter(|x| !x.is_null()).map(as_text);
    let mut c = Completion::default();
    match provider {
        "OPENAI" | "AZURE_OPENAI" | "MISTRAL" | "XAI" | "DEEPSEEK" | "GROQ" | "OPENROUTER" | "ORCAROUTER" => {
            c.model = text(&root, "model");
            let choice = root.get("choices").and_then(|c| c.get(0)).cloned().unwrap_or_default();
            c.stop_reason = text(&choice, "finish_reason");
            c.text = choice.get("message").and_then(|m| text(m, "content"));
            c.set_usage(parse_usage(provider, root.get("usage")));
            if provider == "MISTRAL" && c.model.is_none() {
                // a Conversations response names its model only on its outputs
                c.model = root.get("outputs").and_then(Value::as_array).and_then(|o| o.iter().rev().find_map(|e| e.get("model").and_then(Value::as_str))).map(str::to_string);
            }
        }
        "OPENAI_RESPONSES" => {
            c.model = text(&root, "model");
            c.stop_reason = text(&root, "status");
            c.text = text(&root, "output_text").or_else(|| {
                let joined: String = root.get("output").and_then(Value::as_array).into_iter().flatten()
                    .flat_map(|item| item.get("content").and_then(Value::as_array).into_iter().flatten())
                    .filter(|c| c.get("type").and_then(Value::as_str) == Some("output_text"))
                    .filter_map(|c| text(c, "text"))
                    .collect();
                (!joined.is_empty()).then_some(joined)
            });
            c.set_usage(parse_usage(provider, root.get("usage")));
        }
        // `AnthropicLlmClient`, and for Bedrock (`BedrockLlmClient.parseBody`) a Converse envelope
        // (`output.message.content[]`, `stopReason`, camelCase usage) when `output.message` is an object; Bedrock reads
        // each usage shape (`parseUsage`: Converse, OpenAI, invocation metrics, else Anthropic)
        "BEDROCK" if root.pointer("/output/message").is_some_and(Value::is_object) => {
            let joined: String = root.pointer("/output/message/content").and_then(Value::as_array).into_iter().flatten()
                .filter_map(|b| b.get("text").and_then(Value::as_str))
                .collect();
            c.text = (!joined.is_empty()).then_some(joined);
            c.stop_reason = text(&root, "stopReason");
            c.set_usage(converse_usage(root.get("usage")));
        }
        "ANTHROPIC" | "BEDROCK" => {
            c.model = text(&root, "model");
            c.stop_reason = text(&root, "stop_reason");
            let joined: String = root.get("content").and_then(Value::as_array).into_iter().flatten()
                .filter(|b| b.get("type").and_then(Value::as_str) == Some("text"))
                .filter_map(|b| text(b, "text"))
                .collect();
            c.text = (!joined.is_empty()).then_some(joined);
            c.set_usage(parse_usage(provider, root.get("usage")));
        }
        "GEMINI" => {
            c.model = text(&root, "modelVersion");
            let candidate = root.get("candidates").and_then(|c| c.get(0)).cloned().unwrap_or_default();
            c.stop_reason = text(&candidate, "finishReason");
            let joined: String = candidate.pointer("/content/parts").and_then(Value::as_array).into_iter().flatten()
                .filter_map(|p| text(p, "text"))
                .collect();
            c.text = (!joined.is_empty()).then_some(joined);
            c.set_usage(parse_usage(provider, root.get("usageMetadata")).or_else(|| {
                // a Vertex AI text embeddings `:predict` response (`predictedEmbeddingsUsage`)
                let counts = root.get("predictions").and_then(Value::as_array).into_iter().flatten().map(|p| p.pointer("/embeddings/statistics/token_count"));
                summed_counts(counts).map(|input| Usage { input_tokens: Some(input), ..Usage::default() })
            }));
        }
        "OLLAMA" => {
            c.model = text(&root, "model");
            c.stop_reason = text(&root, "done_reason");
            c.text = root.get("message").and_then(|m| text(m, "content"));
            c.set_usage(parse_usage("OLLAMA", Some(&root)));
        }
        // `CohereLlmClient`: chat text (v2 `message.content[]` text blocks, else v1 `text`), and the billed count of
        // each side, else the count the model used, from v2 `usage` or `ApiMeta` `meta`.
        "COHERE" => {
            let joined: String = root.pointer("/message/content").and_then(Value::as_array).into_iter().flatten()
                .filter(|b| b.get("type").and_then(Value::as_str) == Some("text"))
                .filter_map(|b| b.get("text").and_then(Value::as_str))
                .collect();
            c.text = (!joined.is_empty()).then_some(joined).or_else(|| root.get("text").and_then(Value::as_str).map(str::to_string));
            c.stop_reason = root.get("finish_reason").and_then(Value::as_str).map(str::to_string);
            c.set_usage(parse_usage("COHERE", root.get("usage")).or_else(|| parse_usage("COHERE", root.get("meta"))));
        }
        // `VoyageLlmClient`: the response's `model` and its `usage.total_tokens`, all input.
        "VOYAGE" => {
            c.model = root.get("model").and_then(Value::as_str).map(str::to_string);
            c.set_usage(parse_usage("VOYAGE", root.get("usage")));
        }
        _ => return None,
    }
    Some(c)
}

// ---------------------------------------------------------------------------------------------------------------
// OTLP protobuf
// ---------------------------------------------------------------------------------------------------------------

/// `ExportTraceServiceRequest` and `ExportMetricsServiceRequest` encoding (opentelemetry-proto `trace/v1`, `metrics/v1`).
mod otlp {
    use super::{Attribute, Kind, Span};
    use crate::metrics::{OtelHistogramPoint, OtelPoint, OtelValue};

    fn varint(out: &mut Vec<u8>, mut v: u64) {
        while v >= 0x80 {
            out.push((v as u8) | 0x80);
            v >>= 7;
        }
        out.push(v as u8);
    }

    fn tag(out: &mut Vec<u8>, field: u32, wire: u8) {
        varint(out, ((field as u64) << 3) | wire as u64);
    }

    fn bytes(out: &mut Vec<u8>, field: u32, b: &[u8]) {
        tag(out, field, 2);
        varint(out, b.len() as u64);
        out.extend_from_slice(b);
    }

    fn fixed64(out: &mut Vec<u8>, field: u32, v: u64) {
        tag(out, field, 1);
        out.extend_from_slice(&v.to_le_bytes());
    }

    fn fixed32(out: &mut Vec<u8>, field: u32, v: u32) {
        tag(out, field, 5);
        out.extend_from_slice(&v.to_le_bytes());
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len() / 2).filter_map(|i| u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok()).collect()
    }

    fn string_value(s: &str) -> Vec<u8> {
        let mut v = Vec::new();
        bytes(&mut v, 1, s.as_bytes());
        v
    }

    fn key_value(key: &str, value: &Attribute) -> Vec<u8> {
        let any = match value {
            Attribute::Str(s) => string_value(s),
            Attribute::Long(n) => {
                let mut v = Vec::new();
                tag(&mut v, 3, 0);
                varint(&mut v, *n as u64);
                v
            }
            Attribute::StrArray(items) => {
                let mut array = Vec::new();
                for item in items {
                    bytes(&mut array, 1, &string_value(item));
                }
                let mut v = Vec::new();
                bytes(&mut v, 5, &array);
                v
            }
        };
        let mut kv = Vec::new();
        bytes(&mut kv, 1, key.as_bytes());
        bytes(&mut kv, 2, &any);
        kv
    }

    fn span(s: &Span) -> Vec<u8> {
        let mut v = Vec::new();
        bytes(&mut v, 1, &hex(&s.trace_id));
        bytes(&mut v, 2, &hex(&s.span_id));
        if let Some(state) = &s.trace_state {
            bytes(&mut v, 3, state.as_bytes());
        }
        if let Some(parent) = &s.parent_span_id {
            bytes(&mut v, 4, &hex(parent));
        }
        bytes(&mut v, 5, s.name.as_bytes());
        tag(&mut v, 6, 0);
        varint(&mut v, if s.kind == Kind::Server { 2 } else { 3 });
        fixed64(&mut v, 7, s.start_nanos);
        fixed64(&mut v, 8, s.end_nanos);
        for (key, value) in &s.attributes {
            bytes(&mut v, 9, &key_value(key, value));
        }
        // Status UNSET: an empty message.
        bytes(&mut v, 15, &[]);
        let remote = if s.parent_span_id.is_some() { 0x300 } else { 0x100 };
        fixed32(&mut v, 16, remote | s.sampled as u32);
        v
    }

    fn resource() -> Vec<u8> {
        let mut resource = Vec::new();
        let version = env!("CARGO_PKG_VERSION");
        for (k, value) in [("service.name", "mockserver"), ("service.version", version), ("telemetry.sdk.language", "rust"), ("telemetry.sdk.name", "opentelemetry")] {
            bytes(&mut resource, 1, &key_value(k, &Attribute::Str(value.into())));
        }
        resource
    }

    /// `InstrumentationScope`: the `org.mockserver` tracer and meter.
    fn scope() -> Vec<u8> {
        let mut scope = Vec::new();
        bytes(&mut scope, 1, b"org.mockserver");
        scope
    }

    /// `NumberDataPoint`.
    fn data_point(p: &OtelPoint, start: u64, now: u64) -> Vec<u8> {
        let mut v = Vec::new();
        fixed64(&mut v, 2, start);
        fixed64(&mut v, 3, now);
        match p.value {
            OtelValue::Double(d) => fixed64(&mut v, 4, d.to_bits()),
            OtelValue::Long(n) => fixed64(&mut v, 6, n as u64),
        }
        for (key, value) in &p.attributes {
            bytes(&mut v, 7, &key_value(key, &typed(key, value)));
        }
        v
    }

    /// An attribute's `AnyValue`: semconv types `http.response.status_code` and `server.port` as ints, the rest are strings.
    fn typed(key: &str, value: &str) -> Attribute {
        match value.parse::<i64>() {
            Ok(n) if key == "http.response.status_code" || key == "server.port" => Attribute::Long(n),
            _ => Attribute::Str(value.to_string()),
        }
    }

    /// `HistogramDataPoint`: explicit bounds, per-bucket counts, sum, min and max.
    fn histogram_point(p: &OtelHistogramPoint, now: u64) -> Vec<u8> {
        let h = &p.histogram;
        let mut v = Vec::new();
        fixed64(&mut v, 2, h.start_nanos);
        fixed64(&mut v, 3, now);
        fixed64(&mut v, 4, h.count);
        fixed64(&mut v, 5, h.sum.to_bits());
        let counts: Vec<u8> = h.bucket_counts.iter().flat_map(|c| c.to_le_bytes()).collect();
        bytes(&mut v, 6, &counts);
        let bounds: Vec<u8> = h.bounds.iter().flat_map(|b| b.to_bits().to_le_bytes()).collect();
        bytes(&mut v, 7, &bounds);
        for (key, value) in &p.attributes {
            bytes(&mut v, 9, &key_value(key, &typed(key, value)));
        }
        if h.count > 0 {
            fixed64(&mut v, 11, h.min.to_bits());
            fixed64(&mut v, 12, h.max.to_bits());
        }
        v
    }

    /// `ExportMetricsServiceRequest` (opentelemetry-proto `metrics/v1`): one `Metric` per instrument name (its points
    /// in order), a `Gauge`, a monotonic `Sum`, a non-monotonic (up-down) `Sum` or a `Histogram`, the sums and the
    /// histogram with the aggregation temporality (1 delta, 2 cumulative; an up-down sum is always cumulative).
    pub fn encode_metrics(points: &[(OtelPoint, u64)], histograms: &[OtelHistogramPoint], now: u64, delta: bool) -> Vec<u8> {
        let mut scope_metrics = Vec::new();
        bytes(&mut scope_metrics, 1, &scope());
        let temporality = |data: &mut Vec<u8>| {
            tag(data, 2, 0);
            varint(data, if delta { 1 } else { 2 });
        };
        let mut i = 0;
        while i < histograms.len() {
            let first = &histograms[i];
            let mut data = Vec::new();
            while i < histograms.len() && histograms[i].name == first.name {
                bytes(&mut data, 1, &histogram_point(&histograms[i], now));
                i += 1;
            }
            temporality(&mut data);
            let mut metric = Vec::new();
            bytes(&mut metric, 1, first.name.as_bytes());
            bytes(&mut metric, 2, first.description.as_bytes());
            bytes(&mut metric, 3, b"s");
            bytes(&mut metric, 9, &data);
            bytes(&mut scope_metrics, 2, &metric);
        }
        let mut i = 0;
        while i < points.len() {
            let first = &points[i].0;
            let mut data = Vec::new();
            while i < points.len() && points[i].0.name == first.name {
                bytes(&mut data, 1, &data_point(&points[i].0, points[i].1, now));
                i += 1;
            }
            let mut metric = Vec::new();
            bytes(&mut metric, 1, first.name.as_bytes());
            bytes(&mut metric, 2, first.description.as_bytes());
            if !first.unit.is_empty() {
                bytes(&mut metric, 3, first.unit.as_bytes());
            }
            if first.monotonic {
                tag(&mut data, 2, 0);
                varint(&mut data, if delta { 1 } else { 2 });
                tag(&mut data, 3, 0);
                varint(&mut data, 1);
                bytes(&mut metric, 7, &data);
            } else if first.up_down {
                // An up-down counter: cumulative whatever the temporality preference, as the SDK's delta selector
                // keeps it, and not monotonic (the default `false`, not written).
                tag(&mut data, 2, 0);
                varint(&mut data, 2);
                bytes(&mut metric, 7, &data);
            } else {
                bytes(&mut metric, 5, &data);
            }
            bytes(&mut scope_metrics, 2, &metric);
        }
        let mut resource_metrics = Vec::new();
        bytes(&mut resource_metrics, 1, &resource());
        bytes(&mut resource_metrics, 2, &scope_metrics);
        let mut out = Vec::new();
        bytes(&mut out, 1, &resource_metrics);
        out
    }

    pub fn encode(spans: &[Span]) -> Vec<u8> {
        let resource = resource();
        let mut scope_spans = Vec::new();
        bytes(&mut scope_spans, 1, &scope());
        for s in spans {
            bytes(&mut scope_spans, 2, &span(s));
        }
        let mut resource_spans = Vec::new();
        bytes(&mut resource_spans, 1, &resource);
        bytes(&mut resource_spans, 2, &scope_spans);
        let mut out = Vec::new();
        bytes(&mut out, 1, &resource_spans);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vertex_and_responses_paths() {
        assert!(vertex_host("aiplatform.googleapis.com"));
        assert!(vertex_host("us-central1-aiplatform.googleapis.com"));
        assert!(!vertex_host("xaiplatform.googleapis.com"));
        assert!(openai_responses_path("/backend-api/codex/responses"));
        assert!(!openai_responses_path("/backend-api/xcodex/responses"));
    }

    // -----------------------------------------------------------------------------------------------------------
    // LlmProviderSnifferTest (9.1.0, 898fa8014) — the methods forwarding to a real provider host would need.
    // -----------------------------------------------------------------------------------------------------------

    /// `detectsVertexAiOpenAiCompatibleEndpointsByTheirOpenAiWireApi`.
    #[test]
    fn detects_vertex_ai_open_ai_compatible_endpoints_by_their_open_ai_wire_api() {
        let state = state_for_test();
        let sniffed = |host: &str, path: &str| sniff(&state, Some(host), path);
        for (host, path) in [
            ("us-central1-aiplatform.googleapis.com", "/v1/projects/p/locations/us-central1/endpoints/openapi/chat/completions"),
            ("us-central1-aiplatform.googleapis.com", "/v1beta1/projects/p/locations/us-central1/endpoints/openapi/chat/completions"),
            ("aiplatform.googleapis.com", "/v1/projects/p/locations/global/endpoints/openapi/chat/completions"),
            ("us-east4-aiplatform.googleapis.com", "/v1beta1/projects/p/locations/us-east4/endpoints/1234567890/chat/completions"),
        ] {
            assert_eq!(sniffed(host, path).as_deref(), Some("OPENAI"), "{path}");
            assert_eq!(accountable_operation("OPENAI", "POST", path).map(Operation::gen_ai_name).unwrap_or_default(), "chat");
        }
        let responses = "/v1/projects/p/locations/us/endpoints/openapi/responses";
        assert_eq!(sniffed("aiplatform.us.rep.googleapis.com", responses).as_deref(), Some("OPENAI_RESPONSES"));
        assert_eq!(sniffed("us-central1-aiplatform.googleapis.com", "/v1/projects/p/locations/us-central1/endpoints/openapi/responses?alt=json").as_deref(), Some("OPENAI_RESPONSES"));
        // the Gemini API and a deployed endpoint's own predict method keep Gemini's wire API
        for path in [
            "/v1/projects/p/locations/us-central1/publishers/google/models/gemini-2.5-flash:generateContent",
            "/v1/projects/p/locations/us-central1/endpoints/1234567890:predict",
            "/v1/projects/p/locations/us-central1/endpoints/openapi/chat/completions-archive",
        ] {
            assert_eq!(sniffed("us-central1-aiplatform.googleapis.com", path).as_deref(), Some("GEMINI"), "{path}");
        }
    }

    /// `detectsAi21JambaOnVertexAiByItsOpenAiShapedUsage`.
    #[test]
    fn detects_ai21_jamba_on_vertex_ai_by_its_open_ai_shaped_usage() {
        let state = state_for_test();
        for method in ["rawPredict", "streamRawPredict"] {
            let path = format!("/v1/projects/p/locations/us-central1/publishers/ai21/models/jamba-1.5-large@001:{method}");
            assert_eq!(sniff(&state, Some("us-central1-aiplatform.googleapis.com"), &path).as_deref(), Some("OPENAI"));
            assert_eq!(gemini_model_from_path(&path).as_deref(), Some("jamba-1.5-large@001"));
        }
    }

    /// `detectsTheVertexAiMultiRegionHosts`.
    #[test]
    fn detects_the_vertex_ai_multi_region_hosts() {
        let state = state_for_test();
        assert_eq!(sniff(&state, Some("aiplatform.us.rep.googleapis.com"), "/v1/projects/p/locations/us/publishers/anthropic/models/claude-opus-4-7:rawPredict").as_deref(), Some("ANTHROPIC"));
        assert_eq!(sniff(&state, Some("aiplatform.eu.rep.googleapis.com"), "/v1/projects/p/locations/eu/publishers/anthropic/models/claude-opus-4-7:streamRawPredict").as_deref(), Some("ANTHROPIC"));
        assert_eq!(sniff(&state, Some("aiplatform.us.rep.googleapis.com"), "").as_deref(), Some("GEMINI"));
        for host in ["evil.aiplatform.us.rep.googleapis.com", "aiplatform.evil.com.rep.googleapis.com", "aiplatform.us.rep.googleapis.com.evil.com"] {
            assert!(!vertex_host(host), "{host}");
            assert_eq!(sniff(&state, Some(host), ""), None, "{host}");
        }
    }

    /// `accountsABedrockInvocationOfALegacyTextCompletionModelAsTextCompletion`.
    #[test]
    fn accounts_a_bedrock_invocation_of_a_legacy_text_completion_model_as_text_completion() {
        for model in [
            "amazon.titan-text-express-v1", "amazon.titan-text-lite-v1", "amazon.titan-text-premier-v1%3A0", "amazon.titan-tg1-large",
            "ai21.j2-mid-v1", "ai21.j2-ultra-v1", "cohere.command-text-v14", "cohere.command-light-text-v14",
            "meta.llama3-70b-instruct-v1%3A0", "meta.llama3-2-90b-instruct-v1%3A0", "meta.llama4-maverick-17b-instruct-v1%3A0",
            "mistral.mistral-7b-instruct-v0%3A2", "mistral.mixtral-8x7b-instruct-v0%3A1", "mistral.mistral-small-2402-v1%3A0", "deepseek.r1-v1%3A0",
            "us.meta.llama3-2-90b-instruct-v1%3A0", "us.deepseek.r1-v1%3A0", "arn%3Aaws%3Abedrock%3Aus-east-1%3A%3Afoundation-model%2Fcohere.command-text-v14",
            "AMAZON.TITAN-TEXT-EXPRESS-V1",
        ] {
            assert_eq!(accountable_operation("BEDROCK", "POST", &format!("/model/{model}/invoke")).map(Operation::gen_ai_name).unwrap_or_default(), "text_completion", "{model}");
            assert_eq!(accountable_operation("BEDROCK", "POST", &format!("/model/{model}/invoke-with-response-stream")).map(Operation::gen_ai_name).unwrap_or_default(), "text_completion", "{model}");
            assert_eq!(accountable_operation("BEDROCK", "POST", &format!("/model/{model}/converse")).map(Operation::gen_ai_name).unwrap_or_default(), "chat", "{model}");
            assert_eq!(accountable_operation("BEDROCK", "POST", &format!("/model/{model}/converse-stream")).map(Operation::gen_ai_name).unwrap_or_default(), "chat", "{model}");
        }
        for model in [
            "anthropic.claude-sonnet-4-5-20250929-v1%3A0", "amazon.nova-pro-v1%3A0", "cohere.command-r-plus-v1%3A0", "ai21.jamba-1-5-large-v1%3A0",
            "mistral.mistral-large-2407-v1%3A0", "mistral.pixtral-large-2502-v1%3A0", "mistral.mistral-large-2402-v1%3A0", "openai.gpt-oss-20b-1%3A0",
            "arn%3Aaws%3Abedrock%3Aus-east-1%3A123456789012%3Aapplication-inference-profile%2Fa1b2c3d4e5f6",
        ] {
            assert_eq!(accountable_operation("BEDROCK", "POST", &format!("/model/{model}/invoke")).map(Operation::gen_ai_name).unwrap_or_default(), "chat", "{model}");
        }
    }

    /// `LlmClientTest` (404dd73f8): a Bedrock response with an OpenAI usage object and no Anthropic counts.
    #[test]
    fn bedrock_reads_open_ai_shaped_usage() {
        let body = br#"{"choices":[{"message":{"content":"hi"}}],"usage":{"prompt_tokens":12,"completion_tokens":5,"prompt_tokens_details":{"cached_tokens":3},"completion_tokens_details":{"reasoning_tokens":2}}}"#;
        let c = parse_completion("BEDROCK", body).unwrap();
        assert_eq!((c.input_tokens, c.output_tokens, c.cached_input_tokens, c.reasoning_tokens), (Some(12), Some(5), Some(3), Some(2)));
        // Anthropic counts win when both are there
        let both = br#"{"usage":{"input_tokens":7,"output_tokens":1,"prompt_tokens":12}}"#;
        let c = parse_completion("BEDROCK", both).unwrap();
        assert_eq!((c.input_tokens, c.output_tokens), (Some(7), Some(1)));
    }

    // -----------------------------------------------------------------------------------------------------------
    // OtelEndpointsTest (upstream/mockserver/.../telemetry/OtelEndpointsTest.java) — one #[test] per method.
    // -----------------------------------------------------------------------------------------------------------

    /// `emptyOrNullBaseUsesExporterDefault`.
    #[test]
    fn otel_endpoints_empty_or_null_base_uses_exporter_default() {
        assert_eq!(metrics_endpoint(None), None);
        assert_eq!(metrics_endpoint(Some("")), None);
        assert_eq!(traces_endpoint(None), None);
        assert_eq!(traces_endpoint(Some("")), None);
        assert_eq!(traces_endpoint(Some("  ")), None);
    }

    /// `appendsSignalPathToBareBase`.
    #[test]
    fn otel_endpoints_appends_signal_path_to_bare_base() {
        assert_eq!(metrics_endpoint(Some("http://collector:4318")).as_deref(), Some("http://collector:4318/v1/metrics"));
        assert_eq!(traces_endpoint(Some("http://collector:4318")).as_deref(), Some("http://collector:4318/v1/traces"));
    }

    /// `toleratesTrailingSlash`.
    #[test]
    fn otel_endpoints_tolerates_trailing_slash() {
        assert_eq!(metrics_endpoint(Some("http://collector:4318/")).as_deref(), Some("http://collector:4318/v1/metrics"));
        assert_eq!(traces_endpoint(Some("http://collector:4318//")).as_deref(), Some("http://collector:4318/v1/traces"));
    }

    /// `toleratesValueAlreadyCarryingASignalPath`.
    #[test]
    fn otel_endpoints_tolerates_value_already_carrying_a_signal_path() {
        assert_eq!(metrics_endpoint(Some("http://collector:4318/v1/metrics")).as_deref(), Some("http://collector:4318/v1/metrics"));
        assert_eq!(traces_endpoint(Some("http://collector:4318/v1/metrics")).as_deref(), Some("http://collector:4318/v1/traces"));
    }

    /// `toleratesSignalPathWithTrailingSlash`: the previously-buggy case — signal path + trailing slash must not
    /// double up.
    #[test]
    fn otel_endpoints_tolerates_signal_path_with_trailing_slash() {
        assert_eq!(traces_endpoint(Some("http://collector:4318/v1/metrics/")).as_deref(), Some("http://collector:4318/v1/traces"));
        assert_eq!(metrics_endpoint(Some("http://collector:4318/v1/traces/")).as_deref(), Some("http://collector:4318/v1/metrics"));
    }

    // -----------------------------------------------------------------------------------------------------------
    // W3CTraceContextTest (upstream/mockserver/.../telemetry/W3CTraceContextTest.java) — one #[test] per portable
    // method. `nullVersionFailsValidation` and `nullFlagsFailsValidation` have no Rust equivalent: our
    // `TraceContext.version`/`flags` are plain `String`, not `Option<String>`, and `TraceContext::parse` can never
    // produce one from a well-formed traceparent's absence (a caller with no `traceparent` header never calls
    // `parse` at all — see `inbound`), so those two upstream cases test a constructor state this port cannot reach.
    // -----------------------------------------------------------------------------------------------------------

    /// `parsesValidTraceparent`.
    #[test]
    fn w3c_trace_context_parses_valid_traceparent() {
        let c = TraceContext::parse("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", None).unwrap();
        assert!(c.is_valid());
        assert_eq!(c.version, "00");
        assert_eq!(c.trace_id, "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_eq!(c.parent_id, "00f067aa0ba902b7");
        assert_eq!(c.flags, "01");
        assert_eq!(c.trace_state, None);
    }

    /// `parsesTracestateAlongside`.
    #[test]
    fn w3c_trace_context_parses_tracestate_alongside() {
        let c = TraceContext::parse("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", Some("rojo=00f067aa0ba902b7")).unwrap();
        assert!(c.is_valid());
        assert_eq!(c.trace_state.as_deref(), Some("rojo=00f067aa0ba902b7"));
    }

    /// `rejectsEmptyTraceparent`. (`rejectsNullTraceparent` has no equivalent: `parse` takes `&str`, not
    /// `Option<&str>` — callers filter out a missing header before calling it, see `inbound`.)
    #[test]
    fn w3c_trace_context_rejects_empty_traceparent() {
        assert!(TraceContext::parse("", None).is_none());
    }

    /// `rejectsTooFewParts`.
    #[test]
    fn w3c_trace_context_rejects_too_few_parts() {
        assert!(TraceContext::parse("only-two", None).is_none());
        assert!(TraceContext::parse("one-two-three", None).is_none());
    }

    /// `roundTripsToTraceparentString`.
    #[test]
    fn w3c_trace_context_round_trips_to_traceparent_string() {
        let original = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let c = TraceContext::parse(original, None).unwrap();
        assert_eq!(c.traceparent(), original);
    }

    /// `invalidTraceIdLengthFailsValidation`.
    #[test]
    fn w3c_trace_context_invalid_trace_id_length_fails_validation() {
        let c = TraceContext { version: "00".into(), trace_id: "tooshort".into(), parent_id: "00f067aa0ba902b7".into(), flags: "01".into(), trace_state: None };
        assert!(!c.is_valid());
    }

    /// `invalidParentIdLengthFailsValidation`.
    #[test]
    fn w3c_trace_context_invalid_parent_id_length_fails_validation() {
        let c = TraceContext { version: "00".into(), trace_id: "4bf92f3577b34da6a3ce929d0e0e4736".into(), parent_id: "short".into(), flags: "01".into(), trace_state: None };
        assert!(!c.is_valid());
    }

    /// `parsesUnsampledFlags`.
    #[test]
    fn w3c_trace_context_parses_unsampled_flags() {
        let c = TraceContext::parse("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00", None).unwrap();
        assert!(c.is_valid());
        assert_eq!(c.flags, "00");
    }

    /// `toleratesLeadingAndTrailingWhitespace`.
    #[test]
    fn w3c_trace_context_tolerates_leading_and_trailing_whitespace() {
        let c = TraceContext::parse("  00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01  ", None).unwrap();
        assert!(c.is_valid());
        assert_eq!(c.trace_id, "4bf92f3577b34da6a3ce929d0e0e4736");
    }

    /// `traceparentWithExtraFieldsIsParsed`: future versions may add extra dash-separated fields; parse must
    /// tolerate this.
    #[test]
    fn w3c_trace_context_with_extra_fields_is_parsed() {
        let c = TraceContext::parse("01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra", None).unwrap();
        assert!(c.is_valid());
        assert_eq!(c.version, "01");
    }

    // -----------------------------------------------------------------------------------------------------------
    // TraceContextHandlerTest, the two cases upstream a48d37181 added (after 8.0.0, adopted): one channel, as for an
    // HTTP/1.1 keep-alive connection, carries no context from one request to the next.
    // -----------------------------------------------------------------------------------------------------------

    const VALID_TRACEPARENT: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
    const VALID_TRACESTATE: &str = "rojo=00f067aa0ba902b7";

    fn traced_request(path: &str, headers: &[(&str, &str)]) -> crate::request::HttpRequest {
        let mut request = crate::request::HttpRequest { path: path.into(), ..Default::default() };
        for (name, value) in headers {
            crate::request::push(&mut request.headers, name, value.to_string());
        }
        request
    }

    fn header<'a>(reply: &'a crate::reply::Reply, name: &str) -> Option<&'a str> {
        reply.headers.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str())
    }

    /// `shouldNotCarryTraceContextOverToLaterRequestWithoutTraceparent`.
    #[test]
    fn trace_context_handler_does_not_carry_context_over_to_a_later_request_without_traceparent() {
        let state = State::new(crate::Config::for_tests().with_property("otelPropagateTraceContext", "true").with_property("otelGenerateTraceId", "false"), Vec::new());
        let channel = Mutex::new(None);
        inbound(&state, &traced_request("/a", &[("traceparent", VALID_TRACEPARENT), ("tracestate", VALID_TRACESTATE)]), &channel);
        let mut response_a = crate::reply::Reply::status(200);
        outbound(&state, &mut response_a, &channel);
        assert_eq!(header(&response_a, "traceparent"), Some(VALID_TRACEPARENT));

        inbound(&state, &traced_request("/b", &[]), &channel);
        let mut response_b = crate::reply::Reply::status(200);
        outbound(&state, &mut response_b, &channel);
        assert!(channel.lock().is_none());
        assert_eq!(header(&response_b, "traceparent"), None);
        assert_eq!(header(&response_b, "tracestate"), None);
    }

    /// `shouldNotCarryTraceContextOverToLaterRequestWithInvalidTraceparent`.
    #[test]
    fn trace_context_handler_does_not_carry_context_over_to_a_later_request_with_invalid_traceparent() {
        let state = State::new(crate::Config::for_tests().with_property("otelPropagateTraceContext", "true"), Vec::new());
        let channel = Mutex::new(None);
        inbound(&state, &traced_request("/a", &[("traceparent", VALID_TRACEPARENT)]), &channel);
        assert!(channel.lock().is_some());
        inbound(&state, &traced_request("/b", &[("traceparent", "00-short-00f067aa0ba902b7-01")]), &channel);
        assert!(channel.lock().is_none());
    }

    /// A `State` built directly (synchronous, no server bound) — the per-test-tracer equivalent for tests that
    /// only need `state.telemetry` and don't touch the network.
    fn state_for_test() -> Arc<State> {
        State::new(crate::Config::for_tests(), Vec::new())
    }

    // -----------------------------------------------------------------------------------------------------------
    // GenAiSpansTest (upstream/mockserver/.../telemetry/GenAiSpansTest.java) — one #[test] per method.
    // -----------------------------------------------------------------------------------------------------------

    /// `emitsGenAiSpanWithSemanticConventionAttributes`.
    #[test]
    fn gen_ai_spans_emits_span_with_semantic_convention_attributes() {
        let state = state_for_test();
        let capture = state.telemetry.capture();
        let completion = Completion { stop_reason: Some("end_turn".into()), input_tokens: Some(10), output_tokens: Some(2), tool_calls: 1, text: Some("hi".into()), ..Default::default() };
        completion_span(&state, "ANTHROPIC", Some("claude-3-5-sonnet"), &completion);
        let spans = capture.spans();
        assert_eq!(spans.len(), 1);
        let span = &spans[0];
        assert_eq!(span.name, "chat claude-3-5-sonnet");
        assert_eq!(span.string("gen_ai.operation.name"), Some("chat"));
        assert_eq!(span.string("gen_ai.system"), Some("anthropic"));
        assert_eq!(span.string("gen_ai.request.model"), Some("claude-3-5-sonnet"));
        assert_eq!(span.attribute("gen_ai.response.finish_reasons"), Some(&Attribute::StrArray(vec!["end_turn".into()])));
        assert_eq!(span.long("gen_ai.usage.input_tokens"), Some(10));
        assert_eq!(span.long("gen_ai.usage.output_tokens"), Some(2));
        assert_eq!(span.long("mockserver.gen_ai.tool_call_count"), Some(1));
    }

    /// `emitsCachedAndReasoningTokenAttributesWhenPresent`.
    #[test]
    fn gen_ai_spans_emits_cached_and_reasoning_token_attributes_when_present() {
        let state = state_for_test();
        let capture = state.telemetry.capture();
        let completion =
            Completion { input_tokens: Some(100), output_tokens: Some(40), cached_input_tokens: Some(80), cache_creation_tokens: Some(5), reasoning_tokens: Some(25), text: Some("hi".into()), ..Default::default() };
        completion_span(&state, "OPENAI", Some("gpt-4o"), &completion);
        let span = capture.spans().into_iter().next().unwrap();
        assert_eq!(span.long("gen_ai.usage.input_tokens"), Some(100));
        assert_eq!(span.long("gen_ai.usage.output_tokens"), Some(40));
        assert_eq!(span.long("mockserver.gen_ai.usage.cached_input_tokens"), Some(80));
        assert_eq!(span.long("mockserver.gen_ai.usage.cache_creation_tokens"), Some(5));
        assert_eq!(span.long("mockserver.gen_ai.usage.reasoning_tokens"), Some(25));
    }

    /// `omitsCachedAndReasoningAttributesWhenAbsent`.
    #[test]
    fn gen_ai_spans_omits_cached_and_reasoning_attributes_when_absent() {
        let state = state_for_test();
        let capture = state.telemetry.capture();
        let completion = Completion { input_tokens: Some(10), output_tokens: Some(2), text: Some("hi".into()), ..Default::default() };
        completion_span(&state, "OPENAI", Some("gpt-4o"), &completion);
        let span = capture.spans().into_iter().next().unwrap();
        assert_eq!(span.long("mockserver.gen_ai.usage.cached_input_tokens"), None);
        assert_eq!(span.long("mockserver.gen_ai.usage.reasoning_tokens"), None);
    }

    /// `mapsProvidersToGenAiSemconvSystemValues`. Upstream also asserts `genAiSystem(null)` is `"unknown"`; our
    /// `gen_ai_system` takes `&str`, not `Option<&str>`, and every call site (`served_completion`,
    /// `forwarded_completion`) always passes a known, non-empty provider constant, so that branch is unreachable
    /// here and is not ported.
    #[test]
    fn gen_ai_spans_maps_providers_to_gen_ai_semconv_system_values() {
        assert_eq!(gen_ai_system("OPENAI"), "openai");
        assert_eq!(gen_ai_system("OPENAI_RESPONSES"), "openai");
        assert_eq!(gen_ai_system("ANTHROPIC"), "anthropic");
        assert_eq!(gen_ai_system("AZURE_OPENAI"), "az.ai.openai");
        assert_eq!(gen_ai_system("BEDROCK"), "aws.bedrock");
        assert_eq!(gen_ai_system("GEMINI"), "gcp.gemini");
        assert_eq!(gen_ai_system("OLLAMA"), "ollama");
    }

    /// `recordCompletionIsNoOpAndSafeWhenDisabled`.
    #[test]
    fn gen_ai_spans_record_completion_is_no_op_and_safe_when_disabled() {
        let state = state_for_test();
        assert!(!state.telemetry.enabled());
        completion_span(&state, "OPENAI", Some("gpt-4o"), &Completion { text: Some("x".into()), ..Default::default() });
    }

    // -----------------------------------------------------------------------------------------------------------
    // RequestSpansTest (upstream/mockserver/.../telemetry/RequestSpansTest.java) — one #[test]/#[tokio::test] per
    // method. Parent-context cases need `with_channel` (a tokio task-local), so those run under `#[tokio::test]`.
    // -----------------------------------------------------------------------------------------------------------

    /// `emitsServerSpanWithHttpAttributes`.
    #[test]
    fn request_spans_emits_server_span_with_http_attributes() {
        let state = state_for_test();
        let capture = state.telemetry.capture();
        request_span(&state, Served { method: "GET", path: "/api/users", status: Some(200), expectation_id: Some("exp-123"), response_time_ms: 42, parented: false, server_address: None, server_port: None });
        let spans = capture.spans();
        assert_eq!(spans.len(), 1);
        let span = &spans[0];
        assert_eq!(span.name, "GET /api/users");
        assert_eq!(span.kind, Kind::Server);
        assert_eq!(span.string("http.request.method"), Some("GET"));
        assert_eq!(span.string("http.route"), Some("/api/users"));
        assert_eq!(span.long("http.response.status_code"), Some(200));
        assert_eq!(span.string("mockserver.expectation_id"), Some("exp-123"));
        assert_eq!(span.long("mockserver.response_time_ms"), Some(42));
    }

    /// `emitsServerAddressAndPortForForwardPath`.
    #[test]
    fn request_spans_emits_server_address_and_port_for_forward_path() {
        let state = state_for_test();
        let capture = state.telemetry.capture();
        request_span(&state, Served { method: "GET", path: "/api/users", status: Some(200), expectation_id: Some("exp-123"), response_time_ms: 42, parented: false, server_address: Some("api.upstream.com"), server_port: Some(8443) });
        let span = capture.spans().into_iter().next().unwrap();
        assert_eq!(span.string("server.address"), Some("api.upstream.com"));
        assert_eq!(span.long("server.port"), Some(8443));
    }

    /// `omitsServerAddressAndPortOnMockedPath`.
    #[test]
    fn request_spans_omits_server_address_and_port_on_mocked_path() {
        let state = state_for_test();
        let capture = state.telemetry.capture();
        request_span(&state, Served { method: "GET", path: "/api/users", status: Some(200), expectation_id: Some("exp-123"), response_time_ms: 42, parented: false, server_address: None, server_port: None });
        let span = capture.spans().into_iter().next().unwrap();
        assert_eq!(span.string("server.address"), None);
        assert_eq!(span.long("server.port"), None);
    }

    /// `emitsSpanWithRemoteParentContext`.
    #[tokio::test]
    async fn request_spans_emits_span_with_remote_parent_context() {
        let state = state_for_test();
        let capture = state.telemetry.capture();
        let parent = TraceContext { version: "00".into(), trace_id: "4bf92f3577b34da6a3ce929d0e0e4736".into(), parent_id: "00f067aa0ba902b7".into(), flags: "01".into(), trace_state: None };
        with_channel(Some(parent), async {
            request_span(&state, Served { method: "POST", path: "/api/orders", status: Some(201), expectation_id: Some("exp-456"), response_time_ms: 100, parented: true, server_address: None, server_port: None });
        })
        .await;
        let spans = capture.spans();
        assert_eq!(spans.len(), 1);
        let span = &spans[0];
        assert_eq!(span.name, "POST /api/orders");
        assert_eq!(span.trace_id, "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_eq!(span.parent_span_id.as_deref(), Some("00f067aa0ba902b7"));
        assert!(span.sampled);
    }

    /// `respectsUnsampledRemoteParentDecision`: upstream's `parentBased(alwaysOn)` sampler drops a child of an
    /// unsampled remote parent — no span reaches the exporter at all, not merely one flagged unsampled. Porting
    /// this exposed a real gap: `request_span` used to build and emit the span regardless of the computed
    /// `sampled` flag. Fixed alongside this test (see the early return in `request_span`).
    #[tokio::test]
    async fn request_spans_respects_unsampled_remote_parent_decision() {
        let state = state_for_test();
        let capture = state.telemetry.capture();
        let parent = TraceContext { version: "00".into(), trace_id: "aaaabbbbccccddddeeee111122223333".into(), parent_id: "1234567890abcdef".into(), flags: "00".into(), trace_state: None };
        with_channel(Some(parent), async {
            request_span(&state, Served { method: "GET", path: "/health", status: Some(200), expectation_id: None, response_time_ms: 1, parented: true, server_address: None, server_port: None });
        })
        .await;
        assert_eq!(capture.spans().len(), 0);
    }

    /// `omitsOptionalAttributesWhenNull`.
    #[test]
    fn request_spans_omits_optional_attributes_when_null() {
        let state = state_for_test();
        let capture = state.telemetry.capture();
        request_span(&state, Served { method: "DELETE", path: "/api/items/1", status: None, expectation_id: None, response_time_ms: 0, parented: false, server_address: None, server_port: None });
        let span = capture.spans().into_iter().next().unwrap();
        assert_eq!(span.name, "DELETE /api/items/1");
        assert_eq!(span.string("http.request.method"), Some("DELETE"));
        assert_eq!(span.string("http.route"), Some("/api/items/1"));
        assert_eq!(span.long("http.response.status_code"), None);
        assert_eq!(span.string("mockserver.expectation_id"), None);
        assert_eq!(span.long("mockserver.response_time_ms"), None);
    }

    /// `usesDefaultsWhenMethodAndPathAreNull`: `Served.method`/`path` are non-`Option<&str>` in this port; empty
    /// string is the reachable equivalent (nothing upstream of `request_span` ever hands it an actual null).
    #[test]
    fn request_spans_uses_defaults_when_method_and_path_are_empty() {
        let state = state_for_test();
        let capture = state.telemetry.capture();
        request_span(&state, Served { method: "", path: "", status: Some(200), expectation_id: None, response_time_ms: 0, parented: false, server_address: None, server_port: None });
        let span = capture.spans().into_iter().next().unwrap();
        assert_eq!(span.name, "HTTP /");
        assert_eq!(span.string("http.request.method"), Some("HTTP"));
    }

    /// `recordRequestIsNoOpAndSafeWhenDisabled`.
    #[test]
    fn request_spans_record_request_is_no_op_and_safe_when_disabled() {
        let state = state_for_test();
        assert!(!state.telemetry.enabled());
        request_span(&state, Served { method: "GET", path: "/test", status: Some(200), expectation_id: Some("some-id"), response_time_ms: 10, parented: false, server_address: None, server_port: None });
    }

    /// `isEnabledReturnsFalseWhenNoTracer`.
    #[test]
    fn request_spans_is_enabled_returns_false_when_no_tracer() {
        let state = state_for_test();
        assert!(!state.telemetry.enabled());
    }

    /// `isEnabledReturnsTrueWhenTracerInstalled`.
    #[test]
    fn request_spans_is_enabled_returns_true_when_tracer_installed() {
        let state = state_for_test();
        state.telemetry.capture();
        assert!(state.telemetry.enabled());
    }

    /// `isEnabledReturnsFalseAfterStop`.
    #[test]
    fn request_spans_is_enabled_returns_false_after_stop() {
        let state = state_for_test();
        state.telemetry.capture();
        state.telemetry.stop();
        assert!(!state.telemetry.enabled());
    }

    /// `ignoresInvalidParentContext`: an invalid parent (trace/parent id too short) is filtered out before it
    /// reaches the span, so the span comes out a root span — `parent_span_id: None` is this port's "no parent"
    /// (upstream's wire form for the same thing is the all-zero span id `"0000000000000000"`).
    #[tokio::test]
    async fn request_spans_ignores_invalid_parent_context() {
        let state = state_for_test();
        let capture = state.telemetry.capture();
        let invalid = TraceContext { version: "00".into(), trace_id: "short".into(), parent_id: "alsoshort".into(), flags: "01".into(), trace_state: None };
        with_channel(Some(invalid), async {
            request_span(&state, Served { method: "GET", path: "/test", status: Some(200), expectation_id: None, response_time_ms: 0, parented: true, server_address: None, server_port: None });
        })
        .await;
        let span = capture.spans().into_iter().next().unwrap();
        assert_eq!(span.name, "GET /test");
        assert_eq!(span.parent_span_id, None);
    }

    // -----------------------------------------------------------------------------------------------------------
    // GenAiSpanExporterTest (upstream/mockserver/.../telemetry/GenAiSpanExporterTest.java). Our design ties
    // enable/capture/stop to one `Telemetry` per `State`, not two process-wide static holders ("GenAiSpans" +
    // "RequestSpans"), so `startInstallsTracerIntoBothSpanHolders` / `stopDisablesBothSpanHolders` become: both
    // `completion_span` and `request_span` honour the same enable/disable lifecycle on one `State`.
    // -----------------------------------------------------------------------------------------------------------

    /// `startInstallsTracerIntoBothSpanHolders`.
    #[test]
    fn gen_ai_span_exporter_start_enables_both_completion_and_request_spans() {
        let state = state_for_test();
        assert!(!state.telemetry.enabled());
        state.telemetry.capture();
        assert!(state.telemetry.enabled(), "GenAi span recording must be enabled after start");
    }

    /// `completionRecordedThroughInstalledTracerReachesExporter`.
    #[test]
    fn gen_ai_span_exporter_completion_reaches_exporter() {
        let state = state_for_test();
        let capture = state.telemetry.capture();
        completion_span(&state, "ANTHROPIC", Some("claude-3-5-sonnet"), &Completion { text: Some("hi".into()), ..Default::default() });
        let spans = capture.spans();
        assert_eq!(spans.len(), 1, "the wired tracer must export the recorded completion span");
        assert_eq!(spans[0].name, "chat claude-3-5-sonnet");
        assert_eq!(spans[0].string("gen_ai.system"), Some("anthropic"));
    }

    /// `requestRecordedThroughInstalledTracerReachesExporter`.
    #[test]
    fn gen_ai_span_exporter_request_reaches_exporter() {
        let state = state_for_test();
        let capture = state.telemetry.capture();
        request_span(&state, Served { method: "GET", path: "/health", status: Some(200), expectation_id: Some("exp-1"), response_time_ms: 5, parented: false, server_address: None, server_port: None });
        assert!(!capture.spans().is_empty(), "the wired tracer must export the recorded request span");
    }

    /// `resourceCarriesMockserverServiceName`: the OTLP resource's `service.name` at the encoder unit; the same
    /// fact is checked at the wire level by `exports_spans_as_otlp_protobuf` below and `scripts/verify-otlp-trace.sh`.
    #[test]
    fn gen_ai_span_exporter_resource_carries_mockserver_service_name() {
        let encoded =
            otlp::encode(&[Span { name: "chat gpt-4o".into(), kind: Kind::Client, trace_id: random_hex(32), span_id: span_id(), parent_span_id: None, trace_state: None, sampled: true, attributes: vec![], start_nanos: 1, end_nanos: 2 }]);
        let has = |needle: &[u8]| encoded.windows(needle.len()).any(|w| w == needle);
        assert!(has(b"service.name"), "resource must carry service.name");
        assert!(has(b"mockserver"), "service.name must be mockserver");
    }

    /// `stopDisablesBothSpanHolders`.
    #[test]
    fn gen_ai_span_exporter_stop_disables_both_span_holders() {
        let state = state_for_test();
        state.telemetry.capture();
        state.telemetry.stop();
        assert!(!state.telemetry.enabled(), "GenAi span recording must be disabled after stop");
    }

    /// `afterStopRecordedCompletionIsANoOp`.
    #[test]
    fn gen_ai_span_exporter_after_stop_recorded_completion_is_a_no_op() {
        let state = state_for_test();
        let capture = state.telemetry.capture();
        state.telemetry.stop();
        completion_span(&state, "ANTHROPIC", Some("claude-3-5-sonnet"), &Completion { text: Some("hi".into()), ..Default::default() });
        assert_eq!(capture.spans().len(), 0);
    }

    /// `startIfEnabledReturnsNullWhenTracesDisabled`: `telemetry::start` is our `startIfEnabled` — with
    /// `otelTracesEnabled` unset (default false) it returns before installing anything or spawning the export
    /// task, so this needs no tokio runtime.
    #[test]
    fn gen_ai_span_exporter_start_if_enabled_is_a_no_op_when_traces_disabled() {
        let state = state_for_test();
        start(&state);
        assert!(!state.telemetry.enabled(), "disabled OTel must not start an exporter");
    }

    // OtelMetricsExporterTest (upstream/mockserver/.../metrics/OtelMetricsExporterTest.java): `startWithReader` and
    // the in-memory reader are `metrics::otel_points` plus `Metrics::collect_otel_histograms` (what each periodic
    // export carries). `exportsJvmAndSlowRequestMetrics`' JVM half has no counterpart (docs/divergences.md).

    fn metrics_state() -> Arc<State> {
        State::new(crate::Config::for_tests().with_property("metricsEnabled", "true"), Vec::new())
    }

    fn otel_point<'a>(points: &'a [crate::metrics::OtelPoint], name: &str, attribute: Option<(&str, &str)>) -> &'a crate::metrics::OtelPoint {
        points
            .iter()
            .find(|p| p.name == name && attribute.is_none_or(|(k, v)| p.attributes.iter().any(|(pk, pv)| pk == k && pv == v)))
            .unwrap_or_else(|| panic!("{name} {attribute:?} not exported"))
    }

    #[test]
    fn otel_metrics_exporter_resolves_delta_temporality_trimmed_and_case_insensitive_else_cumulative() {
        for value in ["delta", "  delta  ", "DELTA", " Delta "] {
            assert!(is_delta_temporality(Some(value)), "{value:?}");
        }
        for value in [Some("cumulative"), Some("deltas"), Some(""), Some("   "), None] {
            assert!(!is_delta_temporality(value), "{value:?}");
        }
    }

    /// The process set under the OTel process semconv names and units, and our build-info gauge.
    #[test]
    fn otel_metrics_exporter_exports_the_process_semconv_set_and_build_info() {
        let state = metrics_state();
        let points = crate::metrics::otel_points(&state);
        let user = otel_point(&points, "process.cpu.time", Some(("cpu.mode", "user")));
        let system = otel_point(&points, "process.cpu.time", Some(("cpu.mode", "system")));
        for cpu in [user, system] {
            assert!(cpu.monotonic && cpu.unit == "s" && matches!(cpu.value, crate::metrics::OtelValue::Double(_)), "{cpu:?}");
        }
        let at = |name: &str| points.iter().position(|p| p.name == name).unwrap();
        assert_eq!(points.iter().filter(|p| p.name == "process.cpu.time").count(), 2);
        assert_eq!(at("process.cpu.time") + 1, points.iter().rposition(|p| p.name == "process.cpu.time").unwrap(), "one Metric's points are adjacent");
        let build = otel_point(&points, "mock_server_native_build_info", Some(("mockserver_version", crate::control::VERSION)));
        assert!(!build.monotonic && !build.up_down && build.value == crate::metrics::OtelValue::Long(1));
        assert!(!points.iter().any(|p| p.name.starts_with("jvm")), "no JVM gauges, no alias");
        if !cfg!(any(target_os = "linux", target_os = "macos")) {
            return;
        }
        for (name, unit) in [("process.memory.usage", "By"), ("process.memory.virtual", "By"), ("process.unix.file_descriptor.count", "{file_descriptor}"), ("process.thread.count", "{thread}")] {
            let p = otel_point(&points, name, None);
            assert!(p.up_down && !p.monotonic && p.unit == unit && p.attributes.is_empty(), "{p:?}");
            assert!(matches!(p.value, crate::metrics::OtelValue::Long(n) if n > 0), "{p:?}");
        }
        let uptime = otel_point(&points, "process.uptime", None);
        assert!(!uptime.monotonic && !uptime.up_down && uptime.unit == "s");
        assert!(matches!(uptime.value, crate::metrics::OtelValue::Double(s) if (0.0..86_400.0 * 365.0).contains(&s)), "{uptime:?}");
    }

    /// A figure the platform cannot give is left out of OTLP too, and uptime is now less the start time.
    #[test]
    fn otel_process_points_leave_out_what_the_platform_cannot_give() {
        let stats = crate::metrics::process::ProcessStats { cpu_user_seconds: 1.5, cpu_system_seconds: 0.25, max_resident_bytes: 1.0, ..Default::default() };
        let names: Vec<String> = crate::metrics::process_otel_points(&stats, 100.0).into_iter().map(|p| p.name).collect();
        assert_eq!(names, ["process.cpu.time", "process.cpu.time"]);
        let stats = crate::metrics::process::ProcessStats { start_time_seconds: Some(40.0), threads: Some(7.0), ..stats };
        let points = crate::metrics::process_otel_points(&stats, 100.5);
        assert_eq!(otel_point(&points, "process.uptime", None).value, crate::metrics::OtelValue::Double(60.5));
        assert_eq!(otel_point(&points, "process.thread.count", None).value, crate::metrics::OtelValue::Long(7));
        assert_eq!(otel_point(&points, "process.cpu.time", Some(("cpu.mode", "system"))).value, crate::metrics::OtelValue::Double(0.25));
    }

    /// An up-down counter is a non-monotonic `Sum`, cumulative even under the delta preference.
    #[test]
    fn otlp_encodes_an_up_down_counter_as_a_cumulative_non_monotonic_sum() {
        let stats = crate::metrics::process::ProcessStats { threads: Some(3.0), ..Default::default() };
        let threads = crate::metrics::process_otel_points(&stats, 0.0).into_iter().find(|p| p.name == "process.thread.count").unwrap();
        let body = otlp::encode_metrics(&[(threads, 1)], &[], 2, true);
        let has = |needle: &[u8]| body.windows(needle.len()).any(|w| w == needle);
        assert!(has(b"{thread}"));
        // Sum.aggregation_temporality (field 2) = CUMULATIVE, no is_monotonic (field 3); scripts/verify-otlp-metrics.sh
        // decodes the whole shape.
        assert!(has(&[0x10, 0x02]) && !has(&[0x18, 0x01]));
    }

    #[test]
    fn otel_metrics_exporter_exports_explicit_mock_server_metrics_as_observable_gauges() {
        let state = metrics_state();
        state.config.metrics.increment(crate::metrics::Count::RequestsReceived);
        let points = crate::metrics::otel_points(&state);
        assert!(points.iter().filter(|p| !p.monotonic && p.attributes.is_empty()).count() >= crate::metrics::NAMES.len());
        let requests = otel_point(&points, "requests_received_count", None);
        assert!(!requests.monotonic);
        assert_eq!(requests.value, crate::metrics::OtelValue::Long(crate::metrics::get(&state, "REQUESTS_RECEIVED_COUNT").unwrap()));
        assert_eq!(requests.value, crate::metrics::OtelValue::Long(1));
    }

    #[test]
    fn otel_metrics_exporter_exports_active_service_chaos_gauge() {
        let state = metrics_state();
        let profile = crate::chaos::http::HttpChaosProfile { error_status: Some(503), ..Default::default() };
        state.chaos.service.put("upstream.svc", profile, 0);
        let points = crate::metrics::otel_points(&state);
        let error = otel_point(&points, "mock_server_active_service_chaos", Some(("fault_type", "error")));
        assert!(!error.monotonic);
        assert_eq!(error.value, crate::metrics::OtelValue::Long(1));
        assert_eq!(otel_point(&points, "mock_server_active_service_chaos", Some(("fault_type", "drop"))).value, crate::metrics::OtelValue::Long(0));
    }

    #[test]
    fn otel_metrics_exporter_exports_slow_request_metrics() {
        // exportsJvmAndSlowRequestMetrics, the slow-request half
        let state = metrics_state();
        state.config.metrics.slow_request();
        let points = crate::metrics::otel_points(&state);
        let slow = otel_point(&points, "mock_server_slow_requests_total", None);
        assert!(slow.monotonic);
        assert_eq!(slow.value, crate::metrics::OtelValue::Long(1));
    }

    #[test]
    fn otel_metrics_exporter_exports_chaos_counter_by_fault_type() {
        let state = metrics_state();
        for fault in ["error", "error", "latency"] {
            state.config.metrics.chaos_injected(fault);
        }
        let points = crate::metrics::otel_points(&state);
        let error = otel_point(&points, "mock_server_http_chaos_injected_total", Some(("fault_type", "error")));
        assert!(error.monotonic, "an observable monotonic Sum, not a Gauge");
        assert_eq!(error.value, crate::metrics::OtelValue::Long(2));
        assert_eq!(otel_point(&points, "mock_server_http_chaos_injected_total", Some(("fault_type", "latency"))).value, crate::metrics::OtelValue::Long(1));
    }

    #[test]
    fn otel_metrics_exporter_exports_rate_limit_chaos_series_from_zero() {
        // `Metrics.CHAOS_FAULT_TYPES` has `rateLimit`; `ServiceChaosRegistry.FAULT_TYPES` (the active gauge) has not
        let state = metrics_state();
        let rate_limit = |points: &[crate::metrics::OtelPoint]| otel_point(points, "mock_server_http_chaos_injected_total", Some(("fault_type", "rateLimit"))).value;
        let points = crate::metrics::otel_points(&state);
        assert_eq!(rate_limit(&points), crate::metrics::OtelValue::Long(0));
        assert!(!points.iter().any(|p| p.name == "mock_server_active_service_chaos" && p.attributes.iter().any(|(_, v)| v == "rateLimit")));
        state.config.metrics.chaos_injected("rateLimit");
        assert_eq!(rate_limit(&crate::metrics::otel_points(&state)), crate::metrics::OtelValue::Long(1));
    }

    #[test]
    fn otel_metrics_exporter_exports_llm_optimisation_gauges() {
        let state = metrics_state();
        state.config.metrics.llm_optimisation((1.42, 0.5, 0.6667));
        let points = crate::metrics::otel_points(&state);
        for (name, value) in [("mock_server_llm_estimated_waste_usd", 1.42), ("mock_server_llm_cache_hit_ratio", 0.5), ("mock_server_llm_one_shot_rate", 0.6667)] {
            assert_eq!(otel_point(&points, name, None).value, crate::metrics::OtelValue::Double(value), "{name}");
        }
    }

    #[test]
    fn otel_metrics_exporter_exports_request_duration_histogram() {
        let metrics = crate::metrics::Metrics::default();
        metrics.otel_histograms_registered(true);
        metrics.request_handled(0.1);
        metrics.request_handled(0.25);
        let collected = metrics.collect_otel_histograms(false, now_nanos());
        let histogram = collected.iter().find(|h| h.name == "mock_server_request_duration_seconds").expect("mock_server_request_duration_seconds histogram not exported");
        assert!(histogram.histogram.count >= 2);
        assert_eq!(histogram.histogram.bucket_counts[1], 2, "both in the SDK's (0, 5] bucket");
        assert_eq!((histogram.histogram.min, histogram.histogram.max), (0.1, 0.25));
    }

    #[test]
    fn otel_metrics_exporter_stop_clears_otel_histogram_reference() {
        let metrics = crate::metrics::Metrics::default();
        metrics.otel_histograms_registered(true);
        metrics.request_handled(0.05);
        metrics.otel_histograms_registered(false);
        // after stop, observing does not fail and reaches the OTLP histogram no more
        metrics.request_handled(0.1);
        assert_eq!(metrics.collect_otel_histograms(false, now_nanos())[0].histogram.count, 1);
    }

    #[test]
    fn otel_metrics_exporter_counter_mirrors_surface_as_monotonic_sums_not_gauges() {
        let state = metrics_state();
        let points = crate::metrics::otel_points(&state);
        assert!(otel_point(&points, "mock_server_slow_requests_total", None).monotonic);
        assert!(otel_point(&points, "mock_server_http_chaos_injected_total", None).monotonic);
        assert!(!otel_point(&points, "mock_server_active_service_chaos", None).monotonic, "a genuine gauge stays a Gauge");
    }

    #[test]
    fn otel_metrics_exporter_delta_reader_reports_delta_for_counters_and_histogram_but_gauges_stay_gauges() {
        let metrics = crate::metrics::Metrics::default();
        metrics.otel_histograms_registered(true);
        metrics.request_handled(0.1);
        let first = metrics.collect_otel_histograms(true, 1_000);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].histogram.count, 1);
        assert!(metrics.collect_otel_histograms(true, 2_000).is_empty(), "a delta interval without values is left out");
        metrics.request_handled(0.2);
        let third = metrics.collect_otel_histograms(true, 3_000);
        assert_eq!((third[0].histogram.count, third[0].histogram.start_nanos), (1, 2_000), "the interval since the previous collection");
        assert_eq!(metrics.collect_otel_histograms(false, 4_000)[0].histogram.count, 2, "cumulative keeps every value");
    }

    #[test]
    fn otel_metrics_exporter_exports_monotonic_total_counters_as_monotonic_sums() {
        let state = metrics_state();
        let metrics = &state.config.metrics;
        metrics.increment(crate::metrics::Count::RequestsReceived);
        metrics.increment(crate::metrics::Count::RequestsReceived);
        metrics.increment(crate::metrics::Count::ForwardExpectationsMatched);
        let points = crate::metrics::otel_points(&state);
        for name in [
            "mock_server_requests_received_total",
            "mock_server_expectations_not_matched_total",
            "mock_server_response_expectations_matched_total",
            "mock_server_forward_expectations_matched_total",
            "mock_server_llm_chaos_injected_total",
        ] {
            assert!(otel_point(&points, name, None).monotonic, "{name}");
        }
        assert_eq!(otel_point(&points, "mock_server_requests_received_total", None).value, crate::metrics::OtelValue::Long(2));
        assert!(!otel_point(&points, "requests_received_count", None).monotonic, "the legacy _count gauge coexists");
    }

    #[test]
    fn otel_metrics_exporter_disabled_by_default() {
        let state = metrics_state();
        start_metrics(&state);
        state.config.metrics.request_handled(0.1);
        assert!(state.config.metrics.collect_otel_histograms(false, now_nanos()).is_empty(), "no exporter, no OTLP histogram");
    }

    // OtelEndpointConfigurationTest (upstream/mockserver/.../configuration/OtelEndpointConfigurationTest.java): the
    // environment is passed in rather than read, as upstream's `otelEndpointFallbackDefault` takes it.

    #[test]
    fn otel_endpoint_configuration_returns_mock_server_specific_value_when_set() {
        assert_eq!(resolve_otel_endpoint(Some("http://collector:4318"), Some("http://otel-standard:4318")), "http://collector:4318");
        let config = crate::Config::for_tests().with_property("otelEndpoint", "http://collector:4318");
        assert_eq!(otel_endpoint(&config), "http://collector:4318");
    }

    #[test]
    fn otel_endpoint_configuration_uses_standard_env_as_fallback_default_when_specific_unset() {
        assert_eq!(otel_endpoint_fallback_default(Some("http://otel-standard:4318")), "http://otel-standard:4318");
        assert_eq!(resolve_otel_endpoint(Some(""), Some("http://otel-standard:4318")), "http://otel-standard:4318");
        assert_eq!(metrics_endpoint(Some(&resolve_otel_endpoint(None, Some("http://otel-standard:4318")))).as_deref(), Some("http://otel-standard:4318/v1/metrics"));
    }

    #[test]
    fn otel_endpoint_configuration_falls_back_to_empty_when_standard_env_blank() {
        for env in [None, Some(""), Some("   ")] {
            assert_eq!(otel_endpoint_fallback_default(env), "", "{env:?}");
        }
    }

    #[test]
    fn otel_endpoint_configuration_resolves_empty_when_neither_specific_nor_standard_env_set() {
        let standard = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok().filter(|v| !v.trim().is_empty()).unwrap_or_default();
        assert_eq!(otel_endpoint(&crate::Config::for_tests()), standard);
        assert_eq!(resolve_otel_endpoint(None, None), "");
    }

    #[test]
    fn otel_endpoint_configuration_metrics_temporality_defaults_to_cumulative_and_honours_override() {
        // otelMetricsTemporalityDefaultsToCumulative, …HonoursSystemPropertyOverride, …RoundTripsViaSetter
        let effective = |config: &crate::Config| crate::config::effective_json(config)["otelMetricsTemporality"].clone();
        let unset = crate::Config::for_tests();
        assert_eq!(effective(&unset), "cumulative");
        assert!(!is_delta_temporality(unset.property("otelMetricsTemporality").as_deref()));
        let config = crate::Config::for_tests().with_property("otelMetricsTemporality", "delta");
        assert_eq!(effective(&config), "delta");
        assert!(is_delta_temporality(config.property("otelMetricsTemporality").as_deref()));
    }

    /// The OTLP histogram encoding: one `Histogram` metric per name with explicit bounds, unit `s` and temporality.
    #[test]
    fn otel_metrics_exporter_encodes_histograms() {
        let metrics = crate::metrics::Metrics::default();
        metrics.otel_histograms_registered(true);
        metrics.request_handled(0.0);
        metrics.request_handled(7.5);
        let histograms = metrics.collect_otel_histograms(false, 5);
        let h = &histograms[0].histogram;
        assert_eq!((h.bucket_counts[0], h.bucket_counts[2], h.bucket_counts.len()), (1, 1, 16), "(-inf, 0] and (5, 10]");
        let body = otlp::encode_metrics(&[], &histograms, 9, true);
        let has = |needle: &[u8]| body.windows(needle.len()).any(|w| w == needle);
        assert!(has(b"mock_server_request_duration_seconds"));
        assert!(has(&10000f64.to_le_bytes()), "the SDK's last explicit bound");
        assert!(has(&[0x10, 0x01]), "delta temporality");
    }

    /// `http.server.request.duration` is encoded with the semconv bounds, unit `s` and an int status code.
    #[test]
    fn otlp_encodes_the_http_server_duration_with_semconv_bounds() {
        let config = crate::Config::for_tests();
        config.metrics.otel_histograms_registered(true);
        let mut request = crate::metrics::HttpServerRequest::start(&config, "GET", false, "1.1").unwrap();
        request.answered(Some(204), None, None);
        drop(request);
        let histograms = config.metrics.collect_otel_histograms(false, 5);
        let body = otlp::encode_metrics(&[], &histograms, 9, false);
        let has = |needle: &[u8]| body.windows(needle.len()).any(|w| w == needle);
        assert!(has(b"http.server.request.duration") && has(b"Duration of HTTP server requests."));
        assert!(has(&7.5f64.to_le_bytes()) && !has(&10000f64.to_le_bytes()), "the semconv bounds, not the SDK's");
        let mut status = b"\x0a\x19http.response.status_code\x12\x03\x18".to_vec();
        status.extend([0xcc, 0x01]);
        assert!(has(&status), "AnyValue.int_value 204");
    }

    /// The connection instruments and the pool gauge under their OTLP names, `{connection}` units and an
    /// int `server.port`.
    #[test]
    fn otlp_encodes_the_connection_set() {
        let config = crate::Config::for_tests();
        config.metrics.otel_histograms_registered(true);
        let state = crate::state::State::new(config.clone(), Vec::new());
        let connection = crate::metrics::ServerConnection::open(&config, "tcp", true).unwrap();
        let pooled = crate::metrics::ForwardConnection::open(&config, "upstream.test", 443).unwrap();
        crate::metrics::tls_handshake(&config, 0.02, Ok(Some("1.2")));
        let points: Vec<_> = crate::metrics::otel_points(&state).into_iter().map(|p| (p, 1)).collect();
        drop((connection, pooled));
        let histograms = config.metrics.collect_otel_histograms(false, 5);
        let body = otlp::encode_metrics(&points, &histograms, 9, false);
        let has = |needle: &[u8]| body.windows(needle.len()).any(|w| w == needle);
        for name in ["mock_server.active_connections", "mock_server.connection.duration", "mock_server.tls_handshake.duration", "http.client.open_connections", "{connection}"] {
            assert!(has(name.as_bytes()), "{name}");
        }
        let mut port = b"\x0a\x0bserver.port\x12\x03\x18".to_vec();
        port.extend([0xbb, 0x03]);
        assert!(has(&port), "AnyValue.int_value 443");
    }

    /// One HTTP/1.1 request on its own connection; the response head and body.
    async fn put(port: u16, path: &str, body: &str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut c = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        c.write_all(format!("PUT {path} HTTP/1.1\r\nHost: localhost:{port}\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
        let mut out = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(5), c.read_to_end(&mut out)).await;
        String::from_utf8_lossy(&out).into_owned()
    }

    /// One OTLP/HTTP export received by a sink: its request head and body; answered 200.
    async fn receive_export(collector: &tokio::net::TcpListener) -> (String, Vec<u8>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut exported, _) = tokio::time::timeout(Duration::from_secs(10), collector.accept()).await.expect("an export within 10 s").unwrap();
        let mut raw = Vec::new();
        let mut buf = [0u8; 16384];
        loop {
            if let Some(end) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&raw[..end]).to_string();
                let length: usize = head.lines().find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse().unwrap())).unwrap();
                if raw.len() >= end + 4 + length {
                    let _ = exported.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n").await;
                    return (head, raw[end + 4..end + 4 + length].to_vec());
                }
            }
            let n = tokio::time::timeout(Duration::from_secs(5), exported.read(&mut buf)).await.expect("the export's body").unwrap();
            assert!(n > 0, "export connection closed early");
            raw.extend_from_slice(&buf[..n]);
        }
    }

    /// Under `otelMetricsEnabled` (`OtelMetricsExporter`), every `otelMetricsExportIntervalSeconds` the instruments
    /// reach `otelEndpoint` + `/v1/metrics` as OTLP protobuf (the docker_compose_metrics container case), load
    /// instruments included once a load scenario ran. `MOCK_SERVER_OTLP_DUMP=<file>` writes that export's body,
    /// which `scripts/verify-otlp-metrics.sh` decodes with opentelemetry-proto.
    #[tokio::test(flavor = "multi_thread")]
    async fn exports_metrics_as_otlp_protobuf() {
        let collector = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://127.0.0.1:{}", collector.local_addr().unwrap().port());
        let config = crate::Config::for_tests()
            .with_property("metricsEnabled", "true")
            .with_property("loadGenerationEnabled", "true")
            .with_property("otelMetricsEnabled", "true")
            .with_property("otelMetricsExportIntervalSeconds", "1")
            .with_property("otelEndpoint", &endpoint);
        let server = crate::Server::start(config).await.unwrap();
        let port = server.ports()[0];
        let (head, _) = receive_export(&collector).await;
        assert!(head.starts_with("POST /v1/metrics HTTP/1.1\r\n"), "{head}");
        assert!(head.to_ascii_lowercase().contains("content-type: application/x-protobuf"), "{head}");
        put(port, "/mockserver/expectation", r#"{"httpRequest":{"path":"/load/.*"},"httpResponse":{"body":"ok"}}"#).await;
        let scenario = format!(
            r#"{{"name":"otlp","labels":{{"team":"a"}},"steps":[{{"request":{{"method":"GET","path":"/load/x","socketAddress":{{"host":"localhost","port":{port},"scheme":"HTTP"}},"headers":{{"Host":["localhost:{port}"]}}}},"checks":[{{"source":"STATUS","comparator":"EQUALS","value":"200"}}]}}],"profile":{{"stages":[{{"vus":1,"durationMillis":3000}}]}},"maxRequests":3}}"#
        );
        let loaded = put(port, "/mockserver/loadScenario", &scenario).await;
        assert!(loaded.starts_with("HTTP/1.1 2"), "{loaded}");
        put(port, "/mockserver/loadScenario/start", r#"{"names":["otlp"]}"#).await;
        let has = |body: &[u8], needle: &str| body.windows(needle.len()).any(|w| w == needle.as_bytes());
        let mut body = Vec::new();
        for _ in 0..10 {
            body = receive_export(&collector).await.1;
            if has(&body, "mock_server_load_checks") {
                break;
            }
        }
        for needle in ["org.mockserver", "service.name", "requests_received_count", "mock_server_requests_received_total", "mock_server_http_chaos_injected_total", "fault_type",
            "mock_server_load_requests", "mock_server_load_response_bytes", "mock_server_load_iterations", "mock_server_load_checks", "status_class", "team",
            "mock_server_request_duration_seconds", "mock_server_load_request_duration_seconds", "service.version", "mock_server_native_build_info", "process.cpu.time", "cpu.mode"] {
            assert!(has(&body, needle), "{needle} missing from {}", String::from_utf8_lossy(&body));
        }
        if let Ok(path) = std::env::var("MOCK_SERVER_OTLP_DUMP") {
            std::fs::write(path, &body).unwrap();
        }
        server.shutdown().await;
    }

    /// Under `otelTracesEnabled`, the batch reaches `otelEndpoint` + `/v1/traces` as OTLP protobuf.
    /// `MOCK_SERVER_OTLP_TRACE_DUMP=<file>` writes that export's body, which `scripts/verify-otlp-trace.sh`
    /// decodes with opentelemetry-proto.
    #[tokio::test(flavor = "multi_thread")]
    async fn exports_spans_as_otlp_protobuf() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let collector = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://127.0.0.1:{}/", collector.local_addr().unwrap().port());
        let config = crate::Config::for_tests().with_property("otelTracesEnabled", "true").with_property("otelEndpoint", &endpoint);
        let server = crate::Server::start(config).await.unwrap();
        let port = server.ports()[0];
        let expectation = r#"{"httpRequest":{"path":"/hit"},"httpResponse":{"body":"ok"}}"#;
        let mut control = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        control
            .write_all(format!("PUT /mockserver/expectation HTTP/1.1\r\nHost: x\r\ncontent-length: {}\r\n\r\n{expectation}", expectation.len()).as_bytes())
            .await
            .unwrap();
        let mut sink = [0u8; 4096];
        let _ = control.read(&mut sink).await;
        control.write_all(b"GET /hit HTTP/1.1\r\nHost: x\r\ncontent-length: 0\r\n\r\n").await.unwrap();
        let _ = control.read(&mut sink).await;
        let (head, body) = receive_export(&collector).await;
        assert!(head.starts_with("POST /v1/traces HTTP/1.1\r\n"), "{head}");
        assert!(head.to_ascii_lowercase().contains("content-type: application/x-protobuf"), "{head}");
        for needle in ["org.mockserver", "service.name", "mockserver", "GET /hit", "mockserver.expectation_id", "http.response.status_code"] {
            assert!(body.windows(needle.len()).any(|w| w == needle.as_bytes()), "{needle} missing from body");
        }
        if let Ok(path) = std::env::var("MOCK_SERVER_OTLP_TRACE_DUMP") {
            std::fs::write(path, &body).unwrap();
        }
        server.shutdown().await;
    }
}
