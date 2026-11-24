//! `org.mockserver.metrics.Metrics` (`metricsEnabled`):
//! - the named counts `retrieve?type=METRICS` returns;
//! - their Prometheus exposition at `GET /mockserver/metrics` (`MetricsHandler`), with the monotonic `_total`
//!   counters, the request and forward histograms, build info and the scrape-time gauges.
//!
//! The per-action counts are the active expectations with that action, read when asked. The JVM collector has no
//! counterpart; the process's own figures are exposed as the standard `process_*` series in its place.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicI64, Ordering};

use parking_lot::Mutex;
use serde_json::{Map, Value};

pub mod process;
pub mod remote_write;

/// `Metrics.Name`, in declaration order (the order `retrieve?type=METRICS` lists them).
pub const NAMES: &[(&str, &str)] = &[
    ("REQUESTS_RECEIVED_COUNT", "Total requests received count"),
    ("EXPECTATIONS_NOT_MATCHED_COUNT", "Expectation not matched count"),
    ("RESPONSE_EXPECTATIONS_MATCHED_COUNT", "Response expectation matched count"),
    ("FORWARD_EXPECTATIONS_MATCHED_COUNT", "Forward expectation matched count"),
    ("FORWARD_ACTIONS_COUNT", "Action forward count"),
    ("FORWARD_TEMPLATE_ACTIONS_COUNT", "Action forward template count"),
    ("FORWARD_CLASS_CALLBACK_ACTIONS_COUNT", "Action forward class callback count"),
    ("FORWARD_OBJECT_CALLBACK_ACTIONS_COUNT", "Action forward object callback count"),
    ("FORWARD_REPLACE_ACTIONS_COUNT", "Action forward replace count"),
    ("FORWARD_VALIDATE_ACTIONS_COUNT", "Action forward validate count"),
    ("FORWARD_WITH_FALLBACK_ACTIONS_COUNT", "Action forward with fallback count"),
    ("RESPONSE_ACTIONS_COUNT", "Action response count"),
    ("RESPONSE_TEMPLATE_ACTIONS_COUNT", "Action response template count"),
    ("RESPONSE_CLASS_CALLBACK_ACTIONS_COUNT", "Action response class callback count"),
    ("RESPONSE_OBJECT_CALLBACK_ACTIONS_COUNT", "Action response object callback count"),
    ("SSE_RESPONSE_ACTIONS_COUNT", "Action SSE response count"),
    ("LLM_RESPONSE_ACTIONS_COUNT", "Action LLM response count"),
    ("LLM_CHAOS_INJECTED_COUNT", "Action LLM chaos injected count"),
    ("WEBSOCKET_RESPONSE_ACTIONS_COUNT", "Action WebSocket response count"),
    ("GRPC_STREAM_RESPONSE_ACTIONS_COUNT", "Action gRPC stream response count"),
    ("GRPC_BIDI_RESPONSE_ACTIONS_COUNT", "Action gRPC bidi response count"),
    ("BINARY_RESPONSE_ACTIONS_COUNT", "Action binary response count"),
    ("DNS_RESPONSE_ACTIONS_COUNT", "Action DNS response count"),
    ("ERROR_ACTIONS_COUNT", "Action error count"),
    ("WEBSOCKET_CALLBACK_CLIENTS_COUNT", "Websocket callback client count"),
    ("WEBSOCKET_CALLBACK_RESPONSE_HANDLERS_COUNT", "Websocket callback response handler count"),
    ("WEBSOCKET_CALLBACK_FORWARD_HANDLERS_COUNT", "Websocket callback forward handler count"),
];

/// The expectation action keys and their `Action.Type` names, with the count each one feeds.
const ACTIONS: &[(&str, &str, &str)] = &[
    ("httpResponse", "RESPONSE", "RESPONSE_ACTIONS_COUNT"),
    ("httpResponseTemplate", "RESPONSE_TEMPLATE", "RESPONSE_TEMPLATE_ACTIONS_COUNT"),
    ("httpResponseClassCallback", "RESPONSE_CLASS_CALLBACK", "RESPONSE_CLASS_CALLBACK_ACTIONS_COUNT"),
    ("httpResponseObjectCallback", "RESPONSE_OBJECT_CALLBACK", "RESPONSE_OBJECT_CALLBACK_ACTIONS_COUNT"),
    ("httpForward", "FORWARD", "FORWARD_ACTIONS_COUNT"),
    ("httpForwardTemplate", "FORWARD_TEMPLATE", "FORWARD_TEMPLATE_ACTIONS_COUNT"),
    ("httpForwardClassCallback", "FORWARD_CLASS_CALLBACK", "FORWARD_CLASS_CALLBACK_ACTIONS_COUNT"),
    ("httpForwardObjectCallback", "FORWARD_OBJECT_CALLBACK", "FORWARD_OBJECT_CALLBACK_ACTIONS_COUNT"),
    ("httpOverrideForwardedRequest", "FORWARD_REPLACE", "FORWARD_REPLACE_ACTIONS_COUNT"),
    ("httpForwardValidateAction", "FORWARD_VALIDATE", "FORWARD_VALIDATE_ACTIONS_COUNT"),
    ("httpForwardWithFallback", "FORWARD_WITH_FALLBACK", "FORWARD_WITH_FALLBACK_ACTIONS_COUNT"),
    ("httpSseResponse", "SSE_RESPONSE", "SSE_RESPONSE_ACTIONS_COUNT"),
    ("httpLlmResponse", "LLM_RESPONSE", "LLM_RESPONSE_ACTIONS_COUNT"),
    ("httpWebSocketResponse", "WEBSOCKET_RESPONSE", "WEBSOCKET_RESPONSE_ACTIONS_COUNT"),
    ("grpcStreamResponse", "GRPC_STREAM_RESPONSE", "GRPC_STREAM_RESPONSE_ACTIONS_COUNT"),
    ("grpcBidiResponse", "GRPC_BIDI_RESPONSE", "GRPC_BIDI_RESPONSE_ACTIONS_COUNT"),
    ("binaryResponse", "BINARY_RESPONSE", "BINARY_RESPONSE_ACTIONS_COUNT"),
    ("dnsResponse", "DNS_RESPONSE", "DNS_RESPONSE_ACTIONS_COUNT"),
    ("httpError", "ERROR", "ERROR_ACTIONS_COUNT"),
];

/// The four counts dual-published as monotonic `_total` counters (`MONOTONIC_TOTAL_COUNTER_NAMES`).
const MONOTONIC: &[(&str, &str)] = &[
    ("REQUESTS_RECEIVED_COUNT", "mock_server_requests_received"),
    ("EXPECTATIONS_NOT_MATCHED_COUNT", "mock_server_expectations_not_matched"),
    ("RESPONSE_EXPECTATIONS_MATCHED_COUNT", "mock_server_response_expectations_matched"),
    ("FORWARD_EXPECTATIONS_MATCHED_COUNT", "mock_server_forward_expectations_matched"),
    ("LLM_CHAOS_INJECTED_COUNT", "mock_server_llm_chaos_injected"),
];

const BUCKETS: &[f64] = &[0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0];
/// `Metrics.REQUEST_TRANSPORT_DURATION_BUCKETS`.
const TRANSPORT_BUCKETS: &[f64] = &[0.0005, 0.001, 0.002, 0.003, 0.005, 0.0075, 0.01, 0.015, 0.02, 0.03, 0.04, 0.05, 0.075, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0];
/// `Metrics.REQUEST_READ_TO_DECODE_DURATION_BUCKETS`.
const READ_TO_DECODE_BUCKETS: &[f64] =
    &[0.0001, 0.00025, 0.0005, 0.001, 0.002, 0.003, 0.005, 0.0075, 0.01, 0.015, 0.02, 0.03, 0.04, 0.05, 0.075, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0];
/// `ResponseWriteStall`: the (protocol, scope) series of `mock_server_response_write_stalls_total`, each exported
/// from the first scrape.
const RESPONSE_WRITE_STALLS: &[(&str, &str)] = &[
    ("http1_1", "connection"),
    ("http2", "connection"),
    ("http2", "stream"),
    ("http3", "stream"),
    ("other", "connection"),
    ("tunnel", "connection"),
    ("websocket", "connection"),
];
/// `MockServerEventLog.DropReason`'s labels, each exported from the first scrape.
const DROP_REASONS: &[&str] = &["in_flight_bytes", "ring_full"];
/// The OTel HTTP semconv's advised bucket boundaries for `http.server.request.duration`.
pub const HTTP_SERVER_BUCKETS: &[f64] = &[0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 7.5, 10.0];
/// The methods semconv knows (RFC 9110 and PATCH); any other is `_OTHER`.
const HTTP_METHODS: &[&str] = &["CONNECT", "DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT", "TRACE"];
/// `Metrics.CHAOS_FAULT_TYPES`: the `fault_type` labels `incrementHttpChaosInjected` counts, the service-profile
/// set and a declarative rate limit's `rateLimit` (`HttpActionHandler`'s two write funnels).
const CHAOS_FAULT_TYPES: &[&str] = &["drop", "error", "graphql", "latency", "malformed", "quota", "slow", "truncate", "rateLimit"];
/// `ServiceChaosRegistry.FAULT_TYPES`: a service chaos profile's fault types, which have no `rateLimit`.
const SERVICE_CHAOS_FAULT_TYPES: &[&str] = &["drop", "error", "graphql", "latency", "malformed", "quota", "slow", "truncate"];

#[derive(Clone)]
struct Histogram {
    /// The upper bounds of its buckets but `+Inf`: upstream's [`BUCKETS`], or the semconv [`HTTP_SERVER_BUCKETS`].
    bounds: &'static [f64],
    buckets: Vec<u64>,
    count: u64,
    sum: f64,
    /// `withExemplars()`: each bucket's (and `+Inf`'s) exemplar, empty when none was ever observed.
    exemplars: Vec<Option<Exemplar>>,
    /// When `ExemplarSampler.rateLimitedObserve` accepts the next exemplar again (milliseconds since the epoch).
    exemplars_open_at: i64,
}

/// `ExemplarSamplerConfig`'s defaults: a bucket's exemplar stays at least the minimum retention, is dropped after the
/// maximum, and one observation with an exemplar closes the sampler for the sample interval.
const EXEMPLAR_MIN_RETENTION_MILLIS: i64 = 7_000;
const EXEMPLAR_MAX_RETENTION_MILLIS: i64 = 70_000;
const EXEMPLAR_SAMPLE_INTERVAL_MILLIS: i64 = 90;

/// An exemplar of a classic histogram bucket (`observeWithExemplar`): its labels, value and time.
#[derive(Debug, Clone, PartialEq)]
pub struct Exemplar {
    pub labels: Attributes,
    pub value: f64,
    pub timestamp_millis: i64,
}

impl Default for Histogram {
    fn default() -> Histogram {
        Histogram::with_bounds(BUCKETS)
    }
}

impl Histogram {
    fn with_bounds(bounds: &'static [f64]) -> Histogram {
        Histogram { bounds, buckets: Vec::new(), count: 0, sum: 0.0, exemplars: Vec::new(), exemplars_open_at: 0 }
    }

    fn observe(&mut self, seconds: f64) {
        if self.buckets.is_empty() {
            self.buckets = vec![0; self.bounds.len()];
        }
        for (i, bound) in self.bounds.iter().enumerate() {
            if seconds <= *bound {
                self.buckets[i] += 1;
            }
        }
        self.count += 1;
        self.sum += seconds;
    }

    /// `observeWithExemplar`: the observation, and `ExemplarSampler.observeWithExemplar`'s choice for its bucket: the
    /// exemplar replaces one older than the minimum retention, and none is taken while the sampler is closed (the
    /// sample interval after the last one offered, as the sampler's own exemplars, which it measures, stay empty).
    fn observe_with_exemplar(&mut self, seconds: f64, exemplar: Exemplar) {
        self.observe(seconds);
        let now = exemplar.timestamp_millis;
        if seconds.is_nan() || now < self.exemplars_open_at {
            return;
        }
        if self.exemplars.is_empty() {
            self.exemplars = vec![None; self.bounds.len() + 1];
        }
        let bucket = self.bounds.iter().position(|bound| seconds <= *bound).unwrap_or(self.bounds.len());
        if self.exemplars[bucket].as_ref().is_none_or(|previous| now - previous.timestamp_millis > EXEMPLAR_MIN_RETENTION_MILLIS) {
            self.exemplars[bucket] = Some(exemplar);
        }
        self.exemplars_open_at = now + EXEMPLAR_SAMPLE_INTERVAL_MILLIS;
    }

    /// `ExemplarSampler.collect`: the exemplars younger than the maximum retention.
    fn live_exemplars(&self) -> Vec<Option<Exemplar>> {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis() as i64);
        self.exemplars.iter().map(|e| e.clone().filter(|e| now - e.timestamp_millis <= EXEMPLAR_MAX_RETENTION_MILLIS)).collect()
    }
}

#[derive(Default)]
struct Series {
    request_duration: Histogram,
    /// `mock_server_request_transport_duration_seconds` and `mock_server_request_read_to_decode_duration_seconds`,
    /// made on their first observation (an empty one is exported all the same).
    request_transport_duration: Option<Histogram>,
    request_read_to_decode_duration: Option<Histogram>,
    /// `mock_server_request_duration_by_method_seconds` (`metricsRequestDurationRouteLabels`, read at startup).
    request_duration_by_method: BTreeMap<String, Histogram>,
    forward_duration: BTreeMap<String, Histogram>,
    forward_requests: BTreeMap<(String, String), u64>,
    forward_protocol: BTreeMap<(String, String), u64>,
    /// The `upstream_host` labels handed out so far (`forwardHostLabels`), at most `MAX_FORWARD_HOST_LABELS`.
    forward_host_labels: std::collections::BTreeSet<String>,
    slow_requests: u64,
    /// The `mock_server_load_*` counters (`observeLoadRequest`, `incrementLoad*`), by name and attributes (OTLP).
    load: BTreeMap<(&'static str, Attributes), i64>,
    /// Their Prometheus twins by name and labels (sorted by name, as `Labels` sorts them): the per-request ones carry
    /// the six fixed labels and the `loadGenerationMetricLabels` allowlist only. Evicted per run (`evictLoadRun`).
    load_prometheus: BTreeMap<(&'static str, Attributes), f64>,
    /// `mock_server_load_request_duration_seconds` by the same per-request labels.
    load_duration: BTreeMap<Attributes, Histogram>,
    /// `mock_server_http_chaos_injected_total` by fault type.
    http_chaos_injected: BTreeMap<String, u64>,
    chaos_auto_halts: u64,
    /// `mock_server_websocket_read_pauses_total` (`incrementWebSocketReadPauses`).
    websocket_read_pauses: u64,
    /// `mock_server_inbound_connections_rejected_total` / `…_idle_closed_total` (`incrementInboundConnectionsRejected`,
    /// `incrementInboundConnectionsIdleClosed`).
    inbound_rejected: u64,
    inbound_idle_closed: u64,
    /// `mock_server_http1_pipelining_wedged_connections_total` (`incrementHttp1PipeliningWedgedConnections`, 9.2.0
    /// #74): connections whose pipelined requests waited behind a response that made no progress.
    http1_pipelining_wedged: u64,
    /// `mock_server_response_write_stalls_total` by (protocol, scope) (`incrementResponseWriteStalls`).
    response_write_stalls: BTreeMap<(&'static str, &'static str), u64>,
    /// `mock_server_async_messages_published_total` / `…_consumed_total` by channel.
    async_published: BTreeMap<String, u64>,
    async_consumed: BTreeMap<String, u64>,
    /// `mock_server_expectation_matched_total` by expectation id (`perExpectationMetricsEnabled`).
    expectation_matched: BTreeMap<String, u64>,
    /// `mock_server_mcp_tool_calls_total` by tool name.
    mcp_tool_calls: BTreeMap<String, u64>,
    /// `mock_server_llm_input_tokens_total`, `…_output_tokens_total` and `…_cost_usd_total` by (provider, model)
    /// (`llmMetricsEnabled`).
    llm_input_tokens: BTreeMap<(String, String), f64>,
    llm_output_tokens: BTreeMap<(String, String), f64>,
    llm_cost_usd: BTreeMap<(String, String), f64>,
    /// The OTLP twins of the two duration histograms, kept once the OTLP exporter started
    /// (`registerOtelRequestDurationHistogram`, `registerOtelLoadInstruments`), the load one by sorted attributes.
    otel_request_duration: Option<OtelSeries>,
    otel_load_duration: BTreeMap<Attributes, OtelSeries>,
    /// When the OTLP reader last collected (nanoseconds since the epoch), 0 before its first collection.
    otel_collected_nanos: u64,
    /// `http_server_request_duration_seconds` by its Prometheus labels (sorted, unset ones absent), and its OTLP twin
    /// `http.server.request.duration` by its semconv attributes, kept once the OTLP exporter started.
    http_server_duration: BTreeMap<Attributes, Histogram>,
    otel_http_server_duration: BTreeMap<Attributes, OtelSeries>,
    /// `http_server_active_requests` by (method, scheme).
    http_server_active: BTreeMap<(&'static str, &'static str), i64>,
    /// `mock_server_active_connections` by (transport, TLS) ([`ServerConnection`]).
    connections_active: BTreeMap<(&'static str, bool), i64>,
    /// `mock_server_connection_duration_seconds` and `mock_server_tls_handshake_duration_seconds` by their
    /// Prometheus labels, and their OTLP twins by semconv-style attributes, kept once the OTLP exporter started.
    connection_duration: BTreeMap<Attributes, Histogram>,
    otel_connection_duration: BTreeMap<Attributes, OtelSeries>,
    tls_handshake_duration: BTreeMap<Attributes, Histogram>,
    otel_tls_handshake_duration: BTreeMap<Attributes, OtelSeries>,
    /// `http_client_open_connections` by (`http.connection.state`, server address, server port) ([`ForwardConnection`]).
    forward_pool_open: BTreeMap<(&'static str, String, u16), i64>,
}

/// The OpenTelemetry SDK's default explicit bucket boundaries (`ExplicitBucketHistogramUtils`), which upstream's two
/// histograms keep, since they set no boundary advice.
pub const OTEL_BOUNDS: [f64; 15] = [0.0, 5.0, 10.0, 25.0, 50.0, 75.0, 100.0, 250.0, 500.0, 750.0, 1000.0, 2500.0, 5000.0, 7500.0, 10000.0];

/// An OTel explicit-bucket histogram aggregation: per-bucket counts (a value lands in the first bucket whose bound is
/// not below it, the last bucket unbounded), count, sum, min and max, and when its first value was recorded.
#[derive(Debug, Clone, PartialEq)]
pub struct OtelHistogram {
    /// The explicit bounds: the SDK's default [`OTEL_BOUNDS`], or the semconv advice [`HTTP_SERVER_BUCKETS`].
    pub bounds: &'static [f64],
    pub bucket_counts: Vec<u64>,
    pub count: u64,
    pub sum: f64,
    pub min: f64,
    pub max: f64,
    pub start_nanos: u64,
}

impl OtelHistogram {
    fn new(start_nanos: u64, bounds: &'static [f64]) -> OtelHistogram {
        OtelHistogram { bounds, bucket_counts: vec![0; bounds.len() + 1], count: 0, sum: 0.0, min: f64::INFINITY, max: f64::NEG_INFINITY, start_nanos }
    }

    fn record(&mut self, value: f64) {
        let bucket = self.bounds.iter().position(|bound| value <= *bound).unwrap_or(self.bounds.len());
        self.bucket_counts[bucket] += 1;
        self.count += 1;
        self.sum += value;
        self.min = self.min.min(value);
        self.max = self.max.max(value);
    }
}

/// One OTLP histogram series: everything since its first value (cumulative) and since the last collection (delta).
#[derive(Debug, Clone)]
struct OtelSeries {
    cumulative: OtelHistogram,
    interval: Option<OtelHistogram>,
}

impl OtelSeries {
    fn new(now: u64) -> OtelSeries {
        OtelSeries::with_bounds(now, &OTEL_BOUNDS)
    }

    fn with_bounds(now: u64, bounds: &'static [f64]) -> OtelSeries {
        OtelSeries { cumulative: OtelHistogram::new(now, bounds), interval: None }
    }

    fn record(&mut self, value: f64, now: u64) {
        self.cumulative.record(value);
        let bounds = self.cumulative.bounds;
        self.interval.get_or_insert_with(|| OtelHistogram::new(now, bounds)).record(value);
    }
}

/// One data point of an OTLP histogram instrument, as a collection reads it.
#[derive(Debug, Clone)]
pub struct OtelHistogramPoint {
    pub name: &'static str,
    pub description: &'static str,
    pub attributes: Attributes,
    pub histogram: OtelHistogram,
}

fn now_nanos() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_nanos() as u64)
}

/// The counts (`Metrics`), shared by a server's configuration.
#[derive(Default)]
pub struct Metrics {
    /// The gauge-backed counts, reset by `reset` (`clearRequestAndExpectationMetrics`).
    counts: [AtomicI64; 5],
    /// Their monotonic `_total` twins, never reset.
    totals: [AtomicI64; 5],
    series: Mutex<Series>,
    /// `updateLlmOptimisationSnapshot`: estimated waste, cache-hit ratio and one-shot rate of the latest report.
    llm_optimisation: Mutex<(f64, f64, f64)>,
    /// `LlmCostBudgetMonitor` (`llmCostBudgetUsd`), counted whether or not metrics are enabled.
    pub cost_budget: crate::llm::budget::CostBudget,
    /// The OTLP exporter is running (`OtelMetricsExporter.startWithReader` registered its histograms; `stop` clears them).
    otel_histograms: std::sync::atomic::AtomicBool,
}

impl std::fmt::Debug for Metrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Metrics")
    }
}

/// One of the imperatively counted names.
#[derive(Clone, Copy)]
pub enum Count {
    RequestsReceived = 0,
    ExpectationsNotMatched = 1,
    ResponseExpectationsMatched = 2,
    ForwardExpectationsMatched = 3,
    LlmChaosInjected = 4,
}

impl Metrics {
    pub fn increment(&self, count: Count) {
        self.counts[count as usize].fetch_add(1, Ordering::Relaxed);
        self.totals[count as usize].fetch_add(1, Ordering::Relaxed);
    }

    /// `clearRequestAndExpectationMetrics`: three of the gauges (requests received, not matched, response matched);
    /// the forward-matched and LLM-chaos gauges and every `_total` counter keep counting.
    pub fn reset(&self) {
        for c in [Count::RequestsReceived, Count::ExpectationsNotMatched, Count::ResponseExpectationsMatched] {
            self.counts[c as usize].store(0, Ordering::Relaxed);
        }
        // `HttpState.reset` also resets `LlmCostBudgetMonitor` (its Prometheus trip counter stays).
        self.cost_budget.reset();
    }

    pub fn llm_optimisation(&self, snapshot: (f64, f64, f64)) {
        *self.llm_optimisation.lock() = snapshot;
    }

    /// `observeRequestDurationSeconds`: the Prometheus histogram, and its OTLP twin while the exporter runs.
    pub fn request_handled(&self, seconds: f64) {
        let mut series = self.series.lock();
        series.request_duration.observe(seconds);
        if self.otel_histograms.load(Ordering::Relaxed) {
            let now = now_nanos();
            series.otel_request_duration.get_or_insert_with(|| OtelSeries::new(now)).record(seconds, now);
        }
    }

    /// `OtelMetricsExporter.startWithReader` / `stop`: the OTLP histograms record from now on, or no longer.
    pub fn otel_histograms_registered(&self, registered: bool) {
        self.otel_histograms.store(registered, Ordering::Relaxed);
    }

    /// A collection of the OTLP histograms at `now`: with `delta`, each series' values since the previous collection
    /// (a series without any is left out, as the SDK leaves it out), else everything since its first value.
    pub fn collect_otel_histograms(&self, delta: bool, now: u64) -> Vec<OtelHistogramPoint> {
        let mut series = self.series.lock();
        let previous = std::mem::replace(&mut series.otel_collected_nanos, now);
        let take = |s: &mut OtelSeries| {
            let interval = s.interval.take();
            match delta {
                true => interval.map(|mut h| {
                    if previous > 0 {
                        h.start_nanos = previous;
                    }
                    h
                }),
                false => Some(s.cumulative.clone()),
            }
        };
        let mut out = Vec::new();
        if let Some(h) = series.otel_request_duration.as_mut().and_then(take) {
            out.push(OtelHistogramPoint { name: "mock_server_request_duration_seconds", description: "MockServer request handling duration in seconds", attributes: Vec::new(), histogram: h });
        }
        let load: Vec<(Attributes, OtelHistogram)> = series.otel_load_duration.iter_mut().filter_map(|(a, s)| Some((a.clone(), take(s)?))).collect();
        for (attributes, histogram) in load {
            out.push(OtelHistogramPoint { name: "mock_server_load_request_duration_seconds", description: "Load-scenario request duration in seconds", attributes, histogram });
        }
        let http: Vec<(Attributes, OtelHistogram)> = series.otel_http_server_duration.iter_mut().filter_map(|(a, s)| Some((a.clone(), take(s)?))).collect();
        for (attributes, histogram) in http {
            out.push(OtelHistogramPoint { name: "http.server.request.duration", description: "Duration of HTTP server requests.", attributes, histogram });
        }
        let connections: Vec<(Attributes, OtelHistogram)> = series.otel_connection_duration.iter_mut().filter_map(|(a, s)| Some((a.clone(), take(s)?))).collect();
        for (attributes, histogram) in connections {
            out.push(OtelHistogramPoint { name: "mock_server.connection.duration", description: CONNECTION_DURATION_HELP, attributes, histogram });
        }
        let handshakes: Vec<(Attributes, OtelHistogram)> = series.otel_tls_handshake_duration.iter_mut().filter_map(|(a, s)| Some((a.clone(), take(s)?))).collect();
        for (attributes, histogram) in handshakes {
            out.push(OtelHistogramPoint { name: "mock_server.tls_handshake.duration", description: TLS_HANDSHAKE_HELP, attributes, histogram });
        }
        out
    }

    /// The by-method twin of [`Metrics::request_handled`], kept only when `metricsRequestDurationRouteLabels` was on at startup.
    pub fn request_handled_by_method(&self, method: &str, seconds: f64) {
        self.series.lock().request_duration_by_method.entry(method.to_string()).or_default().observe(seconds);
    }

    /// `observeRequestTransportDurationSeconds`: from a request's head being decoded to its response written.
    pub fn request_transport(&self, seconds: f64) {
        self.series.lock().request_transport_duration.get_or_insert_with(|| Histogram::with_bounds(TRANSPORT_BUCKETS)).observe(seconds.max(0.0));
    }

    /// `observeRequestReadToDecodeDurationSeconds`: from the read that delivered a request's first bytes to its head
    /// being decoded (HTTP/1.1).
    pub fn request_read_to_decode(&self, seconds: f64) {
        self.series.lock().request_read_to_decode_duration.get_or_insert_with(|| Histogram::with_bounds(READ_TO_DECODE_BUCKETS)).observe(seconds.max(0.0));
    }

    /// `Metrics.incrementSlowRequestTotal`: a forward slower than `slowRequestThresholdMillis`.
    pub fn slow_request(&self) {
        self.series.lock().slow_requests += 1;
    }

    /// `observeForwardRequest`: a forwarded or proxied request's latency and response status, by upstream host
    /// (`unknown` when empty) and status class (`unknown` outside 100–599).
    pub fn forwarded(&self, host: &str, seconds: f64, status: u32) {
        let mut series = self.series.lock();
        let host = host_label(&mut series.forward_host_labels, host);
        series.forward_duration.entry(host.clone()).or_default().observe(seconds.max(0.0));
        *series.forward_requests.entry((status_class(status), host)).or_default() += 1;
    }

    /// `getForwardRequestCount`.
    pub fn forward_request_count(&self, host: &str, status_class: &str) -> u64 {
        self.series.lock().forward_requests.get(&(status_class.to_string(), host.to_string())).copied().unwrap_or(0)
    }

    /// `HttpClientInitializer`: a new upstream connection and the protocol it negotiated.
    pub fn upstream_connection(&self, host: &str, http2: bool) {
        let protocol = if http2 { "http2" } else { "http1_1" };
        let mut series = self.series.lock();
        let host = host_label(&mut series.forward_host_labels, host);
        *series.forward_protocol.entry((protocol.to_string(), host)).or_default() += 1;
    }

    /// `forwardUpstreamProtocolCount`.
    pub fn upstream_protocol_count(&self, host: &str, protocol: &str) -> u64 {
        self.series.lock().forward_protocol.get(&(protocol.to_string(), host.to_string())).copied().unwrap_or(0)
    }

    /// `getAsyncMessagePublishedCount` / `getAsyncMessageConsumedCount`.
    pub fn async_message_count(&self, published: bool, channel: &str) -> u64 {
        let series = self.series.lock();
        let counts = if published { &series.async_published } else { &series.async_consumed };
        counts.get(channel).copied().unwrap_or(0)
    }

    /// `getMonotonicTotalCount`: a dual-published `_total` counter's value.
    pub fn total(&self, count: Count) -> i64 {
        self.totals[count as usize].load(Ordering::Relaxed)
    }

    /// `incrementHttpChaosInjected`.
    pub fn chaos_injected(&self, fault: &str) {
        *self.series.lock().http_chaos_injected.entry(fault.to_string()).or_default() += 1;
    }

    /// `incrementChaosAutoHalt`.
    pub fn chaos_auto_halted(&self) {
        self.series.lock().chaos_auto_halts += 1;
    }

    /// `incrementResponseWriteStalls`: a response cut by `responseWriteStallTimeoutMillis`, by its `protocol` and
    /// `scope` labels (one of [`RESPONSE_WRITE_STALLS`]).
    pub fn response_write_stalled(&self, protocol: &'static str, scope: &'static str) {
        *self.series.lock().response_write_stalls.entry((protocol, scope)).or_default() += 1;
    }

    /// `incrementWebSocketReadPauses`: a mocked WebSocket stopped reading for too many pending reply sets.
    pub fn websocket_read_paused(&self) {
        self.series.lock().websocket_read_pauses += 1;
    }

    /// `incrementInboundConnectionsRejected`: a connection closed on accept by `maxInboundConnections`.
    pub fn inbound_connection_rejected(&self) {
        self.series.lock().inbound_rejected += 1;
    }

    /// `incrementInboundConnectionsIdleClosed`: a connection closed by `inboundConnectionIdleTimeoutMillis`.
    pub fn inbound_connection_idle_closed(&self) {
        self.series.lock().inbound_idle_closed += 1;
    }

    pub fn http1_pipelining_wedged_connection(&self) {
        self.series.lock().http1_pipelining_wedged += 1;
    }

    /// `incrementLoadIteration` / `incrementLoadThrottled` / `incrementLoadError` / `incrementLoadCheck`: adds `by` to
    /// a `mock_server_load_*` counter, whose OTLP attributes and Prometheus labels are the same.
    pub fn load_count(&self, name: &'static str, attributes: Attributes, by: i64) {
        let mut series = self.series.lock();
        *series.load_prometheus.entry((name, sorted(attributes.clone()))).or_default() += by as f64;
        *series.load.entry((name, otel_attributes(attributes))).or_default() += by;
    }

    /// `observeLoadRequest`: one completed load request. `fixed` is the six structured label values, in
    /// `LOAD_FIXED_LABELS` order; `custom` the merged scenario and step labels, all of which go to OTLP while
    /// Prometheus gets only the `allowlist` names (`""` when absent). The duration histogram takes an exemplar when
    /// the request carried a trace id. Byte counts that are not positive are not added.
    #[allow(clippy::too_many_arguments)]
    pub fn observe_load_request(
        &self,
        allowlist: &[String],
        fixed: [&str; 6],
        custom: &[(String, String)],
        latency_seconds: f64,
        request_bytes: i64,
        response_bytes: i64,
        trace_id: Option<&str>,
    ) {
        let latency = latency_seconds.max(0.0);
        let fixed: Attributes = LOAD_FIXED_LABELS.iter().zip(fixed).map(|(k, v)| (k.to_string(), v.to_string())).collect();
        let mut labels = fixed.clone();
        for name in allowlist {
            let value = custom.iter().find(|(k, _)| k == name).map_or("", |(_, v)| v.as_str());
            labels.push((name.clone(), value.to_string()));
        }
        let labels = sorted(labels);
        let attributes = otel_attributes(fixed.into_iter().chain(custom.iter().cloned()));
        let mut series = self.series.lock();
        if self.otel_histograms.load(Ordering::Relaxed) {
            let now = now_nanos();
            series.otel_load_duration.entry(attributes.clone()).or_insert_with(|| OtelSeries::new(now)).record(latency, now);
        }
        let histogram = series.load_duration.entry(labels.clone()).or_default();
        match trace_id.filter(|t| !t.is_empty()) {
            Some(trace_id) => {
                let timestamp_millis = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis() as i64);
                histogram.observe_with_exemplar(latency, Exemplar { labels: vec![("trace_id".into(), trace_id.into())], value: latency, timestamp_millis });
            }
            None => histogram.observe(latency),
        }
        for (name, by) in [("mock_server_load_requests", 1), ("mock_server_load_request_bytes", request_bytes), ("mock_server_load_response_bytes", response_bytes)] {
            if by > 0 {
                *series.load_prometheus.entry((name, labels.clone())).or_default() += by as f64;
                *series.load.entry((name, attributes.clone())).or_default() += by;
            }
        }
    }

    /// `evictLoadRun`: drops every Prometheus `mock_server_load_*` series of the run (the OTLP ones stay).
    pub fn evict_load_run(&self, run_id: &str) {
        let of_run = |labels: &Attributes| labels.iter().any(|(k, v)| k == "run_id" && v == run_id);
        let mut series = self.series.lock();
        series.load_prometheus.retain(|(_, labels), _| !of_run(labels));
        series.load_duration.retain(|labels, _| !of_run(labels));
    }

    /// `incrementAsyncMessagePublished` / `incrementAsyncMessageConsumed`.
    pub fn async_message(&self, published: bool, channel: &str) {
        let mut series = self.series.lock();
        let counts = if published { &mut series.async_published } else { &mut series.async_consumed };
        *counts.entry(channel.to_string()).or_default() += 1;
    }

    /// `incrementExpectationMatched`: a match of the expectation `id`, counted when [`per_expectation_enabled`].
    pub fn expectation_matched(&self, id: &str) {
        *self.series.lock().expectation_matched.entry(id.to_string()).or_default() += 1;
    }

    /// `getExpectationMatchedCount`: 0 for an id never matched.
    pub fn expectation_matched_count(&self, id: &str) -> u64 {
        self.series.lock().expectation_matched.get(id).copied().unwrap_or(0)
    }

    /// `incrementMcpToolCall`: a completed tool invocation.
    pub fn mcp_tool_call(&self, tool: &str) {
        *self.series.lock().mcp_tool_calls.entry(tool.to_string()).or_default() += 1;
    }

    /// `getMcpToolCallCount`.
    pub fn mcp_tool_call_count(&self, tool: &str) -> u64 {
        self.series.lock().mcp_tool_calls.get(tool).copied().unwrap_or(0)
    }

    /// `incrementLlmTokens`: the provider label lower-cased, a missing provider or model `unknown`; counts that are
    /// not positive (and an unknown cost) are not added. Called only when [`llm_metrics_enabled`].
    pub fn llm_tokens(&self, provider: Option<&str>, model: Option<&str>, input_tokens: i64, output_tokens: i64, cost_usd: Option<f64>) {
        let provider = provider.filter(|p| !p.is_empty()).map_or_else(|| "unknown".to_string(), str::to_lowercase);
        let model = model.filter(|m| !m.is_empty()).unwrap_or("unknown").to_string();
        let key = (provider, model);
        let mut series = self.series.lock();
        if input_tokens > 0 {
            *series.llm_input_tokens.entry(key.clone()).or_default() += input_tokens as f64;
        }
        if output_tokens > 0 {
            *series.llm_output_tokens.entry(key.clone()).or_default() += output_tokens as f64;
        }
        if let Some(cost) = cost_usd.filter(|c| *c > 0.0) {
            *series.llm_cost_usd.entry(key).or_default() += cost;
        }
    }

    /// `getLlmInputTokens` / `getLlmOutputTokens` / `getLlmCostUsd` (the provider matched lower-cased), and
    /// `getLlmCostUsdTotal` summed over every provider and model.
    pub fn llm_usage(&self, provider: &str, model: &str) -> (i64, i64, f64) {
        let series = self.series.lock();
        let key = (provider.to_lowercase(), model.to_string());
        let get = |m: &BTreeMap<(String, String), f64>| m.get(&key).copied().unwrap_or(0.0);
        (get(&series.llm_input_tokens) as i64, get(&series.llm_output_tokens) as i64, get(&series.llm_cost_usd))
    }

    pub fn llm_cost_usd_total(&self) -> f64 {
        self.series.lock().llm_cost_usd.values().sum()
    }

    /// `http_server_active_requests`: one more request in flight.
    fn http_server_started(&self, method: &'static str, scheme: &'static str) {
        *self.series.lock().http_server_active.entry((method, scheme)).or_default() += 1;
    }

    /// One completed request into `http_server_request_duration_seconds`, and its OTLP twin while the exporter runs;
    /// it is no longer active.
    fn http_server_observe(&self, r: &HttpServerRequest, seconds: f64) {
        let status = r.status.map(|s| s.to_string());
        // semconv: the status code when it says the server failed (5xx), else why no response was sent
        let error = r.error.map(str::to_string).or_else(|| status.clone().filter(|_| r.status.is_some_and(|s| s >= 500)));
        let fields = [
            ("error", "type", error),
            ("http", "request.method", Some(r.method.to_string())),
            ("http", "response.status_code", status),
            ("http", "route", r.route.map(str::to_string)),
            ("network", "protocol.name", Some("http".to_string())),
            ("network", "protocol.version", Some(r.version.to_string())),
            ("url", "scheme", Some(r.scheme.to_string())),
        ];
        let set = || fields.iter().filter_map(|(ns, name, v)| Some((ns, name, v.clone()?)));
        let labels: Attributes = sorted(set().map(|(ns, name, v)| (format!("{ns}_{}", name.replace('.', "_")), v)).collect());
        let mut series = self.series.lock();
        if self.otel_histograms.load(Ordering::Relaxed) {
            let attributes = otel_attributes(set().map(|(ns, name, v)| (format!("{ns}.{name}"), v)));
            let now = now_nanos();
            series.otel_http_server_duration.entry(attributes).or_insert_with(|| OtelSeries::with_bounds(now, HTTP_SERVER_BUCKETS)).record(seconds, now);
        }
        series.http_server_duration.entry(labels).or_insert_with(|| Histogram::with_bounds(HTTP_SERVER_BUCKETS)).observe(seconds);
        *series.http_server_active.entry((r.method, r.scheme)).or_default() -= 1;
    }
}

/// One HTTP server request under the OTel HTTP semantic conventions: counted in
/// `http_server_active_requests` while it lives, observed once into `http_server_request_duration_seconds` when it is
/// dropped, with what [`HttpServerRequest::answered`] said, or `error_type="cancelled"` when nothing did (the
/// exchange was abandoned before an answer: the client reset the stream, or the server stopped). A transport starts
/// one as it hands a request to the handler and drops it once the response is written.
pub struct HttpServerRequest {
    metrics: std::sync::Arc<Metrics>,
    started: std::time::Instant,
    method: &'static str,
    scheme: &'static str,
    version: &'static str,
    answered: bool,
    status: Option<u32>,
    route: Option<&'static str>,
    error: Option<&'static str>,
}

impl HttpServerRequest {
    /// A request with this method over this scheme and HTTP version (`1.1`, `2`, `3`), measured while `metricsEnabled`
    /// or the OTLP exporter runs; `None` otherwise.
    pub fn start(config: &crate::config::Config, method: &str, secure: bool, version: &'static str) -> Option<HttpServerRequest> {
        let metrics = &config.metrics;
        if !enabled(config) && !metrics.otel_histograms.load(Ordering::Relaxed) {
            return None;
        }
        let method = HTTP_METHODS.iter().find(|m| **m == method).copied().unwrap_or("_OTHER");
        let scheme = if secure { "https" } else { "http" };
        metrics.http_server_started(method, scheme);
        Some(HttpServerRequest { metrics: metrics.clone(), started: std::time::Instant::now(), method, scheme, version, answered: false, status: None, route: None, error: None })
    }

    /// How the request ended: the status code sent, the control-plane operation that answered it, and when no
    /// response was sent, why (`error_type`).
    pub fn answered(&mut self, status: Option<u32>, route: Option<&'static str>, error: Option<&'static str>) {
        (self.answered, self.status, self.route, self.error) = (true, status, route, error);
    }
}

impl Drop for HttpServerRequest {
    fn drop(&mut self) {
        if !self.answered {
            self.error = Some("cancelled");
        }
        self.metrics.http_server_observe(self, self.started.elapsed().as_secs_f64());
    }
}

/// Kestrel's advised bucket boundaries for `kestrel.connection.duration`, which ours follows; a TLS handshake takes [`HTTP_SERVER_BUCKETS`], as `kestrel.tls_handshake.duration` does.
pub const CONNECTION_BUCKETS: &[f64] = &[0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0];
const ACTIVE_CONNECTIONS_HELP: &str = "Number of connections that are currently active on the server.";
const CONNECTION_DURATION_HELP: &str = "The duration of connections on the server.";
const TLS_HANDSHAKE_HELP: &str = "The duration of TLS handshakes on the server.";
const FORWARD_POOL_HELP: &str = "Number of outbound HTTP connections that are currently active or idle on the client.";

/// Measured while `metricsEnabled` or the OTLP exporter runs.
fn measured(config: &crate::config::Config) -> bool {
    enabled(config) || config.metrics.otel_histograms.load(Ordering::Relaxed)
}

/// One observation into a labelled histogram and, while the OTLP exporter runs, its twin: `fields` are the
/// attributes by their dotted names (an unset one absent), the Prometheus labels the same with `_` for `.`.
fn observe_labelled(
    histograms: &mut BTreeMap<Attributes, Histogram>,
    otel: Option<&mut BTreeMap<Attributes, OtelSeries>>,
    fields: &[(&str, Option<String>)],
    bounds: &'static [f64],
    seconds: f64,
) {
    let set = || fields.iter().filter_map(|(name, v)| Some((*name, v.clone()?)));
    if let Some(otel) = otel {
        let now = now_nanos();
        otel.entry(otel_attributes(set().map(|(n, v)| (n.to_string(), v)))).or_insert_with(|| OtelSeries::with_bounds(now, bounds)).record(seconds, now);
    }
    let labels = sorted(set().map(|(n, v)| (n.replace('.', "_"), v)).collect());
    histograms.entry(labels).or_insert_with(|| Histogram::with_bounds(bounds)).observe(seconds);
}

impl Metrics {
    /// A connection moves between `mock_server_active_connections` series: out of `from`, into `to`.
    fn connection_moved(&self, from: Option<(&'static str, bool)>, to: Option<(&'static str, bool)>) {
        let mut series = self.series.lock();
        if let Some(from) = from {
            *series.connections_active.entry(from).or_default() -= 1;
        }
        if let Some(to) = to {
            *series.connections_active.entry(to).or_default() += 1;
        }
    }

    /// A connection ended: out of the gauge, into `mock_server_connection_duration_seconds`.
    fn connection_closed(&self, c: &ServerConnection, seconds: f64) {
        let fields = [("error.type", c.error.map(str::to_string)), ("network.transport", Some(c.transport.to_string())), ("tls", Some(c.tls.to_string()))];
        let mut series = self.series.lock();
        *series.connections_active.entry((c.transport, c.tls)).or_default() -= 1;
        let series = &mut *series;
        let otel = self.otel_histograms.load(Ordering::Relaxed).then_some(&mut series.otel_connection_duration);
        observe_labelled(&mut series.connection_duration, otel, &fields, CONNECTION_BUCKETS, seconds);
    }

    /// A forward-pool connection moves between `http_client_open_connections` states (`active`, `idle`).
    fn forward_connection_moved(&self, address: &str, port: u16, from: Option<&'static str>, to: Option<&'static str>) {
        let mut series = self.series.lock();
        for (state, delta) in [(from, -1), (to, 1)] {
            if let Some(state) = state {
                *series.forward_pool_open.entry((state, address.to_string(), port)).or_default() += delta;
            }
        }
    }
}

/// One connection a listener accepted (Kestrel's `kestrel.active_connections` and
/// `kestrel.connection.duration` under our server's name): counted in `mock_server_active_connections` while it
/// lives, observed once into `mock_server_connection_duration_seconds` when dropped. A connection found to speak
/// TLS moves to `tls="true"` ([`ServerConnection::tls`]); one whose TLS handshake failed carries `error_type`.
pub struct ServerConnection {
    metrics: std::sync::Arc<Metrics>,
    started: std::time::Instant,
    transport: &'static str,
    tls: bool,
    error: Option<&'static str>,
}

impl ServerConnection {
    /// A connection over this transport (`tcp`, `udp` for QUIC), measured while `metricsEnabled` or the OTLP exporter
    /// runs; `None` otherwise.
    pub fn open(config: &crate::config::Config, transport: &'static str, tls: bool) -> Option<ServerConnection> {
        if !measured(config) {
            return None;
        }
        config.metrics.connection_moved(None, Some((transport, tls)));
        Some(ServerConnection { metrics: config.metrics.clone(), started: std::time::Instant::now(), transport, tls, error: None })
    }

    /// The connection turned out to speak TLS.
    pub fn tls(&mut self) {
        if !self.tls {
            self.metrics.connection_moved(Some((self.transport, false)), Some((self.transport, true)));
            self.tls = true;
        }
    }

    /// Why the connection ended (`error_type`).
    pub fn failed(&mut self, error: &'static str) {
        self.error = Some(error);
    }
}

impl Drop for ServerConnection {
    fn drop(&mut self) {
        self.metrics.connection_closed(self, self.started.elapsed().as_secs_f64());
    }
}

/// One TLS handshake the server terminated into `mock_server_tls_handshake_duration_seconds` (Kestrel's
/// `kestrel.tls_handshake.duration`): with the negotiated `tls_protocol_version` (`1.2`, `1.3`) when it succeeded, else
/// why it failed (`error_type`). Measured while `metricsEnabled` or the OTLP exporter runs.
pub fn tls_handshake(config: &crate::config::Config, seconds: f64, outcome: Result<Option<&'static str>, &'static str>) {
    if !measured(config) {
        return;
    }
    let (version, error) = match outcome {
        Ok(version) => (version, None),
        Err(error) => (None, Some(error)),
    };
    let fields = [("error.type", error.map(str::to_string)), ("tls.protocol.version", version.map(str::to_string))];
    let metrics = &config.metrics;
    let mut series = metrics.series.lock();
    let series = &mut *series;
    let otel = metrics.otel_histograms.load(Ordering::Relaxed).then_some(&mut series.otel_tls_handshake_duration);
    observe_labelled(&mut series.tls_handshake_duration, otel, &fields, HTTP_SERVER_BUCKETS, seconds);
}

/// One connection of the forwarding client's pool (`src/client.rs`) under the OTel HTTP client semconv's
/// `http.client.open_connections`: `active` while it carries an exchange, `idle` while it waits in the pool, gone from
/// both once dropped (closed, evicted, or refused by a full pool).
pub struct ForwardConnection {
    metrics: std::sync::Arc<Metrics>,
    address: String,
    port: u16,
    state: &'static str,
}

impl ForwardConnection {
    /// A new, active connection to this upstream, measured while `metricsEnabled` or the OTLP exporter runs.
    pub fn open(config: &crate::config::Config, address: &str, port: u16) -> Option<ForwardConnection> {
        if !measured(config) {
            return None;
        }
        config.metrics.forward_connection_moved(address, port, None, Some("active"));
        Some(ForwardConnection { metrics: config.metrics.clone(), address: address.to_string(), port, state: "active" })
    }

    /// Into the pool (`idle`) or back out of it (`active`).
    pub fn idle(&mut self, idle: bool) {
        let state = if idle { "idle" } else { "active" };
        if state != self.state {
            self.metrics.forward_connection_moved(&self.address, self.port, Some(self.state), Some(state));
            self.state = state;
        }
    }
}

impl Drop for ForwardConnection {
    fn drop(&mut self) {
        self.metrics.forward_connection_moved(&self.address, self.port, Some(self.state), None);
    }
}

pub fn enabled(config: &crate::config::Config) -> bool {
    config.bool_property("metricsEnabled", false)
}

/// `isPerExpectationMetricsActive`: `metricsEnabled` and `perExpectationMetricsEnabled` (whose default is the legacy
/// `perExpectationMetrics` key), the latter as the server started, since upstream registers the counter then.
pub fn per_expectation_enabled(config: &crate::config::Config) -> bool {
    let legacy = config.bool_startup_property("perExpectationMetrics", false);
    enabled(config) && config.bool_startup_property("perExpectationMetricsEnabled", legacy)
}

/// `isLlmMetricsActive`: `metricsEnabled` and `llmMetricsEnabled` as the server started (the counters are registered then).
pub fn llm_metrics_enabled(config: &crate::config::Config) -> bool {
    enabled(config) && config.bool_startup_property("llmMetricsEnabled", false)
}

/// Every name's value: the imperative counts, then the per-action and WebSocket counts read now.
fn values(state: &crate::state::State) -> Vec<(&'static str, &'static str, i64)> {
    let metrics = &state.config.metrics;
    let mut by_action: BTreeMap<&str, i64> = BTreeMap::new();
    for e in state.store.active() {
        if let Some((_, _, name)) = ACTIONS.iter().find(|(key, _, _)| e.canonical.get(*key).is_some()) {
            *by_action.entry(name).or_default() += 1;
        }
    }
    let (clients, response_handlers, forward_handlers) = state.callbacks.counts();
    NAMES
        .iter()
        .map(|(name, help)| {
            let value = match *name {
                "REQUESTS_RECEIVED_COUNT" => metrics.counts[0].load(Ordering::Relaxed),
                "EXPECTATIONS_NOT_MATCHED_COUNT" => metrics.counts[1].load(Ordering::Relaxed),
                "RESPONSE_EXPECTATIONS_MATCHED_COUNT" => metrics.counts[2].load(Ordering::Relaxed),
                "FORWARD_EXPECTATIONS_MATCHED_COUNT" => metrics.counts[3].load(Ordering::Relaxed),
                "LLM_CHAOS_INJECTED_COUNT" => metrics.counts[4].load(Ordering::Relaxed),
                "WEBSOCKET_CALLBACK_CLIENTS_COUNT" => clients as i64,
                "WEBSOCKET_CALLBACK_RESPONSE_HANDLERS_COUNT" => response_handlers as i64,
                "WEBSOCKET_CALLBACK_FORWARD_HANDLERS_COUNT" => forward_handlers as i64,
                other => by_action.get(other).copied().unwrap_or(0),
            };
            (*name, *help, value)
        })
        .collect()
}

/// `Metrics.get(name)`: one name's value now.
pub fn get(state: &crate::state::State, name: &str) -> Option<i64> {
    values(state).into_iter().find(|(n, _, _)| *n == name).map(|(_, _, v)| v)
}

/// Metric attributes (OTLP) or labels, in order.
pub type Attributes = Vec<(String, String)>;

/// `Metrics.LOAD_FIXED_LABELS`: the structured labels of the per-request load series, in order.
pub const LOAD_FIXED_LABELS: [&str; 6] = ["scenario", "run_id", "step", "route", "method", "status_class"];

/// Labels sorted by name, as the Prometheus client's `Labels` keeps them.
fn sorted(mut labels: Attributes) -> Attributes {
    labels.sort_by(|a, b| a.0.cmp(&b.0));
    labels
}

/// `Metrics.MAX_FORWARD_HOST_LABELS`: the distinct `upstream_host` labels the forward series may hold.
pub(crate) const MAX_FORWARD_HOST_LABELS: usize = 500;

/// `Metrics.forwardHostLabel`: the host, `unknown` when there is none; once `MAX_FORWARD_HOST_LABELS` hosts have a
/// label, a host not among them is recorded as `_other`. The labels outlive a reset, as upstream's static set does.
fn host_label(labels: &mut std::collections::BTreeSet<String>, host: &str) -> String {
    let host = if host.is_empty() { "unknown" } else { host };
    if labels.contains(host) {
        return host.to_string();
    }
    if labels.len() >= MAX_FORWARD_HOST_LABELS {
        return "_other".into();
    }
    labels.insert(host.to_string());
    host.to_string()
}

/// `Metrics.statusClass`: `2xx` and so on, `unknown` outside 100–599.
fn status_class(status: u32) -> String {
    if (100..600).contains(&status) { format!("{}xx", status / 100) } else { "unknown".into() }
}

/// OTel `Attributes` as `AttributesBuilder.build` makes them: a later value of a key replaces the earlier one, keys
/// sorted.
fn otel_attributes(pairs: impl IntoIterator<Item = (String, String)>) -> Attributes {
    let mut out: BTreeMap<String, String> = BTreeMap::new();
    for (k, v) in pairs {
        out.insert(k, v);
    }
    out.into_iter().collect()
}

/// `registerLoadMetrics`'s allowlist: `loadGenerationMetricLabels` as the server started, split on commas, trimmed,
/// blanks dropped.
pub fn load_label_names(config: &crate::config::Config) -> Vec<String> {
    config.startup_property("loadGenerationMetricLabels").map(|text| text.split(',').map(str::trim).filter(|v| !v.is_empty()).map(str::to_string).collect()).unwrap_or_default()
}

/// A value `OtelMetricsExporter`'s observable instruments record.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum OtelValue {
    Long(i64),
    Double(f64),
}

/// One data point of an `OtelMetricsExporter` instrument: an observable counter (`monotonic`) or gauge.
#[derive(Debug, Clone)]
pub struct OtelPoint {
    pub name: String,
    pub description: String,
    /// The instrument's unit: `By` for the load byte counters (`setUnit("By")`), the semconv unit for the process
    /// instruments, else none.
    pub unit: &'static str,
    pub monotonic: bool,
    /// An observable up-down counter: a non-monotonic, always cumulative `Sum` (when not `monotonic`).
    pub up_down: bool,
    pub value: OtelValue,
    pub attributes: Attributes,
}

/// `activeCountByFaultType`: active service chaos profiles per fault type, every type present.
fn active_service_chaos(state: &crate::state::State) -> BTreeMap<&'static str, i64> {
    let mut counts: BTreeMap<&'static str, i64> = SERVICE_CHAOS_FAULT_TYPES.iter().map(|t| (*t, 0)).collect();
    for (_, profile) in state.chaos.service.entries() {
        for t in profile.fault_types() {
            *counts.entry(t).or_default() += 1;
        }
    }
    counts
}

/// `mock_server_load_*` counter descriptions (`OtelMetricsExporter.registerLoadMetrics`).
const LOAD_COUNTERS: &[(&str, &str)] = &[
    ("mock_server_load_requests", "Total load-scenario requests"),
    ("mock_server_load_request_bytes", "Total load-scenario request body bytes"),
    ("mock_server_load_response_bytes", "Total load-scenario response body bytes"),
    ("mock_server_load_iterations", "Total completed load-scenario iterations"),
    ("mock_server_load_throttled", "Total load-scenario dispatches throttled by the self-load guard"),
    ("mock_server_load_errors", "Total load-scenario request errors by kind"),
    ("mock_server_load_checks", "Total per-step load-scenario response checks by outcome"),
];

/// The Prometheus `mock_server_load_*` counters and their help texts (`Metrics.registerLoadMetrics`).
const LOAD_PROMETHEUS_COUNTERS: &[(&str, &str)] = &[
    ("mock_server_load_requests", "Total load-scenario requests by scenario/run/step/route/method/status class"),
    ("mock_server_load_request_bytes", "Total load-scenario request body bytes by scenario/run/step/route/method/status class"),
    ("mock_server_load_response_bytes", "Total load-scenario response body bytes by scenario/run/step/route/method/status class"),
    ("mock_server_load_iterations", "Total completed load-scenario iterations by scenario and run"),
    ("mock_server_load_throttled", "Total load-scenario dispatches throttled by the self-load guard, by reason (inflight_cap, rate_limit)"),
    ("mock_server_load_errors", "Total load-scenario request errors by kind (timeout, connection, render, http_5xx, null_response)"),
    ("mock_server_load_checks", "Total per-step load-scenario response checks by scenario/run/step and outcome (pass, fail)"),
];

/// `OtelMetricsExporter.startWithReader`'s instruments, read now: a gauge per name, the monotonic `_total` counters,
/// slow requests, chaos injections and active service chaos by fault type, the load counters and gauges, and the
/// LLM-optimisation gauges (attributes sorted by key, as OTel keeps them), then ours: the `mock_server_native_build_info`
/// gauge, the process set in place of the JVM gauges ([`process_otel_points`], docs/divergences.md), the tokio set
/// of the server runtime ([`tokio_otel_points`]) and `http.server.active_requests`. The histograms are
/// [`Metrics::collect_otel_histograms`].
pub fn otel_points(state: &crate::state::State) -> Vec<OtelPoint> {
    let metrics = &state.config.metrics;
    let point = |name: &str, description: &str, monotonic: bool, value: OtelValue, attributes: Attributes| OtelPoint {
        name: name.into(),
        description: description.into(),
        unit: if name.starts_with("mock_server_load_") && name.ends_with("_bytes") { "By" } else { "" },
        monotonic,
        up_down: false,
        value,
        attributes,
    };
    let fault = |t: &str| vec![("fault_type".to_string(), t.to_string())];
    let mut out: Vec<OtelPoint> = values(state).into_iter().map(|(name, help, v)| point(&name.to_ascii_lowercase(), help, false, OtelValue::Long(v), vec![])).collect();
    for (i, (count, name)) in MONOTONIC.iter().enumerate() {
        let help = NAMES.iter().find(|(n, _)| n == count).map(|(_, h)| *h).unwrap_or_default();
        let total = metrics.totals[i].load(Ordering::Relaxed);
        out.push(point(&format!("{name}_total"), &format!("{help} (monotonic counter; mirrors Prometheus counter)"), true, OtelValue::Long(total), vec![]));
    }
    let series = metrics.series.lock();
    out.push(point(
        "mock_server_slow_requests_total",
        "Total forwarded requests that exceeded the slow-request threshold (mirrors Prometheus counter)",
        true,
        OtelValue::Long(series.slow_requests as i64),
        vec![],
    ));
    for t in CHAOS_FAULT_TYPES {
        let n = series.http_chaos_injected.get(*t).copied().unwrap_or(0);
        out.push(point("mock_server_http_chaos_injected_total", "Total HTTP chaos faults injected by type (mirrors Prometheus counter)", true, OtelValue::Long(n as i64), fault(t)));
    }
    for (name, help) in LOAD_COUNTERS {
        for ((_, attributes), n) in series.load.iter().filter(|((k, _), _)| k == name) {
            out.push(point(name, help, true, OtelValue::Long(*n), attributes.clone()));
        }
    }
    drop(series);
    for (t, n) in active_service_chaos(state) {
        out.push(point(
            "mock_server_active_service_chaos",
            "Number of active service-scoped chaos profiles configured with each fault type (mirrors Prometheus gauge)",
            false,
            OtelValue::Long(n),
            fault(t),
        ));
    }
    let gauges = state.load.runs.gauges();
    for (name, help, pick) in [
        ("mock_server_load_active_vus", "Number of active virtual users in the running load scenario", 0),
        ("mock_server_load_inflight_requests", "Number of in-flight load-scenario requests", 1),
    ] {
        for (scenario, run_id, vus, in_flight) in &gauges {
            let n = if pick == 0 { *vus } else { *in_flight };
            out.push(point(name, help, false, OtelValue::Long(n.into()), vec![("run_id".into(), run_id.clone()), ("scenario".into(), scenario.clone())]));
        }
    }
    let (waste, cache_hit, one_shot) = *metrics.llm_optimisation.lock();
    for (name, help, value) in [
        ("mock_server_llm_estimated_waste_usd", "Estimated recoverable LLM spend (USD) from the latest optimisation report", waste),
        ("mock_server_llm_cache_hit_ratio", "Cache-hit ratio (0..1) from the latest LLM optimisation report", cache_hit),
        ("mock_server_llm_one_shot_rate", "One-shot rate (0..1) from the latest LLM optimisation report", one_shot),
    ] {
        out.push(point(name, help, false, OtelValue::Double(value), vec![]));
    }
    out.push(point("mock_server_native_build_info", "mock-server build information", false, OtelValue::Long(1), rs_build_info()));
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0.0, |d| d.as_secs_f64());
    out.extend(process_otel_points(&process::read(), now));
    if let Some(runtime) = &state.runtime {
        out.extend(tokio_otel_points(runtime));
    }
    out.extend(http_server_otel_points(metrics));
    out.extend(connection_otel_points(metrics));
    out
}

/// The process set under the OTel process semantic conventions: `process.cpu.time` a counter by
/// `cpu.mode`, `process.uptime` a gauge, the rest up-down counters, each with its semconv unit; a figure the platform
/// cannot give is left out. `now` is seconds since the epoch.
pub fn process_otel_points(p: &process::ProcessStats, now: f64) -> Vec<OtelPoint> {
    let instrument = |name: &str, description: &str, unit: &'static str, monotonic: bool, up_down: bool, value: OtelValue, attributes: Attributes| OtelPoint {
        name: name.into(),
        description: description.into(),
        unit,
        monotonic,
        up_down,
        value,
        attributes,
    };
    let mode = |m: &str| vec![("cpu.mode".to_string(), m.to_string())];
    let mut out = vec![
        instrument("process.cpu.time", "Total CPU seconds broken down by different CPU modes.", "s", true, false, OtelValue::Double(p.cpu_user_seconds), mode("user")),
        instrument("process.cpu.time", "Total CPU seconds broken down by different CPU modes.", "s", true, false, OtelValue::Double(p.cpu_system_seconds), mode("system")),
    ];
    for (name, description, unit, value) in [
        ("process.memory.usage", "The amount of physical memory in use.", "By", p.resident_bytes),
        ("process.memory.virtual", "The amount of committed virtual memory.", "By", p.virtual_bytes),
        ("process.unix.file_descriptor.count", "Number of unix file descriptors in use by the process.", "{file_descriptor}", p.open_fds),
        ("process.thread.count", "Process threads count.", "{thread}", p.threads),
    ] {
        if let Some(value) = value {
            out.push(instrument(name, description, unit, false, true, OtelValue::Long(value as i64), Vec::new()));
        }
    }
    if let Some(start) = p.start_time_seconds {
        out.push(instrument("process.uptime", "The time the process has been running.", "s", false, false, OtelValue::Double((now - start).max(0.0)), Vec::new()));
    }
    out
}

/// `retrieve?type=METRICS`: every name and its value, compact; `{}` while metrics are disabled.
pub fn retrieve(state: &crate::state::State) -> String {
    if !enabled(&state.config) {
        return "{}".into();
    }
    let map: Map<String, Value> = values(state).into_iter().map(|(name, _, v)| (name.to_string(), Value::from(v))).collect();
    Value::Object(map).to_string()
}

/// A Java `double` as Prometheus's Java client writes it.
fn num(v: f64) -> String {
    java_compat::lang::JValue::Double(v).to_java_string()
}

/// One metric family as the Prometheus client's `MetricSnapshot` holds it: what `GET /mockserver/metrics` renders and
/// the remote-write exporter (`PrometheusRemoteWriteExporter`) pushes, so both carry the same series.
#[derive(Debug, Clone, PartialEq)]
pub struct Snapshot {
    /// The Prometheus name; a counter's is without its `_total` suffix.
    pub name: String,
    pub help: String,
    pub data: Data,
}

/// A family's data points, by metric type.
#[derive(Debug, Clone, PartialEq)]
pub enum Data {
    Counter(Vec<(Attributes, f64)>),
    Gauge(Vec<(Attributes, f64)>),
    Histogram(Vec<HistogramPoint>),
}

/// A classic histogram's data point (`HistogramDataPointSnapshot` with `ClassicHistogramBuckets`).
#[derive(Debug, Clone, PartialEq)]
pub struct HistogramPoint {
    pub labels: Attributes,
    /// Each bucket's own (not cumulative) count by upper bound, ascending, the last bound `+Inf`.
    pub buckets: Vec<(f64, u64)>,
    pub count: u64,
    pub sum: f64,
    /// Each bucket's exemplar, by bucket; empty for a histogram without exemplars.
    pub exemplars: Vec<Option<Exemplar>>,
}

impl HistogramPoint {
    fn of(labels: Attributes, h: &Histogram) -> HistogramPoint {
        // `Histogram` counts cumulatively; the snapshot holds each bucket's own count.
        let cumulative = if h.buckets.is_empty() { vec![0; h.bounds.len()] } else { h.buckets.clone() };
        let mut previous = 0;
        let mut buckets: Vec<(f64, u64)> = h
            .bounds
            .iter()
            .zip(&cumulative)
            .map(|(bound, n)| {
                let own = n - previous;
                previous = *n;
                (*bound, own)
            })
            .collect();
        buckets.push((f64::INFINITY, h.count - previous));
        HistogramPoint { labels, buckets, count: h.count, sum: h.sum, exemplars: h.live_exemplars() }
    }
}

impl Snapshot {
    fn gauge(name: &str, help: &str, points: Vec<(Attributes, f64)>) -> Snapshot {
        Snapshot { name: name.into(), help: help.into(), data: Data::Gauge(points) }
    }

    fn counter(name: &str, help: &str, points: Vec<(Attributes, f64)>) -> Snapshot {
        Snapshot { name: name.into(), help: help.into(), data: Data::Counter(points) }
    }

    /// The name the text format sorts and announces it by: a counter's with `_total`.
    fn exposed_name(&self) -> String {
        match self.data {
            Data::Counter(_) => format!("{}_total", self.name),
            _ => self.name.clone(),
        }
    }

    fn kind(&self) -> &'static str {
        match self.data {
            Data::Counter(_) => "counter",
            Data::Gauge(_) => "gauge",
            Data::Histogram(_) => "histogram",
        }
    }

    /// The family's sample lines, as `PrometheusTextFormatWriter` writes them, or with `open_metrics` as
    /// `OpenMetricsTextFormatWriter` does (bucket exemplars).
    fn samples(&self, open_metrics: bool) -> Vec<String> {
        let line = |name: &str, labels: &Attributes, extra: Option<(&str, String)>, value: String| {
            let mut pairs: Vec<String> = labels.iter().map(|(k, v)| format!("{k}=\"{}\"", escape_label(v))).collect();
            if let Some((k, v)) = extra {
                pairs.push(format!("{k}=\"{v}\""));
            }
            match pairs.is_empty() {
                true => format!("{name} {value}"),
                false => format!("{name}{{{}}} {value}", pairs.join(",")),
            }
        };
        match &self.data {
            Data::Counter(points) => points.iter().map(|(l, v)| line(&format!("{}_total", self.name), l, None, num(*v))).collect(),
            Data::Gauge(points) => points.iter().map(|(l, v)| line(&self.name, l, None, num(*v))).collect(),
            Data::Histogram(points) => {
                let mut out = Vec::new();
                for p in points {
                    let mut cumulative = 0;
                    for (i, (bound, n)) in p.buckets.iter().enumerate() {
                        cumulative += n;
                        let mut sample = line(&format!("{}_bucket", self.name), &p.labels, Some(("le", bucket_bound(*bound))), cumulative.to_string());
                        if let Some(Some(e)) = p.exemplars.get(i).filter(|_| open_metrics) {
                            let labels: Vec<String> = e.labels.iter().map(|(k, v)| format!("{k}=\"{}\"", escape_label(v))).collect();
                            sample.push_str(&format!(" # {{{}}} {} {}.{:03}", labels.join(","), num(e.value), e.timestamp_millis / 1000, e.timestamp_millis % 1000));
                        }
                        out.push(sample);
                    }
                    out.push(line(&format!("{}_count", self.name), &p.labels, None, p.count.to_string()));
                    out.push(line(&format!("{}_sum", self.name), &p.labels, None, num(p.sum)));
                }
                out
            }
        }
    }
}

/// A label value escaped as the text format escapes it: backslash, double quote and newline.
fn escape_label(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n")
}

/// `RemoteWriteV1Encoder.formatBucketBound`: `+Inf`/`-Inf`, otherwise the Java `double` (`1.0`), as the text
/// format writes a bucket's `le` or a summary's `quantile`.
pub fn bucket_bound(bound: f64) -> String {
    match bound {
        f64::INFINITY => "+Inf".into(),
        f64::NEG_INFINITY => "-Inf".into(),
        _ => num(bound),
    }
}

/// `GET /mockserver/metrics`: the text exposition, families sorted by name; `None` while metrics are disabled.
pub fn exposition(state: &crate::state::State) -> Option<String> {
    exposition_as(state, false)
}

/// [`exposition`] in the OpenMetrics text format when `open_metrics` (the `Accept` header asked for
/// `application/openmetrics-text`): each family's `# TYPE` before its `# HELP`, a counter's family named without its
/// `_total` suffix, and a closing `# EOF`.
pub fn exposition_as(state: &crate::state::State, open_metrics: bool) -> Option<String> {
    if !enabled(&state.config) {
        return None;
    }
    let mut out = String::new();
    for f in snapshots(state) {
        let name = if open_metrics { f.name.clone() } else { f.exposed_name() };
        if open_metrics {
            out.push_str(&format!("# TYPE {name} {}\n# HELP {name} {}\n", f.kind(), f.help));
        } else {
            out.push_str(&format!("# HELP {name} {}\n# TYPE {name} {}\n", f.help, f.kind()));
        }
        for s in f.samples(open_metrics) {
            out.push_str(&s);
            out.push('\n');
        }
    }
    if open_metrics {
        out.push_str("# EOF\n");
    }
    Some(out)
}

/// `PrometheusRegistry.scrape()`: every family the exposition serves, sorted as it serves them.
pub fn snapshots(state: &crate::state::State) -> Vec<Snapshot> {
    let metrics = &state.config.metrics;
    let series = metrics.series.lock();
    let none = Attributes::new;
    let label = |k: &str, v: &str| vec![(k.to_string(), v.to_string())];
    let mut families: Vec<Snapshot> = Vec::new();
    for (name, help, value) in values(state) {
        families.push(Snapshot::gauge(&name.to_ascii_lowercase(), help, vec![(none(), value as f64)]));
    }
    families.push(Snapshot::gauge(
        "mock_server_active_service_chaos",
        "Number of active service-scoped chaos profiles configured with each fault type",
        active_service_chaos(state).iter().map(|(t, n)| (label("fault_type", t), *n as f64)).collect(),
    ));
    let build_info = [("artifact_id", "mockserver-core"), ("git_hash", crate::control::UPSTREAM_GIT_HASH), ("group_id", "org.mock-server"), ("major_minor_version", "9.2"), ("version", crate::control::VERSION)];
    families.push(Snapshot::gauge(
        "mock_server_build_info",
        "Mock Server build information",
        vec![(build_info.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(), 1.0)],
    ));
    families.push(Snapshot::gauge("mock_server_native_build_info", "mock-server build information", vec![(rs_build_info(), 1.0)]));
    // `getClusterMemberCount`: the state backend's members, never fewer than this node.
    let members = state.state_backend.cluster_info().members.len().max(1);
    families.push(Snapshot::gauge("mock_server_cluster_members", "Number of members in the MockServer cluster (1 for a single-node deployment)", vec![(none(), members as f64)]));
    let mut by_type: BTreeMap<&str, i64> = BTreeMap::new();
    for e in state.store.active() {
        if let Some((_, kind, _)) = ACTIONS.iter().find(|(key, _, _)| e.canonical.get(*key).is_some()) {
            *by_type.entry(kind).or_default() += 1;
        }
    }
    if !by_type.is_empty() {
        families.push(Snapshot::gauge(
            "mock_server_expectations_by_type",
            "Number of active expectations grouped by action type",
            by_type.iter().map(|(t, n)| (label("action_type", t), *n as f64)).collect(),
        ));
    }
    families.push(Snapshot::gauge("mock_server_upstream_circuit_open", "Number of upstreams whose forward/proxy circuit breaker is currently open", vec![(none(), state.forward_connections.breaker.open_count() as f64)]));
    families.extend(store_and_log_snapshots(state));
    let (waste, cache_hit, one_shot) = *metrics.llm_optimisation.lock();
    for (name, help, value) in [
        ("mock_server_llm_estimated_waste_usd", "Estimated recoverable LLM spend (USD) from the latest optimisation report", waste),
        ("mock_server_llm_cache_hit_ratio", "Cache-hit ratio (0..1) from the latest LLM optimisation report", cache_hit),
        ("mock_server_llm_one_shot_rate", "One-shot rate (0..1, fraction of non-retry calls) from the latest LLM optimisation report", one_shot),
    ] {
        families.push(Snapshot::gauge(name, help, vec![(none(), value)]));
    }
    for (i, (count, name)) in MONOTONIC.iter().enumerate() {
        let help = NAMES.iter().find(|(n, _)| n == count).map(|(_, h)| *h).unwrap_or_default();
        let total = metrics.totals[i].load(Ordering::Relaxed);
        families.push(Snapshot::counter(name, &format!("{help} (monotonic counter; use rate()/increase() on this _total series)"), vec![(none(), total as f64)]));
    }
    families.push(Snapshot::counter("mock_server_slow_requests", "Total number of forwarded requests that exceeded the slow request threshold", vec![(none(), series.slow_requests as f64)]));
    // Our event log records each entry as it is logged: nothing is ever dropped before being recorded.
    families.push(Snapshot::counter(
        "mock_server_dropped_log_events",
        "Log events dropped before being recorded, by reason (ring_full: the event-log ring buffer was full; in_flight_bytes: the bodies waiting to be logged would have exceeded the in-flight byte cap)",
        DROP_REASONS.iter().map(|r| (label("reason", r), 0.0)).collect(),
    ));
    families.extend(transport_snapshots(&series, state.drift.dropped()));
    families.push(Snapshot::counter(
        "mock_server_evicted_log_entries",
        "Number of event log entries evicted because the event log reached its maximum size",
        vec![(none(), state.log.evicted_since_start() as f64)],
    ));
    families.push(Snapshot::counter("mock_server_chaos_auto_halt", "Total number of times the chaos auto-halt circuit-breaker triggered", vec![(none(), series.chaos_auto_halts as f64)]));
    if !series.http_chaos_injected.is_empty() {
        families.push(Snapshot::counter(
            "mock_server_http_chaos_injected",
            "Total HTTP chaos faults injected by type",
            series.http_chaos_injected.iter().map(|(t, n)| (label("fault_type", t), *n as f64)).collect(),
        ));
    }
    for (name, help, counts) in [
        ("mock_server_async_messages_published", "Total async/broker messages published by channel", &series.async_published),
        ("mock_server_async_messages_consumed", "Total async/broker messages consumed/recorded by channel", &series.async_consumed),
    ] {
        if !counts.is_empty() {
            families.push(Snapshot::counter(name, help, counts.iter().map(|(c, n)| (label("channel", c), *n as f64)).collect()));
        }
    }
    families.push(Snapshot::counter(
        "mock_server_llm_cost_budget_tripped",
        "Total number of times the LLM cost-budget circuit-breaker tripped",
        vec![(none(), metrics.cost_budget.tripped_total() as f64)],
    ));
    if per_expectation_enabled(&state.config) && !series.expectation_matched.is_empty() {
        families.push(Snapshot::counter(
            "mock_server_expectation_matched",
            "Total expectation matches (matched and responded) labeled by stable expectation id",
            series.expectation_matched.iter().map(|(id, n)| (label("expectation_id", id), *n as f64)).collect(),
        ));
    }
    if !series.mcp_tool_calls.is_empty() {
        families.push(Snapshot::counter("mock_server_mcp_tool_calls", "Total MCP tool calls by tool name", series.mcp_tool_calls.iter().map(|(t, n)| (label("tool", t), *n as f64)).collect()));
    }
    if llm_metrics_enabled(&state.config) {
        let provider_and_model = |((p, m), v): (&(String, String), &f64)| (vec![("model".to_string(), m.clone()), ("provider".to_string(), p.clone())], *v);
        for (name, help, counts) in [
            ("mock_server_llm_input_tokens", "Total LLM input tokens by provider and model", &series.llm_input_tokens),
            ("mock_server_llm_output_tokens", "Total LLM output tokens by provider and model", &series.llm_output_tokens),
            ("mock_server_llm_cost_usd", "Cumulative estimated LLM cost in USD by provider and model", &series.llm_cost_usd),
        ] {
            if !counts.is_empty() {
                let mut points: Vec<(Attributes, f64)> = counts.iter().map(provider_and_model).collect();
                points.sort_by(|a, b| a.0.cmp(&b.0));
                families.push(Snapshot::counter(name, help, points));
            }
        }
    }
    for (name, help) in LOAD_PROMETHEUS_COUNTERS {
        let points: Vec<(Attributes, f64)> = series.load_prometheus.iter().filter(|((n, _), _)| n == name).map(|((_, labels), v)| (labels.clone(), *v)).collect();
        if !points.is_empty() {
            families.push(Snapshot::counter(name, help, points));
        }
    }
    if !series.load_duration.is_empty() {
        families.push(Snapshot {
            name: "mock_server_load_request_duration_seconds".into(),
            help: "Load-scenario request duration in seconds, labeled by scenario/run/step/route/method/status class".into(),
            data: Data::Histogram(series.load_duration.iter().map(|(labels, h)| HistogramPoint::of(labels.clone(), h)).collect()),
        });
    }
    let gauges = state.load.runs.gauges();
    if !gauges.is_empty() {
        for (name, help, pick) in [
            ("mock_server_load_active_vus", "Number of active virtual users in the running load scenario, by scenario and run", 0),
            ("mock_server_load_inflight_requests", "Number of in-flight (dispatched, not-yet-completed) load-scenario requests, by scenario and run", 1),
        ] {
            let mut points: Vec<(Attributes, f64)> = gauges
                .iter()
                .map(|(scenario, run_id, vus, in_flight)| (vec![("run_id".to_string(), run_id.clone()), ("scenario".to_string(), scenario.clone())], f64::from(if pick == 0 { *vus } else { *in_flight })))
                .collect();
            points.sort_by(|a, b| a.0.cmp(&b.0));
            families.push(Snapshot::gauge(name, help, points));
        }
    }
    let class_and_host = |a: &str, b: &str, (x, y): &(String, String)| vec![(a.to_string(), x.clone()), (b.to_string(), y.clone())];
    if !series.forward_requests.is_empty() {
        families.push(Snapshot::counter(
            "mock_server_forward_requests",
            "Total forwarded/proxied requests by upstream host and response status class",
            series.forward_requests.iter().map(|(k, n)| (class_and_host("status_class", "upstream_host", k), *n as f64)).collect(),
        ));
    }
    if !series.forward_protocol.is_empty() {
        families.push(Snapshot::counter(
            "mock_server_forward_upstream_protocol",
            "Total forward/proxy upstream connections by upstream host and the protocol actually negotiated to the upstream (http2 via ALPN, or http1_1)",
            series.forward_protocol.iter().map(|(k, n)| (class_and_host("protocol", "upstream_host", k), *n as f64)).collect(),
        ));
    }
    families.push(Snapshot {
        name: "mock_server_request_duration_seconds".into(),
        help: "MockServer request handling duration in seconds".into(),
        data: Data::Histogram(vec![HistogramPoint::of(none(), &series.request_duration)]),
    });
    if state.config.bool_startup_property("metricsRequestDurationRouteLabels", false) {
        families.push(Snapshot {
            name: "mock_server_request_duration_by_method_seconds".into(),
            help: "MockServer request handling duration in seconds, labeled by HTTP method".into(),
            data: Data::Histogram(series.request_duration_by_method.iter().map(|(method, h)| HistogramPoint::of(label("method", method), h)).collect()),
        });
    }
    if !series.forward_duration.is_empty() {
        families.push(Snapshot {
            name: "mock_server_forward_request_duration_seconds".into(),
            help: "Latency of forwarded/proxied requests in seconds, labeled by upstream host".into(),
            data: Data::Histogram(series.forward_duration.iter().map(|(host, h)| HistogramPoint::of(label("upstream_host", host), h)).collect()),
        });
    }
    families.extend(http_server_snapshots(&series));
    families.extend(connection_snapshots(&series));
    drop(series);
    families.extend(process_metrics());
    if let Some(runtime) = &state.runtime {
        families.extend(tokio_snapshots(runtime));
    }
    families.sort_by_key(Snapshot::exposed_name);
    families
}

/// `/proc/sys/net/core/somaxconn`, read once (`Metrics.readSomaxconn`); `None` where it cannot be read (not Linux).
/// `Scheduler.getQueuedTaskCount`, the action scheduler pool's queue, summed over its sources: the delayed tasks
/// whose delay has not elapsed, and the immediate tasks waiting for a pool thread (forward continuations and drift
/// analyses behind analyses holding every thread). Our other immediate tasks never wait in a queue.
pub(crate) fn scheduler_queued(state: &crate::state::State) -> usize {
    [state.overload.pending_delayed(), state.drift.queued()].into_iter().sum()
}

fn somaxconn() -> Option<i64> {
    static SOMAXCONN: std::sync::OnceLock<Option<i64>> = std::sync::OnceLock::new();
    *SOMAXCONN.get_or_init(|| std::fs::read_to_string("/proc/sys/net/core/somaxconn").ok().and_then(|s| s.trim().parse().ok()))
}

/// The scrape-time gauges of the event log (`RingStats`), the expectation store (`ExpectationStoreStats`), the accept
/// queue and the action scheduler. Ours records each log entry as it is logged, so its ring is always empty; the
/// ring's capacity is the `ringBufferSize` in force and its in-flight budget the one upstream would apply
/// (`eventLogInFlightBytes`). Expectation bytes are an estimate, the size of each active expectation's JSON. Delays
/// and template renders run as tasks of their own, never queued behind a bounded pool.
fn store_and_log_snapshots(state: &crate::state::State) -> Vec<Snapshot> {
    let config = &state.config;
    let gauge = |name: &str, help: &str, value: f64| Snapshot::gauge(name, help, vec![(Attributes::new(), value)]);
    let (entries, bytes, max_bytes, max_entries) = state.log.retained();
    let in_flight_cap = crate::config::event_log_in_flight_bytes(config, max_bytes);
    let expectation_bytes = state.store.expectation_bytes();
    let backlog = config.int_property("soBacklog", 1024);
    let mut families = vec![
        gauge("mock_server_accept_queue_backlog_configured", "Configured TCP accept-queue depth (soBacklog)", backlog as f64),
        gauge("mock_server_event_log_ring_occupancy", "Event-log disruptor ring-buffer slots currently occupied (published, not yet consumed)", 0.0),
        gauge("mock_server_event_log_ring_capacity", "Event-log disruptor ring-buffer total slot count (ringBufferSize in force)", state.init_only_in_force.0 as f64),
        gauge("mock_server_event_log_in_flight_bytes", "Request/response body bytes held by log entries published to the ring but not yet processed", 0.0),
        gauge(
            "mock_server_event_log_max_in_flight_bytes",
            "In-flight body-byte budget in force (the larger of maxEventLogSizeInBytes and a heap-derived cap); 0 means the in-flight bound is disabled",
            in_flight_cap as f64,
        ),
        gauge("mock_server_event_log_retained_entries", "Event-log entries retained after processing (backing deque element count)", entries as f64),
        gauge("mock_server_event_log_retained_bytes", "Request/response body bytes held by log entries retained after processing (backing deque summed weight)", bytes as f64),
        gauge("mock_server_event_log_max_retained_bytes", "Retained body-byte budget in force (maxEventLogSizeInBytes); 0 means the retained byte bound is disabled", max_bytes as f64),
        gauge("mock_server_event_log_max_retained_entries", "Retained entry-count cap in force (maxLogEntries)", max_entries as f64),
        gauge("mock_server_expectations_bytes", "Estimated retained heap (summed entry weight) held by the expectation store", expectation_bytes as f64),
        gauge(
            "mock_server_max_expectations_bytes",
            "Expectation-store byte budget in force (maxExpectationsSizeInBytes); 0 means the byte bound is disabled",
            state.store.max_bytes() as f64,
        ),
        Snapshot::counter(
            "mock_server_expectations_byte_evicted",
            "Total expectations evicted to stay within the byte budget (maxExpectationsSizeInBytes)",
            vec![(Attributes::new(), state.store.byte_evicted() as f64)],
        ),
        gauge("mock_server_scheduler_queued_tasks", "Tasks queued on the shared action scheduler pool (response delays, forward continuations, drift analysis)", scheduler_queued(state) as f64),
        gauge("mock_server_template_action_queued_tasks", "Response/forward template renders queued waiting for a template-action thread", state.overload.queued_template_actions() as f64),
        gauge("mock_server_pending_delayed_tasks", "All delayed tasks waiting for their delay, bounded or not", state.overload.pending_delayed() as f64),
    ];
    let rejections = state.overload.rejections();
    if !rejections.is_empty() {
        families.push(Snapshot::counter(
            "mock_server_overload_rejections",
            "Tasks refused because a bound was full, by reason (delayed_responses and template_actions answered 503, delay_skipped sent without chaos latency, side_actions dropped, websocket_replies closed with 1013, static_files, file_bodies, extension_admin and extension_dataplane answered 503)",
            rejections.into_iter().map(|(reason, n)| (vec![("reason".to_string(), reason.to_string())], n as f64)).collect(),
        ));
    }
    if let Some(kernel) = somaxconn() {
        families.push(gauge(
            "mock_server_accept_queue_backlog_effective",
            "Effective TCP accept-queue depth: min(soBacklog, /proc/sys/net/core/somaxconn read at startup); omitted when somaxconn is unreadable",
            backlog.min(kernel) as f64,
        ));
    }
    families
}

/// The inbound transport set: the transport and read-to-decode histograms (exported, empty, from the first scrape),
/// the open inbound connections (TCP, so HTTP/3 is excluded), the connections refused by the cap and closed as idle,
/// the write stalls, the WebSocket read pauses, and the drift analyses dropped for a
/// full backlog.
fn transport_snapshots(series: &Series, dropped_drift_analyses: u64) -> Vec<Snapshot> {
    let histogram = |name: &str, help: &str, h: &Option<Histogram>, bounds: &'static [f64]| Snapshot {
        name: name.into(),
        help: help.into(),
        data: Data::Histogram(vec![HistogramPoint::of(Attributes::new(), h.as_ref().unwrap_or(&Histogram::with_bounds(bounds)))]),
    };
    let open: i64 = series.connections_active.iter().filter(|((transport, _), _)| *transport == "tcp").map(|(_, n)| *n).sum();
    vec![
        histogram(
            "mock_server_request_transport_duration_seconds",
            "Time from a request's head being decoded to the last byte of its response being written to the socket, in seconds (HTTP/1.1 and HTTP/2)",
            &series.request_transport_duration,
            TRANSPORT_BUCKETS,
        ),
        histogram(
            "mock_server_request_read_to_decode_duration_seconds",
            "Time from the socket read that delivered the first bytes of a request to its head being decoded, in seconds (HTTP/1.1)",
            &series.request_read_to_decode_duration,
            READ_TO_DECODE_BUCKETS,
        ),
        Snapshot::gauge("mock_server_inbound_connections_open", "Inbound client connections currently open (HTTP/1.1, HTTP/2, TLS, SOCKS, tunnels; excludes HTTP/3)", vec![(Attributes::new(), open.max(0) as f64)]),
        Snapshot::counter("mock_server_inbound_connections_rejected", "Inbound connections closed on accept because maxInboundConnections connections were already open", vec![(Attributes::new(), series.inbound_rejected as f64)]),
        Snapshot::counter("mock_server_inbound_connections_idle_closed", "Inbound connections closed after inboundConnectionIdleTimeoutMillis with nothing in progress", vec![(Attributes::new(), series.inbound_idle_closed as f64)]),
        Snapshot::counter("mock_server_http1_pipelining_wedged_connections", "HTTP/1.1 connections whose pipelined requests were held behind a response that made no progress for inboundConnectionIdleTimeoutMillis (closed), or for 300 seconds when that timeout is 0 (left open)", vec![(Attributes::new(), series.http1_pipelining_wedged as f64)]),
        Snapshot::counter(
            "mock_server_response_write_stalls",
            "Responses cut because their client took none of what was waiting for it for responseWriteStallTimeoutMillis, by protocol (http1_1, http2, http3, tunnel, websocket, other) and scope (connection: the connection was closed; stream: one HTTP/2 or HTTP/3 stream was reset)",
            RESPONSE_WRITE_STALLS
                .iter()
                .map(|&(p, s)| {
                    let count = series.response_write_stalls.get(&(p, s)).copied().unwrap_or(0) as f64;
                    (vec![("protocol".to_string(), p.to_string()), ("scope".to_string(), s.to_string())], count)
                })
                .collect(),
        ),
        Snapshot::counter(
            "mock_server_websocket_read_pauses",
            "Times a mocked WebSocket connection stopped reading because too many delayed reply sets were pending on it",
            vec![(Attributes::new(), series.websocket_read_pauses as f64)],
        ),
        Snapshot::counter(
            "mock_server_dropped_drift_analyses",
            "Number of forwarded responses not analysed for mock drift because the drift-analysis backlog was full",
            vec![(Attributes::new(), dropped_drift_analyses as f64)],
        ),
    ]
}

/// The HTTP server set under the OTel-to-Prometheus mapping of the HTTP semconv: the duration
/// histogram with the semconv buckets, an unset attribute an absent label, and the in-flight gauge; each once a request
/// was seen.
fn http_server_snapshots(series: &Series) -> Vec<Snapshot> {
    let mut families = Vec::new();
    if !series.http_server_duration.is_empty() {
        families.push(Snapshot {
            name: "http_server_request_duration_seconds".into(),
            help: "Duration of HTTP server requests.".into(),
            data: Data::Histogram(series.http_server_duration.iter().map(|(labels, h)| HistogramPoint::of(labels.clone(), h)).collect()),
        });
    }
    if !series.http_server_active.is_empty() {
        let points = series.http_server_active.iter().map(|((method, scheme), n)| (vec![("http_request_method".to_string(), method.to_string()), ("url_scheme".to_string(), scheme.to_string())], *n as f64)).collect();
        families.push(Snapshot::gauge("http_server_active_requests", "Number of active HTTP server requests.", points));
    }
    families
}

/// [`http_server_snapshots`]' in-flight gauge as the OTLP up-down counter `http.server.active_requests` (the duration
/// histogram is [`Metrics::collect_otel_histograms`]).
fn http_server_otel_points(metrics: &Metrics) -> Vec<OtelPoint> {
    let series = metrics.series.lock();
    series
        .http_server_active
        .iter()
        .map(|((method, scheme), n)| OtelPoint {
            name: "http.server.active_requests".into(),
            description: "Number of active HTTP server requests.".into(),
            unit: "{request}",
            monotonic: false,
            up_down: true,
            value: OtelValue::Long(*n),
            attributes: vec![("http.request.method".into(), method.to_string()), ("url.scheme".into(), scheme.to_string())],
        })
        .collect()
}

/// The connection set and the forward pool: the active-connection gauge, the connection and
/// TLS handshake histograms and `http_client_open_connections`; each once something was measured.
fn connection_snapshots(series: &Series) -> Vec<Snapshot> {
    let mut families = Vec::new();
    if !series.connections_active.is_empty() {
        let points = series
            .connections_active
            .iter()
            .map(|((transport, tls), n)| (vec![("network_transport".to_string(), transport.to_string()), ("tls".to_string(), tls.to_string())], *n as f64))
            .collect();
        families.push(Snapshot::gauge("mock_server_active_connections", ACTIVE_CONNECTIONS_HELP, points));
    }
    for (name, help, histograms) in [
        ("mock_server_connection_duration_seconds", CONNECTION_DURATION_HELP, &series.connection_duration),
        ("mock_server_tls_handshake_duration_seconds", TLS_HANDSHAKE_HELP, &series.tls_handshake_duration),
    ] {
        if !histograms.is_empty() {
            families.push(Snapshot { name: name.into(), help: help.into(), data: Data::Histogram(histograms.iter().map(|(labels, h)| HistogramPoint::of(labels.clone(), h)).collect()) });
        }
    }
    if !series.forward_pool_open.is_empty() {
        let points = series
            .forward_pool_open
            .iter()
            .map(|((state, address, port), n)| (vec![("http_connection_state".to_string(), state.to_string()), ("server_address".to_string(), address.clone()), ("server_port".to_string(), port.to_string())], *n as f64))
            .collect();
        families.push(Snapshot::gauge("http_client_open_connections", FORWARD_POOL_HELP, points));
    }
    families
}

/// [`connection_snapshots`]' two gauges as OTLP up-down counters, `mock_server.active_connections` and
/// `http.client.open_connections` (the histograms are [`Metrics::collect_otel_histograms`]).
fn connection_otel_points(metrics: &Metrics) -> Vec<OtelPoint> {
    let series = metrics.series.lock();
    let point = |name: &str, description: &str, n: i64, attributes: Attributes| OtelPoint {
        name: name.into(),
        description: description.into(),
        unit: "{connection}",
        monotonic: false,
        up_down: true,
        value: OtelValue::Long(n),
        attributes,
    };
    let mut out: Vec<OtelPoint> = series
        .connections_active
        .iter()
        .map(|((transport, tls), n)| point("mock_server.active_connections", ACTIVE_CONNECTIONS_HELP, *n, vec![("network.transport".into(), transport.to_string()), ("tls".into(), tls.to_string())]))
        .collect();
    out.extend(series.forward_pool_open.iter().map(|((state, address, port), n)| {
        point("http.client.open_connections", FORWARD_POOL_HELP, *n, vec![("http.connection.state".into(), state.to_string()), ("server.address".into(), address.clone()), ("server.port".into(), port.to_string())])
    }));
    out
}

/// The process's own figures, standing in for `JvmMetricsCollector`: the standard `process_*` set, each series
/// only where the platform gives its figure ([`process::read`]).
fn process_metrics() -> Vec<Snapshot> {
    let p = process::read();
    let mut families = vec![
        Snapshot::counter("process_cpu_seconds", "Total user and system CPU time spent in seconds", vec![(Vec::new(), p.cpu_user_seconds + p.cpu_system_seconds)]),
        Snapshot::gauge("process_max_resident_memory_bytes", "Maximum resident set size in bytes", vec![(Vec::new(), p.max_resident_bytes)]),
        Snapshot::counter(
            "process_console_lines_dropped",
            "Console lines dropped because stdout did not keep up",
            vec![(Vec::new(), crate::log::console_lines_dropped() as f64)],
        ),
    ];
    for (name, help, value) in [
        ("process_resident_memory_bytes", "Resident memory size in bytes", p.resident_bytes),
        ("process_virtual_memory_bytes", "Virtual memory size in bytes", p.virtual_bytes),
        ("process_virtual_memory_max_bytes", "Maximum amount of virtual memory available in bytes", p.virtual_max_bytes),
        ("process_open_fds", "Number of open file descriptors", p.open_fds),
        ("process_max_fds", "Maximum number of open file descriptors", p.max_fds),
        ("process_start_time_seconds", "Start time of the process since unix epoch in seconds", p.start_time_seconds),
        ("process_threads", "Number of OS threads in the process", p.threads),
    ] {
        if let Some(value) = value {
            families.push(Snapshot::gauge(name, help, vec![(Vec::new(), value)]));
        }
    }
    families
}

/// The tokio runtime set, read now from `runtime`'s `RuntimeMetrics`, stable API only (no
/// `tokio_unstable`): tokio-metrics' field names with Prometheus units and suffixes, the per-worker counters labelled
/// `worker`. The per-worker figures need 64-bit atomics (`target_has_atomic = "64"`), as tokio does.
fn tokio_snapshots(runtime: &tokio::runtime::Handle) -> Vec<Snapshot> {
    let m = runtime.metrics();
    #[allow(unused_mut)]
    let mut families = vec![
        Snapshot::gauge("tokio_workers_count", "Number of worker threads of the tokio runtime", vec![(Vec::new(), m.num_workers() as f64)]),
        Snapshot::gauge("tokio_live_tasks_count", "Number of alive tasks in the tokio runtime", vec![(Vec::new(), m.num_alive_tasks() as f64)]),
        Snapshot::gauge("tokio_global_queue_depth", "Number of tasks in the tokio runtime's global queue", vec![(Vec::new(), m.global_queue_depth() as f64)]),
    ];
    #[cfg(target_has_atomic = "64")]
    {
        let worker = |i: usize| vec![("worker".to_string(), i.to_string())];
        let workers = 0..m.num_workers();
        families.push(Snapshot::counter("tokio_worker_park", "Total times each tokio worker thread has parked", workers.clone().map(|i| (worker(i), m.worker_park_count(i) as f64)).collect()));
        families.push(Snapshot::counter(
            "tokio_worker_busy_seconds",
            "Total time each tokio worker thread has been busy, in seconds",
            workers.map(|i| (worker(i), m.worker_total_busy_duration(i).as_secs_f64())).collect(),
        ));
    }
    families
}

/// [`tokio_snapshots`]'s set as OTLP instruments (no semconv exists for tokio, so the names are ours): the three
/// counts up-down counters, as semconv's `*.count` instruments are, and the per-worker park count and busy time
/// monotonic counters with the attribute `tokio.worker`.
pub fn tokio_otel_points(runtime: &tokio::runtime::Handle) -> Vec<OtelPoint> {
    let m = runtime.metrics();
    let instrument = |name: &str, description: &str, unit: &'static str, monotonic: bool, value: OtelValue, attributes: Attributes| OtelPoint {
        name: name.into(),
        description: description.into(),
        unit,
        monotonic,
        up_down: !monotonic,
        value,
        attributes,
    };
    #[allow(unused_mut)]
    let mut out = vec![
        instrument("tokio.workers.count", "Number of worker threads of the tokio runtime.", "{thread}", false, OtelValue::Long(m.num_workers() as i64), Vec::new()),
        instrument("tokio.live_tasks.count", "Number of alive tasks in the tokio runtime.", "{task}", false, OtelValue::Long(m.num_alive_tasks() as i64), Vec::new()),
        instrument("tokio.global_queue.depth", "Number of tasks in the tokio runtime's global queue.", "{task}", false, OtelValue::Long(m.global_queue_depth() as i64), Vec::new()),
    ];
    #[cfg(target_has_atomic = "64")]
    {
        let worker = |i: usize| vec![("tokio.worker".to_string(), i.to_string())];
        for i in 0..m.num_workers() {
            out.push(instrument("tokio.worker.park.count", "Total times the tokio worker thread has parked.", "{park}", true, OtelValue::Long(m.worker_park_count(i) as i64), worker(i)));
        }
        for i in 0..m.num_workers() {
            let busy = m.worker_total_busy_duration(i).as_secs_f64();
            out.push(instrument("tokio.worker.busy.time", "Total time the tokio worker thread has been busy.", "s", true, OtelValue::Double(busy), worker(i)));
        }
    }
    out
}

/// `mock_server_native_build_info`'s labels: this build's version, the MockServer version it reproduces, and the compiler,
/// target and commit `build.rs` recorded (`unknown` for a commit not given in `MOCK_SERVER_GIT_HASH` nor found by git).
pub fn rs_build_info() -> Attributes {
    [
        ("git_hash", env!("MOCK_SERVER_GIT_HASH")),
        ("mockserver_version", crate::control::VERSION),
        ("rustc", env!("MOCK_SERVER_RUSTC")),
        ("target", env!("MOCK_SERVER_TARGET")),
        ("version", env!("CARGO_PKG_VERSION")),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect()
}

/// `MetricLabels.routeOf`: the path without its query, id-like segments (digits, UUIDs, 16+ hex digits) as `{id}`.
pub fn route_of(path: Option<&str>) -> String {
    let Some(path) = path.filter(|p| !p.trim().is_empty()) else { return "/".into() };
    let without_query = path.split('?').next().unwrap_or_default();
    if without_query.is_empty() {
        return "/".into();
    }
    let hex = |c: char| c.is_ascii_hexdigit();
    let id_like = |s: &str| {
        !s.is_empty()
            && (s.chars().all(|c| c.is_numeric())
                || (s.len() == 36 && s.char_indices().all(|(i, c)| if matches!(i, 8 | 13 | 18 | 23) { c == '-' } else { hex(c) }))
                || (s.chars().count() >= 16 && s.chars().all(hex)))
    };
    let route = without_query.split('/').map(|s| if id_like(s) { "{id}" } else { s }).collect::<Vec<_>>().join("/");
    if route.is_empty() { "/".into() } else { route }
}

#[cfg(test)]
mod tests {
    use super::{per_expectation_enabled, route_of, snapshots, Metrics};

    mod dashboards;

    fn config(properties: &[(&str, &str)]) -> crate::Config {
        properties.iter().fold(crate::Config::for_tests(), |c, (k, v)| c.with_property(k, v))
    }

    /// Ports of `PerExpectationMetricsTest` (`incrementIsNoOpForNullId` has no counterpart: an id is never null here).
    #[test]
    fn per_expectation_property_on_registers_the_counter() {
        assert!(per_expectation_enabled(&config(&[("metricsEnabled", "true"), ("perExpectationMetricsEnabled", "true")])));
        assert!(per_expectation_enabled(&config(&[("metricsEnabled", "true"), ("perExpectationMetrics", "true")])), "the legacy key");
        assert!(!per_expectation_enabled(&config(&[("metricsEnabled", "true"), ("perExpectationMetrics", "true"), ("perExpectationMetricsEnabled", "false")])));
        assert!(!per_expectation_enabled(&config(&[("perExpectationMetricsEnabled", "true")])), "metrics off");
    }

    #[test]
    fn per_expectation_matches_count_per_id() {
        // propertyOnMatchingExpectationIncrementsItsPerIdCounter, propertyOnDifferentExpectationsGetSeparateSeries
        let metrics = Metrics::default();
        metrics.expectation_matched("expectation-a");
        metrics.expectation_matched("expectation-b");
        metrics.expectation_matched("expectation-b");
        assert_eq!(metrics.expectation_matched_count("expectation-a"), 1);
        assert_eq!(metrics.expectation_matched_count("expectation-b"), 2);
        assert_eq!(metrics.expectation_matched_count("expectation-c"), 0);
    }

    #[test]
    fn per_expectation_off_or_unset_registers_no_series() {
        // propertyOffByDefaultRegistersNoSeries, propertyUnsetRegistersNoSeries
        for properties in [&[("metricsEnabled", "true"), ("perExpectationMetricsEnabled", "false")][..], &[("metricsEnabled", "true")][..]] {
            let state = crate::state::State::new(config(properties), Vec::new());
            assert!(!per_expectation_enabled(&state.config));
            state.config.metrics.expectation_matched("expectation-a");
            assert!(!snapshots(&state).iter().any(|s| s.name == "mock_server_expectation_matched"));
        }
    }

    /// Ports of `LlmMetricsTest`: `recordLlmUsageMetrics` is `llm::budget::record` (provider and model as the
    /// expectation names them), `incrementLlmTokens` is `Metrics::llm_tokens`.
    fn llm_state(llm_metrics: &str) -> std::sync::Arc<crate::state::State> {
        crate::state::State::new(config(&[("metricsEnabled", "true"), ("llmMetricsEnabled", llm_metrics)]), Vec::new())
    }

    #[test]
    fn llm_token_counters_increment() {
        // shouldIncrementTokenCounters, shouldAccumulateAcrossMultipleCompletions
        let state = llm_state("true");
        assert!(super::llm_metrics_enabled(&state.config));
        state.config.metrics.llm_tokens(Some("ANTHROPIC"), Some("claude-opus-4"), 100, 50, None);
        assert_eq!(state.config.metrics.llm_usage("ANTHROPIC", "claude-opus-4"), (100, 50, 0.0));
        crate::llm::budget::record(&state, "OPENAI", Some("gpt-4o"), 200, 100);
        crate::llm::budget::record(&state, "OPENAI", Some("gpt-4o"), 300, 150);
        let (input, output, _) = state.config.metrics.llm_usage("OPENAI", "gpt-4o");
        assert_eq!((input, output), (500, 250));
    }

    #[test]
    fn llm_cost_counter_and_budget_monitor() {
        // shouldIncrementCostCounter, shouldRecordCostOnBudgetMonitor, shouldTrackTotalCostAcrossAllModels
        let state = llm_state("true");
        crate::llm::budget::record(&state, "ANTHROPIC", Some("claude-opus-4"), 1_000_000, 1_000_000);
        assert!((state.config.metrics.llm_usage("ANTHROPIC", "claude-opus-4").2 - 90.0).abs() < 0.01);
        let state = llm_state("true");
        crate::llm::budget::record(&state, "ANTHROPIC", Some("claude-opus-4"), 1_000_000, 0);
        assert!((state.config.metrics.cost_budget.cumulative_usd() - 15.0).abs() < 0.01);
        assert!(state.config.metrics.cost_budget.exceeded(0.10));
        crate::llm::budget::record(&state, "OPENAI", Some("gpt-4o"), 1_000_000, 0);
        assert!((state.config.metrics.llm_cost_usd_total() - 17.5).abs() < 0.01);
    }

    #[test]
    fn llm_usage_without_tokens_or_names() {
        // shouldHandleNullUsageGracefully, shouldHandleNullCompletionGracefully (no completion records nothing),
        // shouldUseUnknownForNullProviderOrModel
        let state = llm_state("true");
        crate::llm::budget::record(&state, "ANTHROPIC", Some("claude-opus-4"), 0, 0);
        assert_eq!(state.config.metrics.llm_usage("ANTHROPIC", "claude-opus-4"), (0, 0, 0.0));
        state.config.metrics.llm_tokens(None, None, 100, 50, None);
        assert_eq!(state.config.metrics.llm_usage("unknown", "unknown"), (100, 50, 0.0));
    }

    #[test]
    fn llm_counters_off_without_llm_metrics() {
        // shouldNotIncrementWhenLlmMetricsDisabled
        let state = llm_state("false");
        assert!(!super::llm_metrics_enabled(&state.config));
        crate::llm::budget::record(&state, "ANTHROPIC", Some("claude-opus-4"), 100, 50);
        assert_eq!(state.config.metrics.llm_usage("ANTHROPIC", "claude-opus-4"), (0, 0, 0.0));
    }

    /// `MetricsTest`'s load-family cases: the allowlist projects the custom labels, eviction drops one run.
    #[test]
    fn load_request_labels_and_eviction() {
        let state = crate::state::State::new(config(&[("metricsEnabled", "true"), ("loadGenerationMetricLabels", " team ,, env")]), Vec::new());
        let allowlist = super::load_label_names(&state.config);
        assert_eq!(allowlist, ["team", "env"]);
        let custom = vec![("team".to_string(), "a".to_string()), ("zone".to_string(), "eu".to_string())];
        let metrics = &state.config.metrics;
        metrics.observe_load_request(&allowlist, ["s", "run-1", "0", "/x", "GET", "2xx"], &custom, 0.003, 0, 5, Some("abc"));
        metrics.observe_load_request(&allowlist, ["s", "run-2", "0", "/x", "GET", "2xx"], &custom, 0.003, 0, 5, None);
        let text = super::exposition_as(&state, true).unwrap();
        let labels = r#"env="",method="GET",route="/x",run_id="run-1",scenario="s",status_class="2xx",step="0",team="a""#;
        assert!(text.contains(&format!("mock_server_load_requests_total{{{labels}}} 1.0")), "{text}");
        assert!(text.contains(&format!("mock_server_load_request_duration_seconds_bucket{{{labels},le=\"0.005\"}} 1 # {{trace_id=\"abc\"}} 0.003 ")), "{text}");
        assert!(!text.contains("mock_server_load_request_bytes"), "a zero byte count is not added");
        assert!(!text.contains("zone"), "a label outside the allowlist is Prometheus-free");
        metrics.evict_load_run("run-1");
        let text = super::exposition(&state).unwrap();
        assert!(!text.contains("run-1") && text.contains("run-2"));
        let otlp = super::otel_points(&state);
        assert!(otlp.iter().any(|p| p.name == "mock_server_load_requests" && p.attributes.iter().any(|(k, v)| k == "run_id" && v == "run-1")), "OTLP keeps the evicted run");
        assert!(otlp.iter().any(|p| p.attributes.iter().any(|(k, _)| k == "zone")), "OTLP carries every custom label");
    }

    // MetricsTest (upstream/mockserver/.../metrics/MetricsTest.java). A scrape is `snapshots`/`exposition` of a state
    // with `metricsEnabled`; the "does not throw when disabled / null argument" cases have no counterpart (the
    // recorders take `&str` and are infallible, and the families are only served while enabled).

    fn enabled_state(properties: &[(&str, &str)]) -> std::sync::Arc<crate::state::State> {
        let mut all = vec![("metricsEnabled", "true")];
        all.extend_from_slice(properties);
        crate::state::State::new(config(&all), Vec::new())
    }

    fn family(state: &crate::state::State, name: &str) -> Option<super::Snapshot> {
        snapshots(state).into_iter().find(|s| s.name == name)
    }

    /// A counter's or gauge's value at the point carrying `label`, 0 when absent (as `scrapeCounterValue` reads it).
    fn value(state: &crate::state::State, name: &str, label: Option<(&str, &str)>) -> f64 {
        let Some(f) = family(state, name) else { return 0.0 };
        let points = match f.data {
            super::Data::Counter(p) | super::Data::Gauge(p) => p,
            super::Data::Histogram(_) => panic!("{name} is a histogram"),
        };
        points.iter().find(|(l, _)| label.is_none_or(|(k, v)| l.iter().any(|(lk, lv)| lk == k && lv == v))).map_or(0.0, |(_, v)| *v)
    }

    fn histogram_count(state: &crate::state::State, name: &str, label: Option<(&str, &str)>) -> u64 {
        match family(state, name).map(|f| f.data) {
            Some(super::Data::Histogram(points)) => points.iter().find(|p| label.is_none_or(|(k, v)| p.labels.iter().any(|(lk, lv)| lk == k && lv == v))).map_or(0, |p| p.count),
            _ => 0,
        }
    }

    /// The standard set on the scrape, as gauges (the CPU time a counter), on the platforms
    /// whose figures `process::read` gives.
    #[test]
    fn scrape_carries_the_standard_process_set() {
        let state = enabled_state(&[]);
        let text = super::exposition(&state).unwrap();
        assert!(text.contains("# TYPE process_cpu_seconds_total counter\n"), "{text}");
        assert!(value(&state, "process_max_resident_memory_bytes", None) > 0.0);
        let names = [
            "process_resident_memory_bytes",
            "process_virtual_memory_bytes",
            "process_virtual_memory_max_bytes",
            "process_open_fds",
            "process_max_fds",
            "process_start_time_seconds",
            "process_threads",
        ];
        for name in names {
            let present = family(&state, name).is_some_and(|f| matches!(f.data, super::Data::Gauge(_)));
            assert_eq!(present, cfg!(any(target_os = "linux", target_os = "macos")), "{name}");
        }
        assert!(!text.contains("process_heap_bytes") && !text.contains("jvm_"), "left out, never faked");
        if cfg!(any(target_os = "linux", target_os = "macos")) {
            assert!(value(&state, "process_open_fds", None) <= value(&state, "process_max_fds", None));
            assert!(value(&state, "process_resident_memory_bytes", None) <= value(&state, "process_virtual_memory_bytes", None));
        }
    }

    /// Ours beside upstream's, whose values stay.
    #[test]
    fn scrape_carries_both_build_infos() {
        let state = enabled_state(&[]);
        let text = super::exposition(&state).unwrap();
        let upstream = r#"mock_server_build_info{artifact_id="mockserver-core",git_hash="789142c1",group_id="org.mock-server",major_minor_version="9.2",version="9.2.0"} 1.0"#;
        assert!(text.contains(upstream), "{text}");
        let labels = super::rs_build_info();
        let keys: Vec<&str> = labels.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, ["git_hash", "mockserver_version", "rustc", "target", "version"]);
        let get = |k: &str| labels.iter().find(|(lk, _)| lk == k).map(|(_, v)| v.as_str()).unwrap();
        assert_eq!(get("mockserver_version"), crate::control::VERSION);
        assert_eq!(get("version"), env!("CARGO_PKG_VERSION"));
        assert!(get("rustc").split('.').count() >= 3 && get("rustc").chars().next().unwrap().is_ascii_digit(), "{labels:?}");
        assert!(get("target").contains(std::env::consts::ARCH), "{labels:?}");
        assert!(!get("git_hash").is_empty());
        assert_eq!(value(&state, "mock_server_native_build_info", Some(("mockserver_version", crate::control::VERSION))), 1.0);
        assert!(text.contains("# TYPE mock_server_native_build_info gauge\nmock_server_native_build_info{git_hash="), "{text}");
    }

    #[test]
    fn metrics_request_duration_histograms() {
        // registersAndRecordsRequestDurationHistogram, observeRequestDurationDoesNotThrow,
        // registersMethodLabeledHistogramWhenEnabled, observeRequestDurationByMethodDoesNotThrowWhenDisabled
        let state = enabled_state(&[]);
        state.config.metrics.request_handled(0.05);
        assert_eq!(histogram_count(&state, "mock_server_request_duration_seconds", None), 1);
        assert!(family(&state, "mock_server_request_duration_by_method_seconds").is_none(), "route labels off");
        let state = enabled_state(&[("metricsRequestDurationRouteLabels", "true")]);
        state.config.metrics.request_handled_by_method("GET", 0.05);
        assert_eq!(histogram_count(&state, "mock_server_request_duration_by_method_seconds", Some(("method", "GET"))), 1);
    }

    /// The cumulative count of a histogram's bucket bounded by `bound`.
    fn bucket_at(state: &crate::state::State, name: &str, bound: f64) -> u64 {
        match family(state, name).map(|f| f.data) {
            Some(super::Data::Histogram(points)) => points[0].buckets.iter().take_while(|(b, _)| *b <= bound).map(|(_, n)| n).sum(),
            _ => panic!("{name} is no histogram"),
        }
    }

    #[test]
    fn metrics_transport_and_read_to_decode_histograms() {
        // recordsTransportDurationWithABucketBoundaryAtFiveMilliseconds,
        // recordsReadToDecodeDurationWithBucketBoundariesBelowAMillisecondAndAtFive
        let state = enabled_state(&[]);
        for name in ["mock_server_request_transport_duration_seconds", "mock_server_request_read_to_decode_duration_seconds"] {
            assert_eq!(histogram_count(&state, name, None), 0, "{name} exported before its first observation");
        }
        for seconds in [0.004, 0.006, 0.040] {
            state.config.metrics.request_transport(seconds);
        }
        assert_eq!(histogram_count(&state, "mock_server_request_transport_duration_seconds", None), 3);
        assert_eq!(bucket_at(&state, "mock_server_request_transport_duration_seconds", 0.005), 1);
        assert!(super::TRANSPORT_BUCKETS.contains(&0.005));
        for seconds in [0.00005, 0.004, 0.006] {
            state.config.metrics.request_read_to_decode(seconds);
        }
        assert_eq!(histogram_count(&state, "mock_server_request_read_to_decode_duration_seconds", None), 3);
        assert_eq!(bucket_at(&state, "mock_server_request_read_to_decode_duration_seconds", 0.0001), 1);
        assert_eq!(bucket_at(&state, "mock_server_request_read_to_decode_duration_seconds", 0.005), 2);
        let text = super::exposition(&state).unwrap();
        assert_eq!(text.matches("mock_server_request_transport_duration_seconds_bucket{").count(), super::TRANSPORT_BUCKETS.len() + 1);
        assert_eq!(text.matches("mock_server_request_read_to_decode_duration_seconds_bucket{").count(), super::READ_TO_DECODE_BUCKETS.len() + 1);
    }

    #[test]
    fn metrics_labelled_counters_exported_at_zero() {
        // exportsEveryDroppedLogEventReasonAtZeroBeforeAnyDrop, exportsEveryResponseWriteStallKindAtZeroBeforeAnyStall
        let state = enabled_state(&[]);
        let points = |name: &str| match family(&state, name).map(|f| f.data) {
            Some(super::Data::Counter(points)) => points,
            _ => panic!("{name} is no counter"),
        };
        let reasons: Vec<String> = points("mock_server_dropped_log_events").iter().map(|(l, v)| format!("{}={v}", l[0].1)).collect();
        assert_eq!(reasons, ["in_flight_bytes=0", "ring_full=0"]);
        let stalls: Vec<String> = points("mock_server_response_write_stalls").iter().map(|(l, _)| format!("{}/{}", l[0].1, l[1].1)).collect();
        assert_eq!(stalls, ["http1_1/connection", "http2/connection", "http2/stream", "http3/stream", "other/connection", "tunnel/connection", "websocket/connection"]);
        for name in ["mock_server_inbound_connections_rejected", "mock_server_inbound_connections_idle_closed", "mock_server_http1_pipelining_wedged_connections", "mock_server_websocket_read_pauses", "mock_server_dropped_drift_analyses", "mock_server_expectations_byte_evicted"] {
            assert_eq!(points(name), [(Vec::new(), 0.0)], "{name}");
        }
    }

    #[test]
    fn metrics_open_inbound_connections() {
        // reportsOpenInboundConnectionsAsTheyOpenAndClose: TCP connections only, HTTP/3 excluded
        let state = enabled_state(&[]);
        let open = |state: &crate::state::State| value(state, "mock_server_inbound_connections_open", None);
        let first = super::ServerConnection::open(&state.config, "tcp", false).unwrap();
        let mut second = super::ServerConnection::open(&state.config, "tcp", false).unwrap();
        second.tls();
        let quic = super::ServerConnection::open(&state.config, "udp", true).unwrap();
        assert_eq!(open(&state), 2.0);
        drop(first);
        assert_eq!(open(&state), 1.0);
        drop((second, quic));
        assert_eq!(open(&state), 0.0);
    }

    #[test]
    fn metrics_accept_queue_backlog() {
        // alwaysEmitsConfiguredAcceptQueueBacklog, omitsEffectiveAcceptQueueBacklogWhenSomaxconnUnreadable
        let state = enabled_state(&[("soBacklog", "2048")]);
        assert_eq!(value(&state, "mock_server_accept_queue_backlog_configured", None), 2048.0);
        let effective = family(&state, "mock_server_accept_queue_backlog_effective");
        match super::somaxconn() {
            Some(kernel) => assert_eq!(value(&state, "mock_server_accept_queue_backlog_effective", None), 2048.0_f64.min(kernel as f64)),
            None => assert!(effective.is_none(), "omitted where somaxconn is unreadable"),
        }
    }

    #[test]
    fn metrics_event_log_and_store_gauges() {
        // registersEventLogRingGauges, eventLogRetainedGaugesReflectSupplierValue, registersExpectationStoreByteGauges
        let state = enabled_state(&[("maxLogEntries", "500"), ("maxEventLogSizeInBytes", "4096")]);
        assert_eq!(value(&state, "mock_server_event_log_max_retained_entries", None), 500.0);
        assert_eq!(value(&state, "mock_server_event_log_max_retained_bytes", None), 4096.0);
        assert_eq!(value(&state, "mock_server_event_log_ring_capacity", None), 512.0, "ringBufferSize: maxLogEntries rounded up to a power of two");
        assert_eq!(value(&state, "mock_server_event_log_ring_occupancy", None), 0.0);
        let heap_cap = (crate::config::ORACLE_HEAP_AVAILABLE_KB / 7 * 1024) as f64;
        assert_eq!(value(&state, "mock_server_event_log_max_in_flight_bytes", None), heap_cap, "the larger of the budget and a seventh of the heap at INFO");
        let debug = enabled_state(&[("maxEventLogSizeInBytes", "4096"), ("logLevel", "DEBUG")]);
        let debug_cap = (crate::config::ORACLE_HEAP_AVAILABLE_KB / 12 * 1024) as f64;
        assert_eq!(value(&debug, "mock_server_event_log_max_in_flight_bytes", None), debug_cap, "a twelfth at DEBUG");
        let unbounded = enabled_state(&[("maxEventLogSizeInBytes", "0")]);
        assert_eq!(value(&unbounded, "mock_server_event_log_max_in_flight_bytes", None), 0.0, "no retention budget, no in-flight cap");
        assert_eq!(value(&state, "mock_server_expectations_bytes", None), 0.0);
        assert_eq!(value(&state, "mock_server_max_expectations_bytes", None), 0.0);
    }

    #[test]
    fn metrics_slow_request_counter() {
        // registersSlowRequestCounter, incrementSlowRequestTotalDoesNotThrowWhenDisabled
        let state = enabled_state(&[]);
        state.config.metrics.slow_request();
        assert_eq!(value(&state, "mock_server_slow_requests", None), 1.0);
    }

    #[test]
    fn metrics_http_chaos_injected_counter_per_fault_type() {
        // registersHttpChaosInjectedCounter, httpChaosInjectedCounterIncrementsPerFaultType
        let state = enabled_state(&[]);
        for fault in ["error", "error", "latency"] {
            state.config.metrics.chaos_injected(fault);
        }
        assert_eq!(value(&state, "mock_server_http_chaos_injected", Some(("fault_type", "error"))), 2.0);
        assert_eq!(value(&state, "mock_server_http_chaos_injected", Some(("fault_type", "latency"))), 1.0);
    }

    #[test]
    fn metrics_active_service_chaos_gauge_reflects_live_registry_by_fault_type() {
        // registersActiveServiceChaosGauge, activeServiceChaosGaugeReflectsLiveRegistryByFaultType,
        // getActiveServiceChaosCountByFaultTypeDoesNotThrowWhenDisabled
        use crate::chaos::http::HttpChaosProfile;
        let state = enabled_state(&[]);
        let metric = "mock_server_active_service_chaos";
        assert!(family(&state, metric).is_some());
        assert_eq!(value(&state, metric, Some(("fault_type", "error"))), 0.0, "no chaos registered");
        state.chaos.service.put("a.svc", HttpChaosProfile { error_status: Some(503), drop_connection_probability: Some(0.5), ..Default::default() }, 0);
        state.chaos.service.put("b.svc", HttpChaosProfile { error_status: Some(500), ..Default::default() }, 0);
        assert_eq!(value(&state, metric, Some(("fault_type", "error"))), 2.0);
        assert_eq!(value(&state, metric, Some(("fault_type", "drop"))), 1.0);
        assert_eq!(value(&state, metric, Some(("fault_type", "latency"))), 0.0);
        state.chaos.service.remove("a.svc");
        assert_eq!(value(&state, metric, Some(("fault_type", "error"))), 1.0, "follows removals");
        assert_eq!(value(&state, metric, Some(("fault_type", "drop"))), 0.0);
        state.chaos.service.reset();
        assert_eq!(value(&state, metric, Some(("fault_type", "error"))), 0.0, "drops to zero when cleared");
    }

    #[test]
    fn metrics_forward_observability() {
        // registersForwardObservabilityMetrics, forwardRequestsCounterLabelsByHostAndStatusClass,
        // forwardObservabilityRecordsLatencyHistogram, getForwardRequestCountReturnsPerHostStatusClassCount,
        // forwardObservabilityNullHostRecordedAsUnknown, forwardObservabilityNullStatusRecordedAsUnknownClass
        let state = enabled_state(&[]);
        let metrics = &state.config.metrics;
        for (host, status) in [("api.example.com", 200), ("api.example.com", 204), ("api.example.com", 502), ("other.example.com", 200)] {
            metrics.forwarded(host, 0.01, status);
        }
        assert_eq!(metrics.forward_request_count("api.example.com", "2xx"), 2);
        assert_eq!(metrics.forward_request_count("api.example.com", "5xx"), 1);
        assert_eq!(metrics.forward_request_count("other.example.com", "2xx"), 1);
        assert_eq!(metrics.forward_request_count("nonexistent", "2xx"), 0);
        assert_eq!(histogram_count(&state, "mock_server_forward_request_duration_seconds", Some(("upstream_host", "other.example.com"))), 1);
        let text = super::exposition(&state).unwrap();
        assert!(text.contains(r#"mock_server_forward_requests_total{status_class="5xx",upstream_host="api.example.com"} 1.0"#), "{text}");
        metrics.forwarded("", 0.01, 200);
        assert_eq!(metrics.forward_request_count("unknown", "2xx"), 1);
        metrics.forwarded("api.example.com", 0.01, 0);
        assert_eq!(metrics.forward_request_count("api.example.com", "unknown"), 1);
    }

    #[test]
    fn metrics_forward_host_labels_are_capped_with_the_overflow_recorded_as_other() {
        // forwardHostLabelsAreCappedWithTheOverflowRecordedAsOther: 500 hosts get a label of their own, the rest share
        // `_other`, and a host seen before the cap keeps its own; the protocol counter shares the same cap
        let state = enabled_state(&[]);
        let metrics = &state.config.metrics;
        for i in 0..super::MAX_FORWARD_HOST_LABELS + 20 {
            metrics.forwarded(&format!("host{i}.example.com"), 0.01, 200);
        }
        metrics.forwarded("host0.example.com", 0.01, 200);
        assert_eq!(metrics.forward_request_count("host0.example.com", "2xx"), 2);
        assert_eq!(metrics.forward_request_count(&format!("host{}.example.com", super::MAX_FORWARD_HOST_LABELS - 1), "2xx"), 1);
        assert_eq!(metrics.forward_request_count(&format!("host{}.example.com", super::MAX_FORWARD_HOST_LABELS), "2xx"), 0);
        assert_eq!(metrics.forward_request_count("_other", "2xx"), 20);
        assert_eq!(histogram_count(&state, "mock_server_forward_request_duration_seconds", Some(("upstream_host", "_other"))), 20);
        metrics.upstream_connection("late.example.com", false);
        assert_eq!(metrics.upstream_protocol_count("_other", "http1_1"), 1);
        metrics.upstream_connection("host3.example.com", true);
        assert_eq!(metrics.upstream_protocol_count("host3.example.com", "http2"), 1);
    }

    #[test]
    fn metrics_forward_upstream_protocol_counter_labels_by_host_and_protocol() {
        // forwardUpstreamProtocolCounterLabelsByHostAndProtocol, incrementForwardUpstreamProtocolDoesNotThrowWhenDisabled
        let state = enabled_state(&[]);
        let metrics = &state.config.metrics;
        metrics.upstream_connection("chatgpt.com", true);
        metrics.upstream_connection("chatgpt.com", true);
        metrics.upstream_connection("api.anthropic.com", false);
        assert!(family(&state, "mock_server_forward_upstream_protocol").is_some());
        assert_eq!(metrics.upstream_protocol_count("chatgpt.com", "http2"), 2);
        assert_eq!(metrics.upstream_protocol_count("api.anthropic.com", "http1_1"), 1);
        assert_eq!(metrics.upstream_protocol_count("chatgpt.com", "http1_1"), 0);
    }

    #[test]
    fn metrics_mcp_tool_calls_counter() {
        // registersMcpToolCallsCounter, mcpToolCallsCounterIncrementsPerToolName, getMcpToolCallCountReturnsPerToolCount
        let state = enabled_state(&[]);
        let metrics = &state.config.metrics;
        for tool in ["create_expectation", "create_expectation", "verify_request", "list_mock_tools", "list_mock_tools", "list_mock_tools"] {
            metrics.mcp_tool_call(tool);
        }
        assert_eq!(value(&state, "mock_server_mcp_tool_calls", Some(("tool", "create_expectation"))), 2.0);
        assert_eq!(value(&state, "mock_server_mcp_tool_calls", Some(("tool", "verify_request"))), 1.0);
        assert_eq!(value(&state, "mock_server_mcp_tool_calls", Some(("tool", "list_mock_tools"))), 3.0);
        assert_eq!(metrics.mcp_tool_call_count("create_expectation"), 2);
        assert_eq!(metrics.mcp_tool_call_count("nonexistent"), 0);
    }

    #[test]
    fn metrics_async_message_counters_per_channel() {
        // registersAsyncMessageCounters, asyncMessageCountersIncrementPerChannel, getAsyncMessageCountsReturnPerChannelCount
        let state = enabled_state(&[]);
        let metrics = &state.config.metrics;
        metrics.async_message(true, "orders/placed");
        metrics.async_message(true, "orders/placed");
        metrics.async_message(true, "payments/processed");
        metrics.async_message(false, "orders/placed");
        assert_eq!(value(&state, "mock_server_async_messages_published", Some(("channel", "orders/placed"))), 2.0);
        assert_eq!(value(&state, "mock_server_async_messages_published", Some(("channel", "payments/processed"))), 1.0);
        assert_eq!(value(&state, "mock_server_async_messages_consumed", Some(("channel", "orders/placed"))), 1.0);
        assert_eq!(metrics.async_message_count(true, "orders/placed"), 2);
        assert_eq!(metrics.async_message_count(false, "orders/placed"), 1);
        assert_eq!(metrics.async_message_count(true, "nonexistent"), 0);
    }

    #[test]
    fn metrics_expectations_by_type_gauge_reflects_active_expectations() {
        // expectationsByTypeGaugeReflectsActiveExpectations, getActiveExpectationCountByTypeDoesNotThrowWhenNoSupplier
        // (registersExpectationsByTypeGauge: an empty family is not written by the text format, so it is left out)
        let state = enabled_state(&[]);
        let metric = "mock_server_expectations_by_type";
        assert_eq!(value(&state, metric, Some(("action_type", "RESPONSE"))), 0.0);
        let compile = |definition: serde_json::Value| crate::control::compile_expectation(&state, definition.as_object().unwrap());
        state.store.upsert(vec![
            compile(serde_json::json!({"id": "a", "httpRequest": {"path": "/a"}, "httpResponse": {"statusCode": 200}})),
            compile(serde_json::json!({"id": "b", "httpRequest": {"path": "/b"}, "httpResponse": {"statusCode": 201}})),
            compile(serde_json::json!({"id": "c", "httpRequest": {"path": "/c"}, "httpError": {"dropConnection": true}})),
        ]);
        assert_eq!(value(&state, metric, Some(("action_type", "RESPONSE"))), 2.0);
        assert_eq!(value(&state, metric, Some(("action_type", "ERROR"))), 1.0);
        assert_eq!(value(&state, metric, Some(("action_type", "FORWARD"))), 0.0);
        state.store.upsert(vec![compile(serde_json::json!({"id": "c", "httpRequest": {"path": "/c"}, "httpResponse": {"statusCode": 200}}))]);
        assert_eq!(value(&state, metric, Some(("action_type", "RESPONSE"))), 3.0, "follows updates");
        assert_eq!(value(&state, metric, Some(("action_type", "ERROR"))), 0.0);
    }

    #[test]
    fn metrics_cluster_members_gauge_defaults_to_one() {
        // registersClusterMembersGauge, clusterMembersGaugeDefaultsToOneWhenNoSupplier (the supplier is the state
        // backend's `clusterInfo().members()`; a clustered membership is covered by the backend's own tests)
        let state = enabled_state(&[]);
        assert_eq!(value(&state, "mock_server_cluster_members", None), 1.0);
    }

    #[test]
    fn metrics_llm_optimisation_gauges() {
        // registersLlmOptimisationGauges, llmOptimisationGaugesReadZeroBeforeAnyReportBuilt,
        // llmOptimisationGaugesReflectLatestSnapshot, updateLlmOptimisationSnapshotIsSafeWhenMetricsDisabled
        let state = enabled_state(&[]);
        let read = |s: &crate::state::State| {
            ["mock_server_llm_estimated_waste_usd", "mock_server_llm_cache_hit_ratio", "mock_server_llm_one_shot_rate"].map(|n| value(s, n, None))
        };
        assert_eq!(read(&state), [0.0, 0.0, 0.0]);
        state.config.metrics.llm_optimisation((1.42, 0.5, 0.6667));
        assert_eq!(read(&state), [1.42, 0.5, 0.6667]);
        state.config.metrics.llm_optimisation((0.0, 1.0, 1.0));
        assert_eq!(read(&state), [0.0, 1.0, 1.0], "latest report wins");
        // clearDropsLlmOptimisationSnapshot tests `Metrics.clear()`, which no server path calls: a reset runs
        // `clearRequestAndExpectationMetrics`, which keeps the snapshot.
        state.config.metrics.reset();
        assert_eq!(read(&state), [0.0, 1.0, 1.0]);
    }

    #[test]
    fn metrics_monotonic_counts_keep_exact_names_and_dual_publish_total_counters() {
        // monotonicCountMetricsKeepExactCountNamesAndAreNotSilentlyRenamed, prometheusClientForcesTotalSuffixOnCounters,
        // dualPublishesTotalCounterAlongsideLegacyCountGauge
        let state = enabled_state(&[]);
        let text = super::exposition(&state).unwrap();
        for (legacy, total) in [
            ("requests_received_count", "mock_server_requests_received_total"),
            ("expectations_not_matched_count", "mock_server_expectations_not_matched_total"),
            ("response_expectations_matched_count", "mock_server_response_expectations_matched_total"),
            ("forward_expectations_matched_count", "mock_server_forward_expectations_matched_total"),
            ("llm_chaos_injected_count", "mock_server_llm_chaos_injected_total"),
        ] {
            assert!(text.contains(&format!("# TYPE {legacy} gauge\n")), "{legacy}");
            assert!(!text.contains(&format!("{legacy}_total")), "{legacy} renamed");
            assert!(text.contains(&format!("# TYPE {total} counter\n")), "{total}");
        }
        assert!(text.contains("# TYPE forward_actions_count gauge\n"));
        assert!(text.contains("# TYPE websocket_callback_clients_count gauge\n"));
    }

    #[test]
    fn metrics_monotonic_total_counter_survives_reset_while_legacy_gauge_is_zeroed() {
        // monotonicTotalCounterIncrementsWithLegacyGauge, getMonotonicTotalCountReturnsZeroWhenDisabledOrNotMonotonic,
        // monotonicTotalCounterSurvivesServerResetWhileLegacyGaugeIsZeroed (its reset is `clearRequestAndExpectationMetrics`,
        // the only one a server runs; `Metrics.clear()` is unreachable, scenario `metrics_reset`)
        use super::Count;
        let state = enabled_state(&[]);
        let metrics = &state.config.metrics;
        assert_eq!(metrics.total(Count::RequestsReceived), 0);
        metrics.increment(Count::RequestsReceived);
        metrics.increment(Count::RequestsReceived);
        metrics.increment(Count::LlmChaosInjected);
        assert_eq!(super::get(&state, "REQUESTS_RECEIVED_COUNT"), Some(2));
        assert_eq!(super::get(&state, "LLM_CHAOS_INJECTED_COUNT"), Some(1));
        assert_eq!((metrics.total(Count::RequestsReceived), metrics.total(Count::LlmChaosInjected)), (2, 1));
        assert_eq!(value(&state, "mock_server_requests_received", None), 2.0);
        assert_eq!(value(&state, "requests_received_count", None), 2.0);
        metrics.increment(Count::RequestsReceived);
        metrics.reset();
        assert_eq!(super::get(&state, "REQUESTS_RECEIVED_COUNT"), Some(0));
        assert_eq!(super::get(&state, "LLM_CHAOS_INJECTED_COUNT"), Some(1), "not one of the three counts a reset clears");
        assert_eq!(metrics.total(Count::RequestsReceived), 3);
    }

    #[test]
    fn metrics_actions_count_constant_for_every_action_type() {
        // shouldHaveActionsCountConstantForEveryActionType
        for (_, kind, name) in super::ACTIONS {
            assert_eq!(*name, format!("{kind}_ACTIONS_COUNT"));
            assert!(super::NAMES.iter().any(|(n, _)| n == name), "{name}");
        }
    }

    /// Ports of `MetricLabelsTest`.
    #[test]
    fn route_of_collapses_id_segments() {
        // collapsesNumericIdSegment, collapsesUuidSegment, collapsesLongHexSegment, collapsesMultipleIdSegments
        assert_eq!(route_of(Some("/api/orders/12345")), "/api/orders/{id}");
        assert_eq!(route_of(Some("/users/9f1c8e0a-1b2c-4d3e-8f90-abcdef012345")), "/users/{id}");
        assert_eq!(route_of(Some("/v2/items/deadbeefcafebabe")), "/v2/items/{id}");
        assert_eq!(route_of(Some("/api/orders/12345/items/67890")), "/api/orders/{id}/items/{id}");
    }

    #[test]
    fn route_of_keeps_route_structure() {
        // keepsNonIdSegmentsVerbatim, dropsQueryString, shortHexTokenIsNotCollapsed, nullOrBlankPathBecomesRoot
        assert_eq!(route_of(Some("/api/orders")), "/api/orders");
        assert_eq!(route_of(Some("/v2/items")), "/v2/items");
        assert_eq!(route_of(Some("/api/orders/12345?expand=true")), "/api/orders/{id}");
        assert_eq!(route_of(Some("/api/abc")), "/api/abc");
        assert_eq!(route_of(None), "/");
        assert_eq!(route_of(Some("")), "/");
    }

    /// The semconv duration histogram's labels (an unset one absent), buckets
    /// and `_OTHER` method, `error_type` for a 5xx and for an exchange dropped unanswered, and the in-flight gauge.
    #[test]
    fn http_server_request_duration_semconv_labels_and_buckets() {
        use super::HttpServerRequest;
        let state = enabled_state(&[]);
        let start = |method: &str, secure: bool, version: &'static str| HttpServerRequest::start(&state.config, method, secure, version).expect("metrics on");
        let mut get = start("GET", false, "1.1");
        let active = |state: &crate::state::State, method: &str, scheme: &str| match family(state, "http_server_active_requests").map(|f| f.data) {
            Some(super::Data::Gauge(points)) => points.iter().find(|(l, _)| l == &vec![("http_request_method".to_string(), method.to_string()), ("url_scheme".to_string(), scheme.to_string())]).map(|(_, v)| *v),
            other => panic!("{other:?}"),
        };
        assert_eq!(active(&state, "GET", "http"), Some(1.0), "in flight");
        get.answered(Some(404), None, None);
        drop(get);
        assert_eq!(active(&state, "GET", "http"), Some(0.0), "the series stays, at zero");
        let mut control = start("PUT", true, "2");
        control.answered(Some(201), Some("/mockserver/expectation"), None);
        drop(control);
        let mut brew = start("BREW", false, "1.1");
        brew.answered(Some(503), None, None);
        drop(brew);
        let mut get = start("get", false, "3");
        get.answered(None, None, Some("timeout"));
        drop(get);
        drop(start("DELETE", false, "1.1"));
        let text = super::exposition(&state).unwrap();
        assert!(text.contains("# HELP http_server_request_duration_seconds Duration of HTTP server requests.\n# TYPE http_server_request_duration_seconds histogram\n"), "{text}");
        let common = r#"network_protocol_name="http",network_protocol_version="1.1",url_scheme="http""#;
        for labels in [
            format!(r#"http_request_method="GET",http_response_status_code="404",{common}"#),
            r#"http_request_method="PUT",http_response_status_code="201",http_route="/mockserver/expectation",network_protocol_name="http",network_protocol_version="2",url_scheme="https""#.to_string(),
            format!(r#"error_type="503",http_request_method="_OTHER",http_response_status_code="503",{common}"#),
            r#"error_type="timeout",http_request_method="_OTHER",network_protocol_name="http",network_protocol_version="3",url_scheme="http""#.to_string(),
            format!(r#"error_type="cancelled",http_request_method="DELETE",{common}"#),
        ] {
            assert!(text.contains(&format!("\nhttp_server_request_duration_seconds_count{{{labels}}} 1\n")), "{labels} in {text}");
        }
        let bounds: Vec<String> = text
            .lines()
            .filter(|l| l.starts_with("http_server_request_duration_seconds_bucket{http_request_method=\"GET\""))
            .map(|l| l.split("le=\"").nth(1).unwrap().split('"').next().unwrap().to_string())
            .collect();
        assert_eq!(bounds, ["0.005", "0.01", "0.025", "0.05", "0.075", "0.1", "0.25", "0.5", "0.75", "1.0", "2.5", "5.0", "7.5", "10.0", "+Inf"]);
        assert!(text.contains("\n# TYPE http_server_active_requests gauge\n"), "{text}");
        assert!(text.contains("mock_server_request_duration_seconds_bucket{le=\"5.0E-4\"} 0\n"), "upstream's family keeps its buckets: {text}");
        assert!(!text.contains("mock_server_request_duration_seconds_count 1"), "and is fed by the handler only");
    }

    /// Off unless the scrape or the OTLP export is on; the OTLP twins carry the semconv names, attributes and bounds.
    #[test]
    fn http_server_request_measured_only_while_exported() {
        use super::HttpServerRequest;
        let config = crate::Config::for_tests();
        assert!(HttpServerRequest::start(&config, "GET", false, "1.1").is_none(), "neither the scrape nor OTLP");
        config.metrics.otel_histograms_registered(true);
        let mut request = HttpServerRequest::start(&config, "POST", true, "1.1").expect("OTLP on");
        let active = super::http_server_otel_points(&config.metrics).into_iter().find(|p| p.name == "http.server.active_requests").expect("exported");
        assert_eq!((active.unit, active.up_down, active.monotonic, active.value), ("{request}", true, false, super::OtelValue::Long(1)));
        assert_eq!(active.attributes, [("http.request.method".to_string(), "POST".to_string()), ("url.scheme".to_string(), "https".to_string())]);
        request.answered(Some(200), Some("/mockserver/retrieve"), None);
        drop(request);
        let histograms = config.metrics.collect_otel_histograms(false, 5);
        let h = histograms.iter().find(|h| h.name == "http.server.request.duration").expect("exported");
        let keys: Vec<&str> = h.attributes.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, ["http.request.method", "http.response.status_code", "http.route", "network.protocol.name", "network.protocol.version", "url.scheme"]);
        assert_eq!((h.histogram.bounds, h.histogram.count, h.histogram.bucket_counts.len()), (super::HTTP_SERVER_BUCKETS, 1, 15));
        assert!(histograms.iter().all(|h| h.name != "mock_server_request_duration_seconds"), "upstream's histogram is the handler's alone");
    }

    /// Accepts any server certificate (the test's HTTP/3 client).
    #[derive(Debug)]
    struct TrustAll;

    impl rustls::client::danger::ServerCertVerifier for TrustAll {
        fn verify_server_cert(
            &self,
            _: &rustls_pki_types::CertificateDer<'_>,
            _: &[rustls_pki_types::CertificateDer<'_>],
            _: &rustls_pki_types::ServerName<'_>,
            _: &[u8],
            _: rustls_pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(&self, _: &[u8], _: &rustls_pki_types::CertificateDer<'_>, _: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(&self, _: &[u8], _: &rustls_pki_types::CertificateDer<'_>, _: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes()
        }
    }

    /// One HTTP/3 GET on a fresh QUIC connection; its status.
    async fn http3_get(port: u16, path: &str) -> u16 {
        use std::sync::Arc;
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(TrustAll))
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
        let connection = endpoint.connect(([127, 0, 0, 1], port).into(), "localhost").unwrap().await.unwrap();
        let (mut driver, mut sender) = h3::client::new(h3_quinn::Connection::new(connection)).await.unwrap();
        let drive = tokio::spawn(async move { std::future::poll_fn(|cx| driver.poll_close(cx)).await });
        let request = http::Request::builder().method("GET").uri(format!("https://localhost:{port}{path}")).body(()).unwrap();
        let mut stream = sender.send_request(request).await.unwrap();
        let _ = stream.finish().await;
        let status = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let status = stream.recv_response().await.unwrap().status().as_u16();
            while stream.recv_data().await.unwrap().is_some() {}
            status
        })
        .await
        .expect("an HTTP/3 response");
        drop(sender);
        drive.abort();
        endpoint.close(0u32.into(), b"");
        status
    }

    /// One HTTP/1.1 request on its own connection; the whole response.
    async fn http1(port: u16, head: &str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        stream.write_all(head.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(10), stream.read_to_end(&mut response)).await;
        String::from_utf8_lossy(&response).into_owned()
    }

    /// Every served request is observed once, on HTTP/1.1, HTTP/2 (h2c) and HTTP/3, the control plane with
    /// its operation as `http_route` (a legacy alias too), the data plane without one; a dropped connection is an
    /// `error_type`, and nothing is left in flight.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn http_server_requests_observed_on_every_transport() {
        let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let config = crate::Config::for_tests().with_property("metricsEnabled", "true").with_property("http3Port", &udp.to_string());
        let server = crate::Server::start(config).await.unwrap();
        let port = server.ports()[0];
        let expectation = r#"[{"httpRequest":{"path":"/drop"},"httpError":{"dropConnection":true}},{"httpRequest":{"path":"/ok"},"httpResponse":{"statusCode":202}}]"#;
        let created = http1(port, &format!("PUT /expectation HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{expectation}", expectation.len())).await;
        assert!(created.starts_with("HTTP/1.1 201"), "{created}");
        assert!(http1(port, "GET /ok HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").await.starts_with("HTTP/1.1 202"));
        assert_eq!(http1(port, "GET /drop HTTP/1.1\r\nHost: localhost\r\n\r\n").await, "", "dropped");
        let io = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let h2 = crate::h2::send(io, "GET", &format!("localhost:{port}"), "/ok", &[], bytes::Bytes::new()).await.unwrap_or_else(|_| panic!("an HTTP/2 response"));
        assert_eq!(h2.status, 202);
        drop(h2);
        let h3 = server.http3_port().expect("the HTTP/3 listener on a UDP port free a moment ago");
        assert_eq!(http3_get(h3, "/ok").await, 202);
        let common = r#"network_protocol_name="http""#;
        let count = |labels: &str| format!("\nhttp_server_request_duration_seconds_count{{{labels}}} 1\n");
        let series = [
            format!(r#"http_request_method="PUT",http_response_status_code="201",http_route="/mockserver/expectation",{common},network_protocol_version="1.1",url_scheme="http""#),
            format!(r#"http_request_method="GET",http_response_status_code="202",{common},network_protocol_version="1.1",url_scheme="http""#),
            format!(r#"error_type="connection_dropped",http_request_method="GET",{common},network_protocol_version="1.1",url_scheme="http""#),
            format!(r#"http_request_method="GET",http_response_status_code="202",{common},network_protocol_version="2",url_scheme="http""#),
            format!(r#"http_request_method="GET",http_response_status_code="202",{common},network_protocol_version="3",url_scheme="https""#),
        ];
        // An exchange is observed when its stream task ends, which can be after the client has read the whole
        // response (HTTP/3's was missing at load ~139): scrape until each is counted, and until an earlier
        // scrape is no longer in flight beside this one.
        let alone = "\nhttp_server_active_requests{http_request_method=\"GET\",url_scheme=\"http\"} 1.0\n";
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let scrape = loop {
            let scrape = http1(port, "GET /mockserver/metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").await;
            if (series.iter().all(|labels| scrape.contains(&count(labels))) && scrape.contains(alone)) || std::time::Instant::now() >= deadline {
                break scrape;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        };
        server.shutdown().await;
        for labels in series {
            assert!(scrape.contains(&count(&labels)), "{labels} in {scrape}");
        }
        // the scrape itself is in flight while it is rendered, and observed after
        assert!(scrape.contains(alone), "{scrape}");
        assert!(scrape.contains("\nhttp_server_active_requests{http_request_method=\"PUT\",url_scheme=\"http\"} 0.0\n"), "{scrape}");
    }

    /// A gauge's value at the point with exactly these labels.
    fn gauge_at(state: &crate::state::State, name: &str, labels: &[(&str, &str)]) -> Option<f64> {
        let labels: super::Attributes = labels.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        match family(state, name).map(|f| f.data) {
            Some(super::Data::Gauge(points)) => points.iter().find(|(l, _)| *l == labels).map(|(_, v)| *v),
            None => None,
            other => panic!("{other:?}"),
        }
    }

    /// The connection and forward-pool metrics: the gauges follow the guards (a connection moving to
    /// TLS, a pooled one between active and idle) and return to 0 once they are dropped; the duration histograms carry
    /// Kestrel's labels, buckets and `error_type`.
    #[test]
    fn connection_and_forward_pool_guards() {
        use super::{ForwardConnection, ServerConnection};
        let state = enabled_state(&[]);
        let active = |transport: &str, tls: &str| gauge_at(&state, "mock_server_active_connections", &[("network_transport", transport), ("tls", tls)]);
        let plain = ServerConnection::open(&state.config, "tcp", false).expect("metrics on");
        let mut secured = ServerConnection::open(&state.config, "tcp", false).unwrap();
        assert_eq!(active("tcp", "false"), Some(2.0));
        secured.tls();
        assert_eq!((active("tcp", "false"), active("tcp", "true")), (Some(1.0), Some(1.0)));
        let mut failed = ServerConnection::open(&state.config, "tcp", false).unwrap();
        failed.tls();
        failed.failed("tls_handshake_failed");
        let quic = ServerConnection::open(&state.config, "udp", true).unwrap();
        assert_eq!(active("udp", "true"), Some(1.0));
        drop((plain, secured, failed, quic));
        assert_eq!((active("tcp", "false"), active("tcp", "true"), active("udp", "true")), (Some(0.0), Some(0.0), Some(0.0)));
        super::tls_handshake(&state.config, 0.003, Ok(Some("1.3")));
        super::tls_handshake(&state.config, 0.2, Err("timeout"));
        let text = super::exposition(&state).unwrap();
        assert!(text.contains("# TYPE mock_server_active_connections gauge\n"), "{text}");
        assert!(text.contains("# TYPE mock_server_connection_duration_seconds histogram\n"), "{text}");
        for count in [
            r#"mock_server_connection_duration_seconds_count{network_transport="tcp",tls="false"} 1"#,
            r#"mock_server_connection_duration_seconds_count{network_transport="tcp",tls="true"} 1"#,
            r#"mock_server_connection_duration_seconds_count{error_type="tls_handshake_failed",network_transport="tcp",tls="true"} 1"#,
            r#"mock_server_connection_duration_seconds_count{network_transport="udp",tls="true"} 1"#,
            r#"mock_server_tls_handshake_duration_seconds_count{tls_protocol_version="1.3"} 1"#,
            r#"mock_server_tls_handshake_duration_seconds_count{error_type="timeout"} 1"#,
        ] {
            assert!(text.contains(&format!("\n{count}\n")), "{count} in {text}");
        }
        let bounds = |prefix: &str| -> Vec<String> {
            text.lines().filter(|l| l.starts_with(prefix)).map(|l| l.split("le=\"").nth(1).unwrap().split('"').next().unwrap().to_string()).collect()
        };
        assert_eq!(bounds("mock_server_connection_duration_seconds_bucket{network_transport=\"udp\""), ["0.01", "0.02", "0.05", "0.1", "0.2", "0.5", "1.0", "2.0", "5.0", "10.0", "30.0", "60.0", "120.0", "300.0", "+Inf"]);
        assert_eq!(bounds("mock_server_tls_handshake_duration_seconds_bucket{error_type").len(), super::HTTP_SERVER_BUCKETS.len() + 1);

        let pool = |state_: &str| gauge_at(&state, "http_client_open_connections", &[("http_connection_state", state_), ("server_address", "upstream.test"), ("server_port", "8443")]);
        let mut first = ForwardConnection::open(&state.config, "upstream.test", 8443).unwrap();
        let second = ForwardConnection::open(&state.config, "upstream.test", 8443).unwrap();
        assert_eq!((pool("active"), pool("idle")), (Some(2.0), None));
        first.idle(true);
        assert_eq!((pool("active"), pool("idle")), (Some(1.0), Some(1.0)));
        first.idle(false);
        first.idle(true);
        drop(second);
        assert_eq!((pool("active"), pool("idle")), (Some(0.0), Some(1.0)));
        drop(first);
        assert_eq!((pool("active"), pool("idle")), (Some(0.0), Some(0.0)));
    }

    /// Off unless the scrape or the OTLP export is on; the OTLP twins carry our names, the semconv pool name and the
    /// `{connection}` unit.
    #[test]
    fn connections_measured_only_while_exported() {
        use super::{ForwardConnection, ServerConnection};
        let config = crate::Config::for_tests();
        assert!(ServerConnection::open(&config, "tcp", false).is_none() && ForwardConnection::open(&config, "a", 1).is_none());
        super::tls_handshake(&config, 0.1, Ok(None));
        assert!(config.metrics.series.lock().tls_handshake_duration.is_empty());
        config.metrics.otel_histograms_registered(true);
        let mut connection = ServerConnection::open(&config, "tcp", false).expect("OTLP on");
        connection.tls();
        let pooled = ForwardConnection::open(&config, "upstream.test", 80).unwrap();
        let points = super::connection_otel_points(&config.metrics);
        let find = |name: &str| points.iter().filter(|p| p.name == name).collect::<Vec<_>>();
        let active = find("mock_server.active_connections");
        let up = active.iter().find(|p| p.value == super::OtelValue::Long(1)).expect("one active");
        assert_eq!((up.unit, up.up_down, up.monotonic), ("{connection}", true, false));
        assert_eq!(up.attributes, [("network.transport".to_string(), "tcp".to_string()), ("tls".to_string(), "true".to_string())]);
        let open = find("http.client.open_connections");
        assert_eq!(open.len(), 1);
        assert_eq!(open[0].attributes, [("http.connection.state".to_string(), "active".to_string()), ("server.address".to_string(), "upstream.test".to_string()), ("server.port".to_string(), "80".to_string())]);
        drop((connection, pooled));
        super::tls_handshake(&config, 0.01, Err("invalid_certificate"));
        let histograms = config.metrics.collect_otel_histograms(false, 5);
        let duration = histograms.iter().find(|h| h.name == "mock_server.connection.duration").expect("exported");
        assert_eq!(duration.attributes, [("network.transport".to_string(), "tcp".to_string()), ("tls".to_string(), "true".to_string())]);
        assert_eq!(duration.histogram.bounds, super::CONNECTION_BUCKETS);
        let handshake = histograms.iter().find(|h| h.name == "mock_server.tls_handshake.duration").expect("exported");
        assert_eq!(handshake.attributes, [("error.type".to_string(), "invalid_certificate".to_string())]);
    }

    /// Every listener path counts its connections while they are open (cleartext HTTP/1.1, TLS, h2c,
    /// binary, QUIC), times each TLS handshake (a refused one with `error_type`), and the gauge is back to the scrape's
    /// own connection once the others closed, those the chaos dropped included.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn connections_counted_on_every_listener_path() {
        use std::sync::Arc;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let config = crate::Config::for_tests().with_property("metricsEnabled", "true").with_property("http3Port", &udp.to_string());
        let server = crate::Server::start(config).await.unwrap();
        let port = server.ports()[0];
        let scrape = || http1(port, "GET /mockserver/metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        let line = |transport: &str, tls: &str, n: u32| format!("\nmock_server_active_connections{{network_transport=\"{transport}\",tls=\"{tls}\"}} {n}.0\n");
        // a keep-alive control connection, opened before any chaos (which arms only connections accepted after it)
        let mut control = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let put = async |stream: &mut tokio::net::TcpStream, path: &str, body: &str| {
            stream.write_all(format!("PUT {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
            let mut head = [0u8; 12];
            stream.read_exact(&mut head).await.unwrap();
            let mut rest = vec![0u8; 4096];
            let _ = tokio::time::timeout(std::time::Duration::from_millis(300), stream.read(&mut rest)).await;
            String::from_utf8_lossy(&head).into_owned()
        };
        assert_eq!(put(&mut control, "/mockserver/expectation", r#"[{"httpRequest":{"path":"/drop"},"httpError":{"dropConnection":true}},{"httpRequest":{"path":"/ok"},"httpResponse":{"statusCode":202}}]"#).await, "HTTP/1.1 201");
        let tls_client = |verify: bool| {
            let builder = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider())).with_safe_default_protocol_versions().unwrap();
            let config = match verify {
                true => builder.with_root_certificates(rustls::RootCertStore::empty()).with_no_client_auth(),
                false => builder.dangerous().with_custom_certificate_verifier(Arc::new(TrustAll)).with_no_client_auth(),
            };
            tokio_rustls::TlsConnector::from(Arc::new(config))
        };
        let name = rustls_pki_types::ServerName::try_from("localhost").unwrap();
        let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let mut secured = tls_client(false).connect(name.clone(), tcp).await.expect("a TLS connection");
        secured.write_all(b"GET /ok HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();
        let mut head = [0u8; 12];
        secured.read_exact(&mut head).await.unwrap();
        assert_eq!(&head, b"HTTP/1.1 202");
        let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        assert!(tls_client(true).connect(name, tcp).await.is_err(), "the client does not trust MockServer's CA");
        let mut binary = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        binary.write_all(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]).await.unwrap();
        let io = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let h2 = crate::h2::send(io, "GET", &format!("localhost:{port}"), "/ok", &[], bytes::Bytes::new()).await.unwrap_or_else(|_| panic!("an HTTP/2 response"));
        assert_eq!(h2.status, 202);
        drop(h2);
        assert_eq!(http3_get(server.http3_port().expect("the HTTP/3 listener"), "/ok").await, 202);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let open = scrape().await;
        // control and TLS stay open, besides the scrape's own (the binary one is answered and closed)
        assert!(open.contains(&line("tcp", "false", 2)) && open.contains(&line("tcp", "true", 1)), "{open}");
        // chaos: an expectation's dropped connection, and a TCP-chaos reset of the next connection from this host
        assert_eq!(http1(port, "GET /drop HTTP/1.1\r\nHost: localhost\r\n\r\n").await, "", "dropped");
        assert_eq!(put(&mut control, "/mockserver/tcpChaos", r#"{"host":"127.0.0.1","chaos":{"resetPeer":true}}"#).await, "HTTP/1.1 200");
        assert_eq!(http1(port, "GET /ok HTTP/1.1\r\nHost: localhost\r\n\r\n").await, "", "reset by TCP chaos");
        assert_eq!(put(&mut control, "/mockserver/tcpChaos", r#"{"clear":true}"#).await, "HTTP/1.1 200");
        drop((control, secured, binary));
        let mut last = String::new();
        for _ in 0..100 {
            last = scrape().await;
            if last.contains(&line("tcp", "false", 1)) && last.contains(&line("tcp", "true", 0)) && last.contains(&line("udp", "true", 0)) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        server.shutdown().await;
        assert!(last.contains(&line("tcp", "false", 1)) && last.contains(&line("tcp", "true", 0)) && last.contains(&line("udp", "true", 0)), "{last}");
        let count = |labels: &str| last.lines().find(|l| l.starts_with(&format!("{labels} "))).and_then(|l| l.rsplit(' ').next()?.parse::<u64>().ok()).unwrap_or(0);
        assert_eq!(count(r#"mock_server_connection_duration_seconds_count{network_transport="tcp",tls="true"}"#), 1, "{last}");
        assert_eq!(count(r#"mock_server_connection_duration_seconds_count{error_type="alert_received",network_transport="tcp",tls="true"}"#), 1, "{last}");
        assert_eq!(count(r#"mock_server_connection_duration_seconds_count{network_transport="udp",tls="true"}"#), 1, "{last}");
        assert!(count(r#"mock_server_connection_duration_seconds_count{network_transport="tcp",tls="false"}"#) >= 6, "{last}");
        assert_eq!(count(r#"mock_server_tls_handshake_duration_seconds_count{tls_protocol_version="1.3"}"#), 2, "TCP and QUIC: {last}");
        assert_eq!(count(r#"mock_server_tls_handshake_duration_seconds_count{error_type="alert_received"}"#), 1, "{last}");
    }

    /// A socket that TCP chaos holds open past its connection's task (`timeout`: until the client gives
    /// up; `slowClose`: the FIN 2 s late) stays in `mock_server_active_connections` while held, and its duration
    /// observation covers the held time. Chaos and scrapes go over a control connection accepted before any chaos,
    /// which leaves it unarmed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tcp_chaos_held_connections_stay_counted() {
        use std::time::{Duration, Instant};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let server = crate::Server::start(crate::Config::for_tests().with_property("metricsEnabled", "true")).await.unwrap();
        let port = server.ports()[0];
        let mut control = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        // one keep-alive exchange on the control connection; the response read up to its content-length
        let mut exchange = async |method: &str, path: &str, body: &str| {
            control.write_all(format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
            let mut response = Vec::new();
            loop {
                let mut chunk = [0u8; 8192];
                let n = control.read(&mut chunk).await.unwrap();
                assert!(n > 0, "the control connection closed");
                response.extend_from_slice(&chunk[..n]);
                let text = String::from_utf8_lossy(&response).into_owned();
                if let Some(end) = text.find("\r\n\r\n") {
                    let length = text[..end].lines().find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length: ").map(|v| v.trim().parse::<usize>().unwrap())).unwrap_or(0);
                    if response.len() >= end + 4 + length {
                        return text;
                    }
                }
            }
        };
        let active = |scrape: &str| scrape.lines().find_map(|l| l.strip_prefix(r#"mock_server_active_connections{network_transport="tcp",tls="false"} "#)).map(|v| v.parse::<f64>().unwrap());
        let duration_sum = |scrape: &str| scrape.lines().find_map(|l| l.strip_prefix(r#"mock_server_connection_duration_seconds_sum{network_transport="tcp",tls="false"} "#)).map_or(0.0, |v| v.parse::<f64>().unwrap());
        // a request with `Connection: close` on a fresh (armed) connection, its response read up to its length
        let served = async || {
            let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            stream.write_all(b"GET /held HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").await.unwrap();
            let mut head = [0u8; 12];
            stream.read_exact(&mut head).await.unwrap();
            assert_eq!(&head, b"HTTP/1.1 202");
            let mut rest = vec![0u8; 4096];
            let _ = tokio::time::timeout(Duration::from_millis(200), stream.read(&mut rest)).await;
            stream
        };
        assert!(exchange("PUT", "/mockserver/expectation", r#"{"httpRequest":{"path":"/held"},"httpResponse":{"statusCode":202}}"#).await.starts_with("HTTP/1.1 201"));
        assert!(exchange("PUT", "/mockserver/tcpChaos", r#"{"host":"127.0.0.1","chaos":{"timeout":true}}"#).await.starts_with("HTTP/1.1 200"));
        let held = served().await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        let scrape = exchange("GET", "/mockserver/metrics", "").await;
        assert_eq!(active(&scrape), Some(2.0), "the control connection and the one `timeout` holds: {scrape}");
        let before = duration_sum(&scrape);
        tokio::time::sleep(Duration::from_millis(500)).await;
        drop(held);
        let mut scrape = String::new();
        for _ in 0..100 {
            scrape = exchange("GET", "/mockserver/metrics", "").await;
            if active(&scrape) == Some(1.0) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(active(&scrape), Some(1.0), "the client gave up on the held socket: {scrape}");
        assert!(duration_sum(&scrape) - before >= 0.8, "the duration covers the held time: {scrape}");
        assert!(exchange("PUT", "/mockserver/tcpChaos", r#"{"clear":true}"#).await.starts_with("HTTP/1.1 200"));
        assert!(exchange("PUT", "/mockserver/tcpChaos", r#"{"host":"127.0.0.1","chaos":{"slowClose":true}}"#).await.starts_with("HTTP/1.1 200"));
        let before = duration_sum(&exchange("GET", "/mockserver/metrics", "").await);
        let started = Instant::now();
        let mut held = served().await;
        let scrape = exchange("GET", "/mockserver/metrics", "").await;
        assert_eq!(active(&scrape), Some(2.0), "the control connection and the one `slowClose` holds: {scrape}");
        let mut rest = Vec::new();
        tokio::time::timeout(Duration::from_secs(10), held.read_to_end(&mut rest)).await.expect("the late FIN").unwrap();
        assert!(started.elapsed() >= Duration::from_millis(1900), "the FIN came after {:?}", started.elapsed());
        let mut scrape = String::new();
        for _ in 0..100 {
            scrape = exchange("GET", "/mockserver/metrics", "").await;
            if active(&scrape) == Some(1.0) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(exchange("PUT", "/mockserver/tcpChaos", r#"{"clear":true}"#).await.starts_with("HTTP/1.1 200"));
        server.shutdown().await;
        assert_eq!(active(&scrape), Some(1.0), "the FIN went out: {scrape}");
        assert!(duration_sum(&scrape) - before >= 1.9, "the duration covers the slow close: {scrape}");
    }

    /// A forward's pooled connection is `active` during the exchange and `idle` in the pool, one
    /// connection for two forwards (reused), and leaves the gauge when the upstream closes it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn forward_pool_connections_by_state() {
        use std::sync::atomic::Ordering;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_port = upstream.local_addr().unwrap().port();
        let (close, closed) = tokio::sync::oneshot::channel::<()>();
        let accepted = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = accepted.clone();
        tokio::spawn(async move {
            let (mut socket, _) = upstream.accept().await.unwrap();
            counter.fetch_add(1, Ordering::SeqCst);
            let mut closed = closed;
            let mut buf = vec![0u8; 4096];
            loop {
                tokio::select! {
                    read = socket.read(&mut buf) => match read {
                        Ok(0) | Err(_) => return,
                        Ok(_) => socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await.unwrap(),
                    },
                    _ = &mut closed => return,
                }
            }
        });
        let server = crate::Server::start(crate::Config::for_tests().with_property("metricsEnabled", "true")).await.unwrap();
        let port = server.ports()[0];
        let expectation = format!(r#"{{"httpRequest":{{"path":"/fwd"}},"httpForward":{{"host":"127.0.0.1","port":{upstream_port}}}}}"#);
        let created = http1(port, &format!("PUT /mockserver/expectation HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{expectation}", expectation.len())).await;
        assert!(created.starts_with("HTTP/1.1 201"), "{created}");
        for _ in 0..2 {
            let forwarded = http1(port, "GET /fwd HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").await;
            assert!(forwarded.starts_with("HTTP/1.1 200"), "{forwarded}");
        }
        assert_eq!(accepted.load(Ordering::SeqCst), 1, "the second forward reused the pooled connection");
        let scrape = || http1(port, "GET /mockserver/metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        let line = |state: &str, n: u32| format!("\nhttp_client_open_connections{{http_connection_state=\"{state}\",server_address=\"127.0.0.1\",server_port=\"{upstream_port}\"}} {n}.0\n");
        let pooled = scrape().await;
        assert!(pooled.contains(&line("idle", 1)) && pooled.contains(&line("active", 0)), "{pooled}");
        close.send(()).unwrap();
        let mut last = String::new();
        for _ in 0..100 {
            last = scrape().await;
            if last.contains(&line("idle", 0)) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        server.shutdown().await;
        assert!(last.contains(&line("idle", 0)) && last.contains(&line("active", 0)), "the upstream closed it: {last}");
    }

    /// A two-worker runtime that has run some work, so its workers have been busy and have parked.
    fn busy_runtime() -> tokio::runtime::Runtime {
        let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
        runtime.block_on(async {
            let spin = || tokio::spawn(async { (0..200_000u64).fold(0u64, |a, b| std::hint::black_box(a ^ b)) });
            let (a, b) = (spin(), spin());
            let _ = (a.await, b.await);
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        });
        runtime
    }

    fn tokio_family<'a>(families: &'a [super::Snapshot], name: &str) -> &'a super::Snapshot {
        families.iter().find(|s| s.name == name).unwrap_or_else(|| panic!("{name} in {families:?}"))
    }

    /// The tokio set on the scrape, its names and types, one counter point per worker.
    #[test]
    fn tokio_families_names_and_types() {
        let runtime = busy_runtime();
        let families = super::tokio_snapshots(runtime.handle());
        let names: Vec<String> = families.iter().map(super::Snapshot::exposed_name).collect();
        assert_eq!(names, ["tokio_workers_count", "tokio_live_tasks_count", "tokio_global_queue_depth", "tokio_worker_park_total", "tokio_worker_busy_seconds_total"]);
        assert_eq!(tokio_family(&families, "tokio_workers_count").data, super::Data::Gauge(vec![(Vec::new(), 2.0)]));
        assert!(matches!(&tokio_family(&families, "tokio_live_tasks_count").data, super::Data::Gauge(p) if p.len() == 1));
        assert!(matches!(&tokio_family(&families, "tokio_global_queue_depth").data, super::Data::Gauge(p) if p.len() == 1));
        let workers = |name: &str| match &tokio_family(&families, name).data {
            super::Data::Counter(points) => points.iter().map(|(a, v)| (a.clone(), *v)).collect::<Vec<_>>(),
            other => panic!("{name} is a counter: {other:?}"),
        };
        for name in ["tokio_worker_park", "tokio_worker_busy_seconds"] {
            let labels: Vec<_> = workers(name).into_iter().map(|(a, _)| a).collect();
            assert_eq!(labels, [vec![("worker".to_string(), "0".to_string())], vec![("worker".to_string(), "1".to_string())]], "{name}");
        }
        assert!(workers("tokio_worker_park").iter().any(|(_, v)| *v > 0.0), "a worker that ran and idled has parked");
    }

    /// The busy counter never goes down from one scrape to the next, and grows while the runtime works.
    #[test]
    fn tokio_busy_counter_is_monotonic() {
        let runtime = busy_runtime();
        let busy = || match super::tokio_snapshots(runtime.handle()).into_iter().find(|s| s.name == "tokio_worker_busy_seconds").map(|s| s.data) {
            Some(super::Data::Counter(points)) => points.into_iter().map(|(_, v)| v).collect::<Vec<f64>>(),
            other => panic!("{other:?}"),
        };
        let mut previous = busy();
        let mut grew = false;
        for _ in 0..20 {
            runtime.block_on(async {
                let _ = tokio::spawn(async { (0..500_000u64).fold(0u64, |a, b| std::hint::black_box(a ^ b)) }).await;
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            });
            let now = busy();
            assert!(now.iter().zip(&previous).all(|(n, p)| n >= p), "{previous:?} then {now:?}");
            grew |= now.iter().sum::<f64>() > previous.iter().sum::<f64>();
            previous = now;
        }
        assert!(grew, "busy time grows while the runtime works: {previous:?}");
    }

    /// The same set on OTLP: semconv-style names, units, the `tokio.worker` attribute, the counters monotonic.
    #[test]
    fn tokio_otel_points_names_units_and_attributes() {
        let runtime = busy_runtime();
        let points = super::tokio_otel_points(runtime.handle());
        // (name, unit, monotonic, up-down, attributes) of each point
        type Summary<'a> = (&'a str, &'a str, bool, bool, Vec<(String, String)>);
        let summary: Vec<Summary> =
            points.iter().map(|p| (p.name.as_str(), p.unit, p.monotonic, p.up_down, p.attributes.clone())).collect();
        let worker = |i: &str| vec![("tokio.worker".to_string(), i.to_string())];
        assert_eq!(
            summary,
            [
                ("tokio.workers.count", "{thread}", false, true, vec![]),
                ("tokio.live_tasks.count", "{task}", false, true, vec![]),
                ("tokio.global_queue.depth", "{task}", false, true, vec![]),
                ("tokio.worker.park.count", "{park}", true, false, worker("0")),
                ("tokio.worker.park.count", "{park}", true, false, worker("1")),
                ("tokio.worker.busy.time", "s", true, false, worker("0")),
                ("tokio.worker.busy.time", "s", true, false, worker("1")),
            ]
        );
        assert_eq!(points[0].value, super::OtelValue::Long(2));
        assert!(points.iter().filter(|p| p.name == "tokio.worker.busy.time").all(|p| matches!(p.value, super::OtelValue::Double(s) if s >= 0.0)));
        assert!(points.iter().filter(|p| p.name == "tokio.worker.park.count").all(|p| matches!(p.value, super::OtelValue::Long(n) if n >= 0)));
    }

    /// The runtime measured is the one serving the listeners: an embedder's server started on a three-worker runtime
    /// reports three workers on its scrape, not the binary's runtime nor the cluster fan-in's two.
    #[test]
    fn tokio_families_measure_the_runtime_the_server_started_on() {
        let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(3).enable_all().build().unwrap();
        let config = crate::Config::for_tests().with_property("metricsEnabled", "true");
        let server = runtime.block_on(crate::Server::start(config)).unwrap();
        let port = server.ports()[0];
        let body = {
            use std::io::{Read, Write};
            let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
            stream.write_all(b"GET /mockserver/metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).unwrap();
            response
        };
        runtime.block_on(server.shutdown());
        assert!(body.contains("\n# TYPE tokio_workers_count gauge\ntokio_workers_count 3.0\n"), "{body}");
        assert!(body.contains("\ntokio_worker_busy_seconds_total{worker=\"2\"} "), "{body}");
        assert!(!body.contains("tokio_worker_busy_seconds_total{worker=\"3\"}"), "{body}");
    }
}
