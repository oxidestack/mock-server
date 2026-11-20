//! Mock drift detection (`org.mockserver.mock.drift`) and traffic diffs (`org.mockserver.mock.diff`): the drift store
//! a forward fills by comparing the upstream's response with every response stub matching the same request
//! (`HttpActionHandler.analyseDrift`, `DriftAnalyzer`, `PercentileTracker`, `DriftAlertNotifier`), read by
//! `GET /mockserver/drift`; `PUT /mockserver/diff` (`TrafficDiffEngine`) and `PUT /mockserver/baseline/compare`
//! (`BaselineDiffer`). Upstream's process-wide singletons are one per server here, cleared by a reset as
//! `HttpState.reset` clears them (`DriftStore.clear`).

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

use parking_lot::Mutex;
use serde_json::{json, Map, Value};

use crate::export::{Request as Definition, Response as ResponseView};
use crate::reply::Reply;
use crate::request::HttpRequest;
use crate::state::State;

/// `DriftStore.getInstance()`'s capacity.
const STORE_CAP: usize = 1000;
/// `PercentileTracker.getInstance()`'s window.
const WINDOW: usize = 100;
/// `DriftAlertNotifier.COOLDOWN_MAP_CAP`.
const COOLDOWN_CAP: usize = 1000;
/// `HttpActionHandler.MIN_PENDING_DRIFT_ANALYSES` and `PENDING_DRIFT_ANALYSES_PER_THREAD`.
const MIN_PENDING_ANALYSES: usize = 16;
const PENDING_ANALYSES_PER_THREAD: usize = 4;
/// `DriftAnalyzer.SKIP_HEADERS`: headers that change per request.
const SKIP_HEADERS: &[&str] = &["date", "x-request-id", "content-length", "transfer-encoding", "connection", "keep-alive", "server"];

/// `DriftRecord`: one aspect of a forwarded response that differs from a matching stub's response.
#[derive(Clone)]
pub struct Record {
    expectation_id: String,
    drift_type: &'static str,
    field: String,
    expected: Option<String>,
    actual: Option<String>,
    confidence: f64,
    epoch_millis: i64,
    /// `semanticSeverity`, as the `SemanticSeverity` ordinal, and `semanticExplanation` (`SemanticDriftExtension`).
    semantic_severity: Option<usize>,
    semantic_explanation: Option<String>,
}

impl Record {
    fn new(expectation_id: &str, drift_type: &'static str, field: impl Into<String>, confidence: f64, now: i64) -> Record {
        Record {
            expectation_id: expectation_id.to_string(),
            drift_type,
            field: field.into(),
            expected: None,
            actual: None,
            confidence,
            epoch_millis: now,
            semantic_severity: None,
            semantic_explanation: None,
        }
    }

    fn expected(mut self, value: impl Into<String>) -> Record {
        self.expected = Some(value.into());
        self
    }

    fn actual(mut self, value: impl Into<String>) -> Record {
        self.actual = Some(value.into());
        self
    }

    /// The record as `ObjectMapperFactory`'s mapper writes it: properties sorted, nulls left out.
    fn json(&self) -> Value {
        let mut o = Map::new();
        if let Some(actual) = &self.actual {
            o.insert("actualValue".into(), actual.clone().into());
        }
        o.insert("confidence".into(), self.confidence.into());
        o.insert("driftType".into(), self.drift_type.into());
        o.insert("epochTimeMs".into(), self.epoch_millis.into());
        o.insert("expectationId".into(), self.expectation_id.clone().into());
        if let Some(expected) = &self.expected {
            o.insert("expectedValue".into(), expected.clone().into());
        }
        o.insert("field".into(), self.field.clone().into());
        if let Some(explanation) = &self.semantic_explanation {
            o.insert("semanticExplanation".into(), explanation.clone().into());
        }
        if let Some(severity) = self.semantic_severity {
            o.insert("semanticSeverity".into(), SEVERITIES[severity].into());
        }
        Value::Object(o)
    }

    /// `DriftAlertNotifier.effectiveSeverity`: the semantic severity, else the structural fallback, as the
    /// `SemanticSeverity` ordinal (0 most severe).
    fn severity(&self) -> usize {
        if let Some(severity) = self.semantic_severity {
            return severity;
        }
        match self.drift_type {
            "STATUS" | "SCHEMA_FIELD_REMOVED" | "SCHEMA_TYPE_CHANGED" => 0,
            "SCHEMA_FIELD_ADDED" | "HEADER_ADDED" => 2,
            _ => 1,
        }
    }
}

const SEVERITIES: [&str; 3] = ["BREAKING", "WARNING", "INFORMATIONAL"];

/// One server's drift state: `DriftStore`, `PercentileTracker` and `DriftAlertNotifier`'s cooldown map.
#[derive(Default)]
pub struct Drift {
    records: Mutex<VecDeque<Record>>,
    /// Per expectation: the circular buffer and the total count recorded.
    windows: Mutex<HashMap<String, (Vec<i64>, usize)>>,
    /// Signature (`expectationId|driftType|field`) → when it last fired.
    fired: Mutex<HashMap<String, i64>>,
    /// `HttpActionHandler.pendingDriftAnalyses`: analyses admitted and not finished yet (queued or running).
    pending: AtomicUsize,
    /// `mock_server_dropped_drift_analyses_total`: analyses shed for a full backlog while `metricsEnabled`.
    dropped: AtomicU64,
    /// The action scheduler's threads (`actionHandlerThreadCount`), as far as they are seen here: a forward's
    /// continuation and the semantic analyses it submits each take one, first come first served, so analyses waiting
    /// on the LLM backend hold back later forwards' responses and queue their analyses behind them.
    threads: OnceLock<tokio::sync::Semaphore>,
    /// Continuations and analyses waiting for one of `threads`: tasks in the action scheduler's queue.
    waiting: AtomicUsize,
}

/// Counts a task in `Drift::waiting` until it has a thread, or is cancelled while waiting.
struct Waiting<'a>(&'a AtomicUsize);

impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Releases a pending analysis's slot when it finishes, however it ends.
struct Admitted(Arc<State>);

impl Drop for Admitted {
    fn drop(&mut self) {
        self.0.drift.pending.fetch_sub(1, Ordering::AcqRel);
    }
}

impl Drift {
    /// `mock_server_dropped_drift_analyses_total`.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Waits for an action scheduler thread (see `threads`).
    pub async fn scheduler_thread(&self, config: &crate::config::Config) -> tokio::sync::SemaphorePermit<'_> {
        let threads = self.threads.get_or_init(|| tokio::sync::Semaphore::new(crate::overload::action_handler_threads(config)));
        self.waiting.fetch_add(1, Ordering::AcqRel);
        let _waiting = Waiting(&self.waiting);
        threads.acquire().await.expect("never closed")
    }

    /// The tasks waiting for an action scheduler thread: their part of `Scheduler.getQueuedTaskCount`.
    pub fn queued(&self) -> usize {
        self.waiting.load(Ordering::Acquire)
    }

    /// `DriftStore.clear`: the records, the percentile windows and the alert cooldowns.
    pub fn clear(&self) {
        self.records.lock().clear();
        self.windows.lock().clear();
        self.fired.lock().clear();
    }

    fn add(&self, record: Record) {
        let mut records = self.records.lock();
        if records.len() >= STORE_CAP {
            records.pop_front();
        }
        records.push_back(record);
    }

    /// `PercentileTracker.record`.
    fn record_time(&self, id: &str, millis: i64) {
        let mut windows = self.windows.lock();
        let (buf, count) = windows.entry(id.to_string()).or_insert_with(|| (vec![0; WINDOW], 0));
        *count += 1;
        buf[(*count - 1) % WINDOW] = millis;
    }

    /// `PercentileTracker.p95`.
    fn p95(&self, id: &str) -> i64 {
        let windows = self.windows.lock();
        let Some((buf, count)) = windows.get(id).filter(|(_, c)| *c > 0) else { return 0 };
        let filled = (*count).min(WINDOW);
        let mut copy = buf[..filled].to_vec();
        copy.sort_unstable();
        let index = ((0.95 * filled as f64).ceil() as i64 - 1).clamp(0, filled as i64 - 1);
        copy[index as usize]
    }
}

/// A response as `DriftAnalyzer` and `BaselineDiffer` read it: the status (`None` when the stub names none), the
/// headers in order with their values, and `getBodyAsString()`.
#[derive(Clone)]
pub struct Observed {
    pub status: Option<i64>,
    pub headers: Vec<(String, Vec<String>)>,
    pub body: Option<String>,
}

impl Observed {
    /// A response in JSON (an expectation's `httpResponse`, or a logged one).
    pub fn json(v: &Value) -> Observed {
        let r = ResponseView::json(v);
        Observed { status: r.status, headers: r.headers, body: r.body.map(|b| b.text) }
    }

    /// An upstream's response: the head as received (see [`Observed::head`]) and the body as logged.
    pub fn upstream(head: &Reply, logged: &Value) -> Observed {
        Observed { body: Observed::json(logged).body, ..Observed::head(head.status, &head.headers) }
    }

    /// A response head as received: headers grouped by name, case-insensitively, in first-seen order (Netty's
    /// `HttpHeaders.names()`), and no body. `x-mockserver-response-time-ms` is added to the forwarded response after
    /// the drift analysis has read it.
    pub fn head(status: u32, headers: &[(String, String)]) -> Observed {
        let mut grouped: Vec<(String, Vec<String>)> = Vec::new();
        for (name, value) in headers.iter().filter(|(n, _)| !n.eq_ignore_ascii_case("x-mockserver-response-time-ms")) {
            match grouped.iter_mut().find(|(n, _)| n.eq_ignore_ascii_case(name)) {
                Some((_, values)) => values.push(value.clone()),
                None => grouped.push((name.clone(), vec![value.clone()])),
            }
        }
        Observed { status: Some(i64::from(status)), headers: grouped, body: None }
    }
}

/// `DriftAnalyzer.toHeaderMap` / `TrafficDiffEngine.toMultiValueMap`: lower-cased names, values joined by commas, a
/// repeated name keeping its first position and its last values.
fn joined(headers: &[(String, Vec<String>)]) -> Vec<(String, String)> {
    let mut map: Vec<(String, String)> = Vec::new();
    for (name, values) in headers {
        let key = name.to_lowercase();
        let value = values.join(",");
        match map.iter_mut().find(|(k, _)| *k == key) {
            Some((_, v)) => *v = value,
            None => map.push((key, value)),
        }
    }
    map
}

fn value_of<'a>(map: &'a [(String, String)], key: &str) -> Option<&'a str> {
    map.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
}

/// `HttpActionHandler.analyseDrift` for one forward: every response stub among the expectations matching the request
/// is compared with the upstream's response (`DriftAnalyzer.analyse`), and the forward's response time recorded
/// against it (`PercentileTracker.record`, `checkPerformanceDrift`). The matching expectations are evaluated when the
/// analysis runs, and an analysis beyond the backlog bound is shed before that (`maxPendingDriftAnalyses`). With
/// semantic drift analysis installed the records wait for the backend's classification on an action scheduler
/// thread, queued behind the work already waiting for one, as upstream's scheduler task is; without it the pass is
/// quick and runs in place.
pub fn analyse_forward(
    state: &Arc<State>,
    matching: impl FnOnce() -> Vec<Arc<crate::store::Expectation>> + Send + 'static,
    real: &Observed,
    response_millis: i64,
) {
    let Some(admitted) = admit(state) else { return };
    let Some((backend, service)) = state.llm.drift(state) else {
        for (id, stub) in &stubs(&matching()) {
            for record in collect(id, stub, real) {
                stored(state, record);
            }
            state.drift.record_time(id, response_millis);
            performance(state, id);
        }
        drop(admitted);
        return;
    };
    let (state, real) = (state.clone(), real.clone());
    tokio::spawn(async move {
        let _admitted = admitted;
        let _thread = state.drift.scheduler_thread(&state.config).await;
        for (id, stub) in &stubs(&matching()) {
            let mut records = collect(id, stub, &real);
            if !records.is_empty() {
                let prompt = semantic_prompt(&records, stub, &real, state.config.property("dataPlaneApiKeyAuthenticationHeader").as_deref());
                if let Some(text) = service.complete(&state, &backend, &prompt).await {
                    apply_semantic(&mut records, &text);
                }
            }
            for record in records {
                stored(&state, record);
            }
            state.drift.record_time(id, response_millis);
            performance(&state, id);
        }
    });
}

/// The response stubs among the matching expectations: each one's id and `httpResponse`.
fn stubs(matching: &[Arc<crate::store::Expectation>]) -> Vec<(String, Observed)> {
    matching
        .iter()
        .filter(|e| matches!(e.action, crate::action::Action::Respond(_)))
        .filter_map(|e| e.input.get("httpResponse").map(|stub| (e.id.clone(), Observed::json(stub))))
        .collect()
}

/// `analyseDrift`'s admission: a slot in the backlog of at most `maxPendingDriftAnalyses()`
/// (max(16, 4 per action-handler thread)), or none, counted as dropped while metrics are enabled.
fn admit(state: &Arc<State>) -> Option<Admitted> {
    let (drift, config) = (&state.drift, &state.config);
    let bound = MIN_PENDING_ANALYSES.max(PENDING_ANALYSES_PER_THREAD.saturating_mul(crate::overload::action_handler_threads(config)));
    if drift.pending.fetch_add(1, Ordering::AcqRel) + 1 > bound {
        drift.pending.fetch_sub(1, Ordering::AcqRel);
        if crate::metrics::enabled(config) {
            drift.dropped.fetch_add(1, Ordering::Relaxed);
        }
        return None;
    }
    Some(Admitted(state.clone()))
}

/// `DriftAnalyzer.analyse`: status, headers, then the JSON shape.
fn collect(id: &str, stub: &Observed, real: &Observed) -> Vec<Record> {
    let now = crate::chaos::now_millis();
    let mut collected = Vec::new();
    if let (Some(expected), Some(actual)) = (stub.status, real.status) && expected != actual {
        collected.push(Record::new(id, "STATUS", "statusCode", 1.0, now).expected(expected.to_string()).actual(actual.to_string()));
    }
    let (stub_headers, real_headers) = (joined(&stub.headers), joined(&real.headers));
    for (key, value) in real_headers.iter().filter(|(k, _)| !SKIP_HEADERS.contains(&k.as_str())) {
        match value_of(&stub_headers, key) {
            None => collected.push(Record::new(id, "HEADER_ADDED", format!("header.{key}"), 0.9, now).actual(value.clone())),
            Some(expected) if expected != value => {
                collected.push(Record::new(id, "HEADER_CHANGED", format!("header.{key}"), 0.85, now).expected(expected).actual(value.clone()))
            }
            Some(_) => {}
        }
    }
    for (key, value) in stub_headers.iter().filter(|(k, _)| !SKIP_HEADERS.contains(&k.as_str())) {
        if value_of(&real_headers, key).is_none() {
            collected.push(Record::new(id, "HEADER_REMOVED", format!("header.{key}"), 0.9, now).expected(value.clone()));
        }
    }
    let is_json = |b: &Option<String>| b.as_deref().is_some_and(|b| !b.is_empty() && (b.trim().starts_with('{') || b.trim().starts_with('[')));
    if is_json(&stub.body) && is_json(&real.body) {
        let parse = |b: &Option<String>| crate::json::parse_lenient(b.as_deref().unwrap_or_default().as_bytes()).ok();
        if let (Some(expected), Some(actual)) = (parse(&stub.body), parse(&real.body)) {
            let (added, removed, changed) = crate::llm::drift::shape_diff(&expected, &actual);
            let (baseline, live) = (crate::llm::drift::shape_types(&expected), crate::llm::drift::shape_types(&actual));
            // `getLiveType` / `getBaselineType`: each record carries the JSON types on its sides.
            let typed = |record: Record, expected: Option<&&str>, actual: Option<&&str>| Record { expected: expected.map(|t| t.to_string()), actual: actual.map(|t| t.to_string()), ..record };
            collected.extend(added.into_iter().map(|p| typed(Record::new(id, "SCHEMA_FIELD_ADDED", p.clone(), 0.9, now), None, live.get(&p))));
            collected.extend(removed.into_iter().map(|p| typed(Record::new(id, "SCHEMA_FIELD_REMOVED", p.clone(), 0.95, now), baseline.get(&p), None)));
            collected.extend(changed.into_iter().map(|p| typed(Record::new(id, "SCHEMA_TYPE_CHANGED", p.clone(), 0.95, now), baseline.get(&p), live.get(&p))));
        }
    }
    collected
}

/// `SemanticDriftExtension.MAX_BODY_LENGTH`.
const SEMANTIC_MAX_BODY: usize = 200;

/// `SemanticDriftExtension.buildPrompt`: bodies and drift values redacted (`LlmPromptRedactor`, with the configured
/// data-plane API-key header among the sensitive ones) before they leave for the backend.
fn semantic_prompt(records: &[Record], stub: &Observed, real: &Observed, data_plane_header: Option<&str>) -> String {
    let truncate = |body: &Option<String>| match body.as_deref().map(crate::llm::redact::redact_text) {
        None => "null".to_string(),
        Some(text) => {
            let units: Vec<u16> = text.encode_utf16().collect();
            if units.len() > SEMANTIC_MAX_BODY { format!("{}...", String::from_utf16_lossy(&units[..SEMANTIC_MAX_BODY])) } else { text }
        }
    };
    let status = |s: Option<i64>| s.map_or_else(|| "null".to_string(), |s| s.to_string());
    let or_null = |field: &str, v: &Option<String>| v.as_deref().map_or_else(|| "null".into(), |v| crate::llm::redact::mask_drift_value(field, v, data_plane_header));
    let mut p = String::from("You are an API compatibility expert. Classify each API drift as BREAKING, WARNING, or INFORMATIONAL.\n\n");
    p.push_str(&format!("STUB RESPONSE: status={}, body={}\n", status(stub.status), truncate(&stub.body)));
    p.push_str(&format!("REAL RESPONSE: status={}, body={}\n\n", status(real.status), truncate(&real.body)));
    p.push_str("DRIFT RECORDS:\n");
    for (i, r) in records.iter().enumerate() {
        p.push_str(&format!("{}. {} on field '{}': expected={}, actual={}\n", i + 1, r.drift_type, r.field, or_null(&r.field, &r.expected), or_null(&r.field, &r.actual)));
    }
    p.push_str("\nFor each numbered drift, reply with: <number>|<BREAKING|WARNING|INFORMATIONAL>|<one sentence explanation>\n");
    p.push_str("Return exactly one line per drift.");
    p
}

/// `SemanticDriftExtension.applySemanticResults`: `<number>|<severity>|<explanation>` lines; a line with an index out
/// of range, an unparseable index or an unknown severity is skipped.
fn apply_semantic(records: &mut [Record], answer: &str) {
    let java_trim = crate::llm::service::java_trim;
    if answer.trim().is_empty() {
        return;
    }
    for line in answer.trim().split('\n') {
        let parts: Vec<&str> = line.splitn(3, '|').collect();
        if parts.len() < 2 {
            continue;
        }
        let Ok(index) = java_trim(parts[0]).parse::<i32>() else { continue };
        let Some(record) = usize::try_from(index - 1).ok().and_then(|i| records.get_mut(i)) else { continue };
        let Some(severity) = SEVERITIES.iter().position(|s| *s == java_trim(parts[1]).to_uppercase()) else { continue };
        record.semantic_severity = Some(severity);
        if let Some(explanation) = parts.get(2).filter(|e| !e.trim().is_empty()) {
            record.semantic_explanation = Some(java_trim(explanation).to_string());
        }
    }
}

/// `DriftAnalyzer.checkPerformanceDrift`, against `driftResponseTimeThresholdMs` as the server started with it.
fn performance(state: &Arc<State>, id: &str) {
    let threshold = state.config.startup_property("driftResponseTimeThresholdMs").and_then(|v| v.trim().parse::<i64>().ok()).unwrap_or(0);
    if threshold <= 0 {
        return;
    }
    let p95 = state.drift.p95(id);
    if p95 > threshold {
        let now = crate::chaos::now_millis();
        stored(state, Record::new(id, "PERFORMANCE", "p95_response_time_ms", 0.8, now).expected(format!("<={threshold}")).actual(p95.to_string()));
    }
}

/// `DriftStore.add`, then `DriftAlertNotifier.onDriftStored`.
fn stored(state: &Arc<State>, record: Record) {
    state.drift.add(record.clone());
    notify(state, &record);
}

/// `DriftAlertNotifier.onDriftStored` as `LifeCycle.installDriftAlertWebhook` configures it: with
/// `driftAlertWebhookEnabled`, a URL and a valid `driftAlertSeverityThreshold`, a record at least that severe POSTs
/// the alert envelope to the URL, at most once per signature per `driftAlertCooldownMillis`, fire and forget.
fn notify(state: &Arc<State>, record: &Record) {
    let config = &state.config;
    if !config.bool_startup_property("driftAlertWebhookEnabled", false) {
        return;
    }
    let Some(url) = config.startup_property("driftAlertWebhookUrl").filter(|u| !u.trim().is_empty()) else { return };
    let threshold = config.startup_property("driftAlertSeverityThreshold").unwrap_or_else(|| "BREAKING".into());
    let Some(threshold) = SEVERITIES.iter().position(|s| *s == threshold.trim().to_uppercase()) else { return };
    let severity = record.severity();
    if severity > threshold {
        return;
    }
    let cooldown = config.startup_property("driftAlertCooldownMillis").and_then(|v| v.trim().parse::<i64>().ok()).unwrap_or(60_000).max(0);
    let now = crate::chaos::now_millis();
    let signature = format!("{}|{}|{}", record.expectation_id, record.drift_type, record.field);
    {
        let mut fired = state.drift.fired.lock();
        if fired.get(&signature).is_some_and(|last| cooldown > 0 && now - last < cooldown) {
            return;
        }
        if fired.len() >= COOLDOWN_CAP && !fired.contains_key(&signature) {
            fired.retain(|_, last| cooldown > 0 && now - *last < cooldown);
            while fired.len() >= COOLDOWN_CAP {
                let Some(key) = fired.keys().next().cloned() else { break };
                fired.remove(&key);
            }
        }
        fired.insert(signature, now);
    }
    let Some(outbound) = webhook_request(&url, record, severity, now) else { return };
    let state = state.clone();
    tokio::spawn(async move {
        let _ = crate::forward::send_json(&state, &outbound).await;
    });
}

/// `DriftAlertNotifier.buildOutbound`: a POST of the alert envelope to the URL's host and port (80 or 443 by
/// default), its raw path and query, with a `Host` header (the port only when not the scheme's default).
fn webhook_request(url: &str, record: &Record, severity: usize, now: i64) -> Option<Value> {
    let uri = crate::java_uri::parse(url).ok()?;
    let (scheme, host) = (uri.scheme.clone()?, uri.host.clone()?);
    let https = scheme.eq_ignore_ascii_case("https");
    let default_port = if https { 443 } else { 80 };
    let port = if uri.port == -1 { default_port } else { uri.port };
    let path = uri.raw_path.clone().filter(|p| !p.is_empty()).unwrap_or_else(|| "/".into());
    let path = match uri.raw_query.as_deref().filter(|q| !q.is_empty()) {
        Some(query) => format!("{path}?{query}"),
        None => path,
    };
    let envelope = json!({"event": "mockserver.drift.alert", "epochTimeMs": now, "severity": SEVERITIES[severity], "drift": record.json()});
    let host_header = if port == default_port { host.clone() } else { format!("{host}:{port}") };
    Some(json!({
        "method": "POST",
        "path": path,
        "secure": https,
        "socketAddress": {"host": host, "port": port, "scheme": if https { "HTTPS" } else { "HTTP" }},
        "headers": {"Host": [host_header], "content-type": ["application/json; charset=utf-8"]},
        "body": {"type": "STRING", "string": serde_json::to_string(&envelope).unwrap_or_default(), "contentType": "application/json; charset=utf-8"},
    }))
}

/// `HttpState.handleDriftGet`: the records of one expectation (`expectationId`, oldest first), else the newest
/// `limit` (default 50, at most 500), newest first.
pub fn get(state: &State, request: &HttpRequest) -> Reply {
    let records = state.drift.records.lock();
    let selected: Vec<Value> = match crate::request::first(&request.query, "expectationId").filter(|id| !id.is_empty()) {
        Some(id) => records.iter().filter(|r| r.expectation_id == id).map(Record::json).collect(),
        None => {
            let limit = crate::request::first(&request.query, "limit")
                .filter(|l| !l.is_empty())
                .and_then(|l| l.parse::<i32>().ok())
                .map_or(50, |l| l.min(500));
            records.iter().rev().take(limit.max(0) as usize).map(Record::json).collect()
        }
    };
    let mut body = Map::new();
    body.insert("count".into(), selected.len().into());
    body.insert("drifts".into(), Value::Array(selected));
    Reply::api_body(200, "application/json", crate::json::pretty(&Value::Object(body)))
}

/// `PUT /mockserver/drift/clear`.
pub fn clear(state: &State) -> Reply {
    state.drift.clear();
    Reply::api_body(200, "application/json", r#"{"status":"cleared"}"#)
}

/// `FieldDiff`, as the mapper writes it.
struct FieldDiff {
    field: String,
    expected: Option<String>,
    actual: Option<String>,
    kind: &'static str,
}

impl FieldDiff {
    fn added(field: impl Into<String>, actual: Option<String>) -> FieldDiff {
        FieldDiff { field: field.into(), expected: None, actual, kind: "ADDED" }
    }

    fn removed(field: impl Into<String>, expected: Option<String>) -> FieldDiff {
        FieldDiff { field: field.into(), expected, actual: None, kind: "REMOVED" }
    }

    fn changed(field: impl Into<String>, expected: Option<String>, actual: Option<String>) -> FieldDiff {
        FieldDiff { field: field.into(), expected, actual, kind: "CHANGED" }
    }

    fn json(&self) -> Value {
        let mut o = Map::new();
        if let Some(actual) = &self.actual {
            o.insert("actualValue".into(), actual.clone().into());
        }
        o.insert("diffType".into(), self.kind.into());
        if let Some(expected) = &self.expected {
            o.insert("expectedValue".into(), expected.clone().into());
        }
        o.insert("field".into(), self.field.clone().into());
        Value::Object(o)
    }
}

/// `TrafficDiffEngine.diff`: method, path, body, headers, query parameters and cookies.
fn diff_requests(expected: &Definition, actual: &Definition) -> Vec<FieldDiff> {
    let mut diffs = Vec::new();
    scalar(&mut diffs, "method", expected.method.clone(), actual.method.clone());
    scalar(&mut diffs, "path", expected.path.clone(), actual.path.clone());
    let body = |r: &Definition| r.body.as_ref().map(|b| b.text.clone());
    scalar(&mut diffs, "body", body(expected), body(actual));
    entries(&mut diffs, "header", &joined(&expected.headers), &joined(&actual.headers));
    entries(&mut diffs, "queryParam", &joined(&expected.query), &joined(&actual.query));
    let cookies = |r: &Definition| -> Vec<(String, String)> {
        let mut map: Vec<(String, String)> = Vec::new();
        for (name, value) in &r.cookies {
            let key = name.to_lowercase();
            match map.iter_mut().find(|(k, _)| *k == key) {
                Some((_, v)) => *v = value.clone(),
                None => map.push((key, value.clone())),
            }
        }
        map
    };
    entries(&mut diffs, "cookie", &cookies(expected), &cookies(actual));
    diffs
}

/// `TrafficDiffEngine.addDiff`: blank (null or empty) on one side is an addition or a removal.
fn scalar(diffs: &mut Vec<FieldDiff>, field: &str, expected: Option<String>, actual: Option<String>) {
    let (expected, actual) = (expected.filter(|s| !s.is_empty()), actual.filter(|s| !s.is_empty()));
    match (expected, actual) {
        (None, None) => {}
        (None, actual) => diffs.push(FieldDiff::added(field, actual)),
        (expected, None) => diffs.push(FieldDiff::removed(field, expected)),
        (Some(e), Some(a)) if e != a => diffs.push(FieldDiff::changed(field, Some(e), Some(a))),
        _ => {}
    }
}

/// `diffMultiValueEntries` / `diffCookies`: every key of either side, the expected side's first.
fn entries(diffs: &mut Vec<FieldDiff>, prefix: &str, expected: &[(String, String)], actual: &[(String, String)]) {
    let mut keys: Vec<&str> = expected.iter().map(|(k, _)| k.as_str()).collect();
    keys.extend(actual.iter().map(|(k, _)| k.as_str()).filter(|k| !expected.iter().any(|(e, _)| e == k)));
    for key in keys {
        match (value_of(expected, key), value_of(actual, key)) {
            (None, actual) => diffs.push(FieldDiff::added(format!("{prefix}.{key}"), actual.map(str::to_string))),
            (expected, None) => diffs.push(FieldDiff::removed(format!("{prefix}.{key}"), expected.map(str::to_string))),
            (Some(e), Some(a)) if e != a => diffs.push(FieldDiff::changed(format!("{prefix}.{key}"), Some(e.into()), Some(a.into()))),
            _ => {}
        }
    }
}

/// `HttpState.handleDiff`: `PUT /mockserver/diff` with `expected` and `actual` request definitions. Every failure is
/// a 400 `{"error": …}` written by Jackson (`errorJson`), so the message keeps its quotes and newlines escaped.
pub fn diff_endpoint(request: &HttpRequest) -> Reply {
    let error = |message: &str| Reply::api_body(400, "application/json", crate::json::compact(&serde_json::json!({"error": message})));
    let body = request.body_json_or_xml_str();
    if body.is_empty() {
        return error("request body required with 'expected' and 'actual' fields");
    }
    let node = match crate::jnode::read_tree(&body) {
        Ok(_) => crate::json::parse_lenient(body.as_bytes()).unwrap_or(Value::Null),
        Err(e) => return error(&format!("failed to diff requests: {}", e.message)),
    };
    let present = |k: &str| node.get(k).is_some_and(|v| !v.is_null());
    if !present("expected") || !present("actual") {
        return error("both 'expected' and 'actual' HttpRequest fields are required");
    }
    let mut definitions = Vec::new();
    for key in ["expected", "actual"] {
        let definition = &node[key];
        if let Err(report) = crate::schema::validate_request_definition(definition) {
            let raw = serde_json::to_string(definition).unwrap_or_default();
            return error(&format!("failed to diff requests: {}", crate::schema::incorrect_request_matcher(&raw, &report)));
        }
        definitions.push(definition);
    }
    if definitions.iter().any(|d| !is_http_request(d)) {
        return error("both 'expected' and 'actual' must be HttpRequest objects");
    }
    let diffs = diff_requests(&Definition::definition(definitions[0]), &Definition::definition(definitions[1]));
    let mut result = Map::new();
    result.insert("diffCount".into(), diffs.len().into());
    result.insert("identical".into(), diffs.is_empty().into());
    result.insert("diffs".into(), Value::Array(diffs.iter().map(FieldDiff::json).collect()));
    Reply::api_body(200, "application/json", crate::json::pretty(&Value::Object(result)))
}

/// A request definition that deserialises to an `HttpRequest` (not an OpenAPI, binary or DNS definition).
fn is_http_request(definition: &Value) -> bool {
    !["specUrlOrPayload", "binaryData", "dnsName"].iter().any(|k| definition.get(*k).is_some())
}

/// `BaselineDiffer.requestKey`: the method upper-cased (`GET` when blank) and the path without one trailing slash.
fn request_key(request: &Definition) -> String {
    let method = request.method.clone().filter(|m| !m.is_empty()).unwrap_or_else(|| "GET".into());
    format!("{} {}", method.to_uppercase(), normalize_path(request.path.as_deref()))
}

fn normalize_path(path: Option<&str>) -> String {
    match path {
        None | Some("") => "/".into(),
        Some(p) if p.len() > 1 && p.ends_with('/') => p[..p.len() - 1].to_string(),
        Some(p) => p.to_string(),
    }
}

/// One interaction of a set: its key, request and (optional) response.
struct Interaction {
    request: Definition,
    response: Option<Observed>,
}

/// `BaselineDiffer.toInteractions` then `indexByKey`: expectations with an HTTP request definition, the first one per
/// key kept.
fn index(expectations: &[Value]) -> Vec<(String, Interaction)> {
    let mut indexed: Vec<(String, Interaction)> = Vec::new();
    for expectation in expectations {
        let Some(request) = expectation.get("httpRequest").filter(|r| r.is_object() && is_http_request(r)) else { continue };
        let request = Definition::definition(request);
        let key = request_key(&request);
        if indexed.iter().all(|(k, _)| *k != key) {
            let response = expectation.get("httpResponse").filter(|r| r.is_object()).map(Observed::json);
            indexed.push((key, Interaction { request, response }));
        }
    }
    indexed
}

/// `BaselineDiffer.diff`: the report of added, removed and changed interactions, compact.
fn baseline_report(baseline: &[Value], current: &[Value]) -> Value {
    let (baseline, current) = (index(baseline), index(current));
    let mut keys: Vec<&str> = baseline.iter().map(|(k, _)| k.as_str()).collect();
    keys.extend(current.iter().map(|(k, _)| k.as_str()).filter(|k| !baseline.iter().any(|(b, _)| b == k)));
    let (mut added, mut removed, mut changed) = (Vec::new(), Vec::new(), Vec::new());
    for key in keys {
        let find = |set: &[(String, Interaction)]| set.iter().position(|(k, _)| k == key);
        match (find(&baseline).map(|i| &baseline[i].1), find(&current).map(|i| &current[i].1)) {
            (None, _) => added.push(json!({"key": key})),
            (_, None) => removed.push(json!({"key": key})),
            (Some(b), Some(c)) => {
                let mut request_diffs = diff_requests(&b.request, &c.request);
                request_diffs.retain(|d| !(d.field == "path" && d.kind == "CHANGED" && normalize_path(d.expected.as_deref()) == normalize_path(d.actual.as_deref())));
                let response_diffs = diff_responses(b.response.as_ref(), c.response.as_ref());
                if !request_diffs.is_empty() || !response_diffs.is_empty() {
                    let mut o = Map::new();
                    o.insert("key".into(), key.into());
                    if !request_diffs.is_empty() {
                        o.insert("requestDiffs".into(), Value::Array(request_diffs.iter().map(FieldDiff::json).collect()));
                    }
                    if !response_diffs.is_empty() {
                        o.insert("responseDiffs".into(), Value::Array(response_diffs.iter().map(FieldDiff::json).collect()));
                    }
                    changed.push(Value::Object(o));
                }
            }
        }
    }
    let drift = !added.is_empty() || !removed.is_empty() || !changed.is_empty();
    json!({"added": added, "changed": changed, "hasDrift": drift, "removed": removed})
}

/// `BaselineDiffer.diffResponseStructure`: status, headers, and the body's JSON shape.
fn diff_responses(baseline: Option<&Observed>, current: Option<&Observed>) -> Vec<FieldDiff> {
    let mut diffs = Vec::new();
    let (baseline, current) = match (baseline, current) {
        (None, None) => return diffs,
        (None, Some(_)) => return vec![FieldDiff::added("response", Some("entire response".into()))],
        (Some(_), None) => return vec![FieldDiff::removed("response", Some("entire response".into()))],
        (Some(b), Some(c)) => (b, c),
    };
    let (b, c) = (baseline.status.map(|s| s.to_string()), current.status.map(|s| s.to_string()));
    if b != c {
        diffs.push(FieldDiff::changed("response.statusCode", b, c));
    }
    entries(&mut diffs, "response.header", &joined(&baseline.headers), &joined(&current.headers));
    let (b, c) = (baseline.body.clone().filter(|s| !s.is_empty()), current.body.clone().filter(|s| !s.is_empty()));
    match (b, c) {
        (None, None) => {}
        (None, c) => diffs.push(FieldDiff::added("response.body", c)),
        (b, None) => diffs.push(FieldDiff::removed("response.body", b)),
        (Some(b), Some(c)) => match (crate::json::parse_lenient(b.as_bytes()), crate::json::parse_lenient(c.as_bytes())) {
            (Ok(bn), Ok(cn)) => shape(&mut diffs, "response.body", &bn, &cn),
            _ if b != c => diffs.push(FieldDiff::changed("response.body", Some(b), Some(c))),
            _ => {}
        },
    }
    diffs
}

/// `BaselineDiffer.nodeType`.
fn node_type(node: Option<&Value>) -> &'static str {
    match node {
        None | Some(Value::Null) => "null",
        Some(Value::Object(_)) => "object",
        Some(Value::Array(_)) => "array",
        Some(Value::Number(_)) => "number",
        Some(Value::Bool(_)) => "boolean",
        Some(Value::String(_)) => "string",
    }
}

/// `BaselineDiffer.diffJsonShape`: a type change, or the fields (and positional elements) added, removed or changed
/// below; a scalar's value never counts.
fn shape(diffs: &mut Vec<FieldDiff>, path: &str, baseline: &Value, current: &Value) {
    let (bt, ct) = (node_type(Some(baseline)), node_type(Some(current)));
    if bt != ct {
        diffs.push(FieldDiff::changed(path, Some(bt.into()), Some(ct.into())));
        return;
    }
    match (baseline, current) {
        (Value::Object(b), Value::Object(c)) => {
            let mut fields: Vec<&String> = b.keys().collect();
            fields.extend(c.keys().filter(|k| !b.contains_key(*k)));
            for field in fields {
                let child = format!("{path}.{field}");
                match (b.get(field), c.get(field)) {
                    (None, c) => diffs.push(FieldDiff::added(child, Some(node_type(c).into()))),
                    (b, None) => diffs.push(FieldDiff::removed(child, Some(node_type(b).into()))),
                    (Some(b), Some(c)) => shape(diffs, &child, b, c),
                }
            }
        }
        (Value::Array(b), Value::Array(c)) => {
            for i in 0..b.len().max(c.len()) {
                let child = format!("{path}[{i}]");
                match (b.get(i), c.get(i)) {
                    (None, c) => diffs.push(FieldDiff::added(child, Some(node_type(c).into()))),
                    (b, None) => diffs.push(FieldDiff::removed(child, Some(node_type(b).into()))),
                    (Some(b), Some(c)) => shape(diffs, &child, b, c),
                }
            }
        }
        _ => {}
    }
}

/// `HttpState`'s `PUT /mockserver/baseline/compare`: `baseline` (and `current`, else the active expectations) as
/// expectation arrays, deserialised and validated as `ExpectationSerializer.deserializeArray` does. `Err` is the
/// message of the 400, which the caller logs.
pub fn baseline_compare(state: &State, request: &HttpRequest) -> Result<Reply, String> {
    let body = request.body_json_or_xml_str();
    if body.trim().is_empty() {
        return Err("baseline compare request body is required — must be a JSON document with a \"baseline\" (and optional \"current\") array of expectations".into());
    }
    if let Err(e) = crate::jnode::read_tree(&body) {
        return Err(e.message);
    }
    let root = crate::json::parse_lenient(body.as_bytes()).map_err(|e| e.to_string())?;
    let baseline = root.get("baseline").filter(|b| !b.is_null()).ok_or("baseline compare request body must contain a \"baseline\" array of expectations")?;
    let baseline = expectations(baseline)?;
    let current = match root.get("current").filter(|c| !c.is_null()) {
        Some(current) => expectations(current)?,
        None => state.store.active().iter().map(|e| e.input.clone()).collect(),
    };
    Ok(Reply::api_body(200, "application/json", serde_json::to_string(&baseline_report(&baseline, &current)).unwrap_or_default()))
}

/// `ExpectationSerializer.deserializeArray(json, true)`: an array of expectations (a single one alone), each
/// validated against the expectation schema.
fn expectations(v: &Value) -> Result<Vec<Value>, String> {
    let items = match v {
        Value::Array(items) => items.clone(),
        other => vec![other.clone()],
    };
    let mut errors = Vec::new();
    for item in &items {
        if let Err(report) = crate::schema::validate_expectation(item) {
            errors.push(crate::schema::incorrect_expectation(item, &report));
        }
    }
    match errors.len() {
        0 => Ok(items),
        1 => Err(errors.remove(0)),
        _ => Err(format!("{}\n]", format!("[\n{}", errors.join(",\n\n")).replace('\n', "\n  "))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok() -> Observed {
        Observed { status: Some(200), headers: Vec::new(), body: None }
    }

    fn changed(field: &str, expected: &str, actual: &str) -> Record {
        Record::new("e", "HEADER_CHANGED", field, 0.85, 0).expected(expected).actual(actual)
    }

    // SemanticDriftExtensionTest (9.1.0, 672a2bcfc).

    /// `buildPromptMasksKeyValueCredentialInDriftValueOfNonCredentialField`.
    #[test]
    fn build_prompt_masks_key_value_credential_in_drift_value_of_non_credential_field() {
        let prompt = semantic_prompt(&[changed("header.x-debug", "user=bob token=stub-kv-secret", "user=bob api_key=live-kv-secret")], &ok(), &ok(), None);
        assert!(!prompt.contains("stub-kv-secret") && !prompt.contains("live-kv-secret"), "{prompt}");
        assert!(prompt.contains("expected=user=bob token=***REDACTED***"), "{prompt}");
        assert!(prompt.contains("actual=user=bob api_key=***REDACTED***"), "{prompt}");
    }

    /// `buildPromptMasksDriftValuesOfSensitiveResponseHeaders`.
    #[test]
    fn build_prompt_masks_drift_values_of_sensitive_response_headers() {
        let records = [
            changed("header.set-cookie", "SESSIONID=stub-cookie-secret; Path=/", "SESSIONID=live-cookie-secret; Path=/"),
            Record::new("e", "HEADER_ADDED", "header.X-Auth-Token", 0.9, 0).actual("opaque-auth-secret"),
            changed("header.content-type", "application/json", "text/plain"),
        ];
        let prompt = semantic_prompt(&records, &ok(), &ok(), None);
        assert!(!prompt.contains("cookie-secret") && !prompt.contains("opaque-auth-secret"), "{prompt}");
        assert!(prompt.contains("'header.set-cookie': expected=***REDACTED***, actual=***REDACTED***"), "{prompt}");
        assert!(prompt.contains("'header.content-type': expected=application/json, actual=text/plain"), "{prompt}");
    }

    /// `buildPromptMasksDriftValuesOfConfiguredDataPlaneApiKeyHeader`.
    #[test]
    fn build_prompt_masks_drift_values_of_configured_data_plane_api_key_header() {
        let records = [changed("header.X-Tenant-Key", "stub-tenant-secret", "live-tenant-secret")];
        assert!(semantic_prompt(&records, &ok(), &ok(), None).contains("live-tenant-secret"));
        let prompt = semantic_prompt(&records, &ok(), &ok(), Some("x-tenant-key"));
        assert!(prompt.contains("'header.X-Tenant-Key': expected=***REDACTED***, actual=***REDACTED***"), "{prompt}");
    }
}
