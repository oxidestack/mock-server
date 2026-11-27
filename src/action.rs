//! Expectation actions, compiled from the input JSON (the input keeps details the canonical form drops, such as
//! whether a JSON body was given as a string).

use std::time::Duration;

use base64::Engine;
use bytes::Bytes;
use serde_json::{Map, Value};

use crate::canonical;
use crate::json;
use crate::reply::Reply;
use crate::request::HttpRequest;

#[derive(Debug)]
pub enum Action {
    Respond(Box<Respond>),
    /// `httpError`: write `response_bytes` verbatim (if any), then close when `drop_connection`; with neither,
    /// nothing is written and the connection is left open, as upstream does.
    /// `streamError` resets the request's HTTP/2 stream with that code instead (a dropped connection over HTTP/1.1).
    Error { delay: Option<Delay>, drop_connection: bool, reset_connection: bool, response_bytes: Option<Bytes>, stream_error: Option<u32> },
    /// `httpSseResponse`: events streamed one by one, each after its delay.
    Sse(Box<Sse>),
    /// `httpLlmResponse` (OpenAI chat completions).
    Llm(Box<crate::llm::Llm>),
    /// `httpForward` / `httpOverrideForwardedRequest`.
    Forward(Box<crate::forward::Forward>),
    /// `httpResponseTemplate`: render the response from the request.
    ResponseTemplate { template: crate::templates::Template, delay: Option<Delay> },
    /// `httpResponseObjectCallback`: ask a WebSocket client for the response.
    ResponseCallback { client_id: String, delay: Option<Delay> },
    /// `httpResponseClassCallback`: a callback class returns the response.
    ResponseClassCallback { class: String, delay: Option<Delay> },
    /// `httpResponses` with `responseMode`: one of several responses per match.
    Responses(Box<Responses>),
    /// `httpWebSocketResponse`: the upgrade is completed and a scripted session served (`crate::ws_mock`).
    WebSocket(Box<Value>),
    /// `grpcStreamResponse`: a gRPC server stream of scripted messages, then the status trailers.
    GrpcStream(Box<Value>),
    /// `grpcBidiResponse`: served by the HTTP/2 connection itself, message by message (`grpc_plane::open_bidi`);
    /// reached through ordinary dispatch it answers nothing.
    GrpcBidi(Box<Value>),
    /// An action this server does not perform (class callbacks, templates, forwards, … for now): answered 404.
    Unsupported(String),
    /// `binaryResponse` / `dnsResponse`: they answer binary and DNS traffic; an HTTP request they match is answered
    /// 501 (9.2.0, #84). Holds the action type's name, `BINARY_RESPONSE` or `DNS_RESPONSE`.
    NonHttp(&'static str),
}

#[derive(Debug, Clone)]
pub struct Respond {
    pub reply: Reply,
    pub delay: Option<Delay>,
    /// A `FILE` body, read (and rendered) when the response is written.
    pub file: Option<FileBody>,
    /// The body `generateFromSchema` produced, which the served response carries as a JSON string body.
    pub generated: Option<String>,
    /// Why `generateFromSchema` produced nothing (`JsonSchemaResponseSynthesisException`'s cause), logged as a WARN
    /// each time the response is served.
    pub generate_failure: Option<String>,
}

impl Respond {
    /// The served response as logged and recorded: the action, with a generated body filled in.
    pub fn served(&self, action: Value) -> Value {
        let Some(generated) = &self.generated else { return action };
        let mut with_body = action.as_object().cloned().unwrap_or_default();
        with_body.insert("body".into(), serde_json::json!({"type": "STRING", "string": generated, "contentType": "application/json"}));
        canonical::response(&Value::Object(with_body))
    }
}

/// `FileBody`: `filePath`, `contentType`, an optional `templateType` and `templatedFilePath` (9.2.0).
#[derive(Debug, Clone)]
pub struct FileBody {
    pub path: String,
    pub content_type: Option<String>,
    pub template: Option<crate::templates::Engine>,
    /// `templatedFilePath`: the path itself is rendered against the request and confined
    /// (`crate::file_path_guard`).
    pub templated_path: bool,
}

/// A `FILE` body's template that failed to render: `renderTemplate`'s exception message and, when the caller had
/// the server state, its bean (`TemplateEvaluationException`).
#[derive(Debug)]
pub struct RenderFailure {
    pub message: String,
    pub bean: Option<Value>,
}

/// `FileBodyException`: the file could not be read; the response is a 500.
#[derive(Debug)]
pub struct FileBodyError {
    /// `getFilePath()`: the literal path, or the rendered one with control characters escaped.
    pub path: String,
    /// The cause's message: the `RuntimeException`'s (`Exception while loading "<path>"`) for a literal path, the
    /// guard's or the I/O exception's for a rendered one.
    pub message: String,
    pub cause: FileBodyCause,
}

/// What a `FileBodyException` wraps.
#[derive(Debug)]
pub enum FileBodyCause {
    /// `FileReader`'s `RuntimeException`, caused by the `FileNotFoundException` of `FileInputStream`:
    /// `<canonical path> (<reason>)`.
    Loading(String),
    /// `TemplatedFilePathGuard.readConfined`'s exception, boxed so the error stays small.
    Confined(Box<crate::file_path_guard::Failure>),
}

impl FileBodyError {
    /// The `FileBodyException` as Jackson's bean (`stackTrace` empty: JVM frames cannot be reproduced).
    pub fn bean(&self) -> Value {
        let throwable = |message: &str| serde_json::json!({"localizedMessage": message, "message": message, "stackTrace": []});
        let mut runtime = serde_json::Map::new();
        match &self.cause {
            FileBodyCause::Loading(cause) => {
                runtime.insert("cause".into(), throwable(cause));
                if let Value::Object(rest) = throwable(&self.message) {
                    runtime.extend(rest);
                }
            }
            FileBodyCause::Confined(failure) => {
                if let Some(file) = &failure.file {
                    runtime.insert("file".into(), file.clone().into());
                }
                if let Some(reason) = &failure.reason {
                    runtime.insert("reason".into(), reason.clone().into());
                }
                if let Value::Object(rest) = throwable(&failure.message) {
                    runtime.extend(rest);
                }
            }
        }
        let outer = format!("Exception while loading file body \"{}\"", self.path);
        let mut bean = serde_json::Map::new();
        bean.insert("cause".into(), Value::Object(runtime));
        bean.insert("filePath".into(), self.path.clone().into());
        if let Value::Object(rest) = throwable(&outer) {
            bean.extend(rest);
        }
        Value::Object(bean)
    }

    /// The classes of the exception chain, outermost first (for [`crate::log::throwable_text`]).
    pub fn classes(&self) -> Vec<&'static str> {
        match &self.cause {
            FileBodyCause::Loading(_) => vec!["org.mockserver.file.FileBodyException", "java.lang.RuntimeException", "java.io.FileNotFoundException"],
            FileBodyCause::Confined(failure) => vec!["org.mockserver.file.FileBodyException", failure.class],
        }
    }
}

/// `new File(path).getCanonicalFile().getPath()`: absolute against the working directory, `.` and `..` removed and
/// symbolic links resolved as far as the path exists.
fn java_canonical_path(path: &str) -> String {
    let absolute = std::env::current_dir().map(|cwd| cwd.join(path)).unwrap_or_else(|_| std::path::PathBuf::from(path));
    let mut normal = std::path::PathBuf::new();
    for part in absolute.components() {
        match part {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normal.pop();
            }
            other => normal.push(other),
        }
    }
    // the longest existing prefix resolved, the rest appended
    let mut existing = normal.clone();
    let mut rest = Vec::new();
    loop {
        if let Ok(real) = std::fs::canonicalize(&existing) {
            let mut out = real;
            out.extend(rest.iter().rev());
            return out.to_string_lossy().into_owned();
        }
        match (existing.file_name().map(|n| n.to_os_string()), existing.parent().map(std::path::Path::to_path_buf)) {
            (Some(name), Some(parent)) => {
                rest.push(name);
                existing = parent;
            }
            _ => return normal.to_string_lossy().into_owned(),
        }
    }
}

/// The JDK's text of an `open`/`read` failure: the C library's `strerror` text, without Rust's ` (os error N)`.
fn os_reason(e: &std::io::Error) -> String {
    let text = e.to_string();
    match text.rfind(" (os error ") {
        Some(at) => text[..at].to_string(),
        None => text,
    }
}

impl FileBody {
    fn compile(o: &Map<String, Value>) -> FileBody {
        let text = |k: &str| canonical::field(o, k).and_then(Value::as_str).map(str::to_string);
        let template = match text("templateType").as_deref() {
            Some("VELOCITY") => Some(crate::templates::Engine::Velocity),
            Some("MUSTACHE") => Some(crate::templates::Engine::Mustache),
            Some("JAVASCRIPT") => Some(crate::templates::Engine::JavaScript),
            _ => None,
        };
        let templated_path = canonical::templated_file_path(o).unwrap_or(false);
        FileBody { path: text("filePath").unwrap_or_default(), content_type: text("contentType").filter(|c| !c.trim().is_empty()), template, templated_path }
    }

    /// `FileReader.readBytesFromClassPathOrPath`, wrapped in `FileBodyException` as `FileBodyMaterialiser` does.
    fn read(&self) -> Result<Vec<u8>, FileBodyError> {
        crate::class_path::read_or_file(&self.path).map_err(|e| FileBodyError {
            path: self.path.clone(),
            message: format!("Exception while loading \"{}\"", self.path),
            cause: FileBodyCause::Loading(format!("{} ({})", java_canonical_path(&self.path), os_reason(&e))),
        })
    }

    /// `readFileTemplate`: the literal path, unless `templatedFilePath` is set and the path has template syntax:
    /// then the path is rendered (a failure is `Ok(Err(message))`, as for the contents), confined and read by
    /// `TemplatedFilePathGuard`. A path without template syntax never reaches the engine.
    fn read_template(&self, engine: crate::templates::Engine, render: &dyn Fn(&str) -> Result<String, RenderFailure>) -> Result<Result<Vec<u8>, RenderFailure>, FileBodyError> {
        use crate::file_path_guard as guard;
        let marker = if self.templated_path { guard::first_template_marker(&self.path, engine) } else { None };
        let Some(marker) = marker else { return self.read().map(Ok) };
        let rendered = match render(&self.path) {
            Ok(rendered) => rendered,
            Err(failure) => return Ok(Err(failure)),
        };
        guard::read_confined(&self.path, marker, &rendered).map(Ok).map_err(|failure| FileBodyError {
            path: guard::printable(&rendered),
            message: failure.message.clone(),
            cause: FileBodyCause::Confined(Box::new(failure)),
        })
    }

    /// `FileBodyMaterialiser.materialise`: the body bytes and its content type. A template (of the contents or of a
    /// `templatedFilePath` path) that fails to render is `Ok(Err(failure))` (`handleAnyException`: the action answers
    /// 404, then logs the exception), an unreadable file `Err` (500).
    /// `state` (when the caller has it) applies the engines' disallowed text. Blank text is served as it is: the
    /// `StringBody` keeps its bytes, and `BodyDecoderEncoder` writes `getRawBytes` (upstream master).
    pub fn materialise(&self, state: Option<&crate::state::State>, request: &HttpRequest) -> Result<Result<(Bytes, Option<String>), RenderFailure>, FileBodyError> {
        use crate::templates::Engine;
        if let Some(engine @ (Engine::Velocity | Engine::Mustache)) = self.template {
            let render = |source: &str| match state {
                Some(state) => crate::templates::render_text_thrown(state, &state.velocity_engines.file_body, engine, source, request)
                    .map_err(|(message, bean)| RenderFailure { message, bean: Some(bean) }),
                None => crate::templates::render_text_unscoped(engine, source, request).map_err(|message| RenderFailure { message, bean: None }),
            };
            let source = match self.read_template(engine, &render)? {
                Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
                Err(failure) => return Ok(Err(failure)),
            };
            let rendered = render(&source);
            return Ok(rendered.map(|rendered| (Bytes::from(canonical::encode(&rendered, self.content_type.as_deref())), self.content_type.clone())));
        }
        let media = crate::media_type::MediaType::parse(self.content_type.as_deref());
        let bytes = self.read()?;
        if self.content_type.is_some() && media.is_string() {
            let text = String::from_utf8_lossy(&bytes).into_owned();
            return Ok(Ok((Bytes::from(canonical::encode(&text, self.content_type.as_deref())), self.content_type.clone())));
        }
        Ok(Ok((Bytes::from(bytes), self.content_type.clone())))
    }
}


/// A `Delay`: fixed, or a template rendered against the request (`DelayTemplateResolver`) that falls back to
/// the fixed value when it renders nothing numeric.
#[derive(Debug, Clone)]
pub struct Delay {
    pub fixed: Duration,
    pub template: Option<crate::templates::Template>,
    /// `DelayDistribution` with the delay's `timeUnit`: when set, each sample is drawn from it.
    pub distribution: Option<(Distribution, String)>,
}

/// `DelayDistribution`: its parameters as given, in the delay's time unit.
#[derive(Debug, Clone, Default)]
pub struct Distribution {
    pub kind: String,
    pub min: Option<i64>,
    pub max: Option<i64>,
    pub median: Option<i64>,
    pub p99: Option<i64>,
    pub mean: Option<i64>,
    pub std_dev: Option<i64>,
}

/// `DelayDistribution.MAX_DELAY_VALUE`.
const MAX_DELAY_VALUE: i64 = 86_400_000;
const Z_SCORE_P99: f64 = 2.326347874;

/// `ThreadLocalRandom.nextGaussian` (Box-Muller over the OS generator; unseeded upstream too).
fn next_gaussian() -> f64 {
    let u1 = crate::random::uniform().max(f64::MIN_POSITIVE);
    let u2 = crate::random::uniform();
    (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos()
}

impl Distribution {
    fn from_json(v: &Value) -> Option<Distribution> {
        let long = |k: &str| v.get(k).and_then(Value::as_i64);
        Some(Distribution {
            kind: v.get("type")?.as_str()?.to_string(),
            min: long("min"),
            max: long("max"),
            median: long("median"),
            p99: long("p99"),
            mean: long("mean"),
            std_dev: long("stdDev"),
        })
    }

    /// `DelayDistribution.sample`.
    pub fn sample(&self) -> i64 {
        let clamp = |v: i64| v.clamp(0, MAX_DELAY_VALUE);
        match self.kind.as_str() {
            "UNIFORM" => {
                let lo = self.min.unwrap_or(0).max(0);
                let hi = self.max.map_or(lo, |m| m.max(lo));
                if lo >= hi {
                    return clamp(lo);
                }
                let span = (hi - lo) as u64 + u64::from(hi != i64::MAX);
                clamp(lo + (crate::random::uniform() * span as f64) as i64)
            }
            "LOG_NORMAL" => {
                let median = self.median.filter(|m| *m > 0).unwrap_or(1);
                let p99 = self.p99.unwrap_or(median);
                if p99 <= median {
                    return clamp(median);
                }
                let mu = (median as f64).ln();
                let sigma = ((p99 as f64).ln() - mu) / Z_SCORE_P99;
                clamp((mu + sigma * next_gaussian()).exp().round() as i64)
            }
            "GAUSSIAN" => {
                let mean = self.mean.unwrap_or(0).max(0);
                let sd = self.std_dev.unwrap_or(0).max(0);
                if sd == 0 {
                    return clamp(mean);
                }
                clamp((mean as f64 + sd as f64 * next_gaussian()).round() as i64)
            }
            _ => 0,
        }
    }
}

/// `TimeUnit.toMillis`.
fn unit_millis(unit: &str, n: i64) -> i64 {
    match unit {
        "DAYS" => n.saturating_mul(86_400_000),
        "HOURS" => n.saturating_mul(3_600_000),
        "MINUTES" => n.saturating_mul(60_000),
        "SECONDS" => n.saturating_mul(1_000),
        "MICROSECONDS" => n / 1_000,
        "NANOSECONDS" => n / 1_000_000,
        _ => n,
    }
}

impl Delay {
    /// `sampleValueMillis`: a draw from the distribution, else the fixed value.
    pub fn sample(&self) -> Duration {
        match &self.distribution {
            Some((d, unit)) => Duration::from_millis(unit_millis(unit, d.sample()).max(0) as u64),
            None => self.fixed,
        }
    }

    pub fn resolve(&self, state: &crate::state::State, request: &HttpRequest) -> Duration {
        let Some(t) = &self.template else { return self.sample() };
        if t.engine == crate::templates::Engine::Velocity {
            crate::foreign::velocity_sandboxed(state);
        }
        let fallback = |reason: &str, thrown: Option<(String, Value)>| {
            // `mockServerLogger.logEvent` with `setHttpRequest(request)`: an event-log entry too
            let mut entry = crate::recorded::LogEntry::at(crate::recorded::Level::Warn, "falling back to static delay because:{}").request(request).args([reason]);
            // a rendering exception is the entry's throwable
            if let Some((text, bean)) = thrown {
                entry = entry.throwable(format!("java.lang.RuntimeException: {text}")).throwable_bean(bean);
            }
            crate::log::warn_event_about(state, entry, request);
            self.fixed
        };
        match crate::templates::render_text_thrown(state, &state.velocity_engines.delay, t.engine, &t.source, request) {
            Ok(rendered) => match parse_millis(&rendered) {
                Some(ms) => Duration::from_millis(ms),
                None => fallback(&format!("delay template rendered non-numeric value \"{rendered}\""), None),
            },
            Err(thrown) => fallback("exception rendering delay template", Some(thrown)),
        }
    }
}

/// `DelayTemplateResolver.parseMillis`.
fn parse_millis(rendered: &str) -> Option<u64> {
    let trimmed = rendered.trim();
    if trimmed.is_empty() {
        return None;
    }
    let digits = trimmed.strip_prefix(['+', '-']).unwrap_or(trimmed);
    if !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit()) && let Ok(v) = trimmed.parse::<i64>() {
        return u64::try_from(v).ok();
    }
    let d = velocity::uberspect::parse_double(trimmed).ok()?;
    if d.is_nan() || d.is_infinite() || d < 0.0 || d > i64::MAX as f64 {
        return None;
    }
    Some(d as u64)
}

impl Action {
    pub fn compile(expectation: &Map<String, Value>) -> Action {
        if let Some(responses) = expectation.get("httpResponses").and_then(Value::as_array).filter(|r| !r.is_empty()) {
            return Action::Responses(Box::new(Responses::compile(responses, expectation)));
        }
        if let Some(r) = expectation.get("httpResponse") {
            return Action::Respond(Box::new(respond(r)));
        }
        if let Some(e) = expectation.get("httpError") {
            return Action::Error {
                delay: e.get("delay").and_then(delay),
                drop_connection: e.get("dropConnection").and_then(Value::as_bool).unwrap_or(false),
                reset_connection: e.get("resetConnection").and_then(Value::as_bool).unwrap_or(false),
                response_bytes: e
                    .get("responseBytes")
                    .and_then(Value::as_str)
                    .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok())
                    .map(Bytes::from),
                stream_error: e.get("streamError").and_then(Value::as_u64).map(|c| c as u32),
            };
        }
        if let Some(sse) = expectation.get("httpSseResponse") {
            return Action::Sse(Box::new(Sse::compile(sse)));
        }
        if let Some(llm) = expectation.get("httpLlmResponse") {
            return match crate::llm::Llm::compile(llm) {
                Ok(llm) => Action::Llm(Box::new(llm)),
                Err(what) => Action::Unsupported(what),
            };
        }
        if let Some(bidi) = expectation.get("grpcBidiResponse").filter(|g| g.is_object()) {
            return Action::GrpcBidi(Box::new(bidi.clone()));
        }
        if let Some(stream) = expectation.get("grpcStreamResponse").filter(|g| g.is_object()) {
            return Action::GrpcStream(Box::new(stream.clone()));
        }
        if let Some(ws) = expectation.get("httpWebSocketResponse").filter(|w| w.is_object()) {
            return Action::WebSocket(Box::new(ws.clone()));
        }
        if let Some(t) = expectation.get("httpResponseTemplate") {
            return Action::ResponseTemplate { template: crate::templates::Template::compile(t), delay: t.get("delay").and_then(delay) };
        }
        if let Some(f) = crate::forward::Forward::compile(expectation) {
            return Action::Forward(Box::new(f));
        }
        if let Some(c) = expectation.get("httpResponseObjectCallback") {
            return Action::ResponseCallback {
                client_id: c.get("clientId").and_then(Value::as_str).unwrap_or_default().to_string(),
                delay: c.get("delay").and_then(delay),
            };
        }
        if let Some(c) = expectation.get("httpResponseClassCallback") {
            return Action::ResponseClassCallback {
                class: c.get("callbackClass").and_then(Value::as_str).unwrap_or_default().to_string(),
                delay: c.get("delay").and_then(delay),
            };
        }
        if expectation.get("binaryResponse").is_some() {
            return Action::NonHttp("BINARY_RESPONSE");
        }
        if expectation.get("dnsResponse").is_some() {
            return Action::NonHttp("DNS_RESPONSE");
        }
        let kind = expectation.keys().find(|k| k.starts_with("http") && *k != "httpRequest").cloned().unwrap_or_default();
        Action::Unsupported(kind)
    }
}

/// `ResponseMode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseMode {
    Sequential,
    Random,
    Weighted,
    Switch,
}

/// `httpResponses`: the responses, as served and as logged, and how one is chosen.
#[derive(Debug)]
pub struct Responses {
    pub responses: Vec<(Respond, Value)>,
    pub mode: ResponseMode,
    pub weights: Vec<i64>,
    pub switch_after: i64,
}

impl Responses {
    fn compile(responses: &[Value], expectation: &Map<String, Value>) -> Responses {
        let mode = match expectation.get("responseMode").and_then(Value::as_str).map(str::to_ascii_uppercase).as_deref() {
            Some("RANDOM") => ResponseMode::Random,
            Some("WEIGHTED") => ResponseMode::Weighted,
            Some("SWITCH") => ResponseMode::Switch,
            _ => ResponseMode::Sequential,
        };
        Responses {
            responses: responses.iter().map(|r| (respond(r), canonical::response(r))).collect(),
            mode,
            weights: expectation.get("responseWeights").and_then(Value::as_array).map(|w| w.iter().map(|v| v.as_i64().unwrap_or(0)).collect()).unwrap_or_default(),
            switch_after: expectation.get("switchAfter").and_then(Value::as_i64).unwrap_or(0),
        }
    }

    /// `Expectation.selectFromResponses`: the index served for the match that took `rotation` (1-based), unless
    /// `x-mockserver-response-index` names one.
    pub fn select(&self, rotation: u32, forced: Option<usize>) -> usize {
        let size = self.responses.len();
        if let Some(index) = forced.filter(|i| *i < size) {
            return index;
        }
        let random = |bound: usize| {
            use rand_core::RngCore;
            (rand_core::OsRng.next_u64() % bound as u64) as usize
        };
        let count = rotation.saturating_sub(1) as usize;
        match self.mode {
            ResponseMode::Random => random(size),
            ResponseMode::Weighted => {
                let weights: Vec<i64> = (0..size).map(|i| self.weights.get(i).copied().filter(|w| *w > 0).unwrap_or(1)).collect();
                let total: i64 = weights.iter().sum();
                let target = random(total as usize) as i64;
                let mut cumulative = 0;
                weights.iter().position(|w| {
                    cumulative += w;
                    target < cumulative
                })
                .unwrap_or(size - 1)
            }
            ResponseMode::Switch => {
                let threshold = if self.switch_after > 0 { self.switch_after as usize } else { 1 };
                (count / threshold).min(size - 1)
            }
            ResponseMode::Sequential => count % size,
        }
    }
}

/// `parseForcedResponseIndex`: the `x-mockserver-response-index` header as a number.
pub fn forced_response_index(request: &HttpRequest) -> Option<i64> {
    request.first_header("x-mockserver-response-index").and_then(|v| v.trim().parse::<i32>().ok()).map(i64::from)
}

/// `HttpSseResponse`.
#[derive(Debug)]
pub struct Sse {
    pub status: u32,
    pub headers: Vec<(String, String)>,
    pub events: Vec<SseEvent>,
    pub delay: Option<Delay>,
    pub template: Option<crate::templates::Engine>,
    pub close_connection: Option<bool>,
    /// How each event is framed (`StreamingFormat`): SSE, or for an LLM stream NDJSON or the AWS event stream.
    pub format: crate::llm::codec::Format,
}

#[derive(Debug, Clone, Default)]
pub struct SseEvent {
    pub event: Option<String>,
    pub data: Option<String>,
    pub id: Option<String>,
    pub retry: Option<i64>,
    pub delay: Option<Delay>,
}

impl Sse {
    fn compile(v: &Value) -> Sse {
        let text = |o: &Value, k: &str| o.get(k).and_then(Value::as_str).map(str::to_string);
        let mut headers = Vec::new();
        for (name, values) in crate::model::multi_values(v.get("headers").unwrap_or(&Value::Null)) {
            for value in values.into_iter().flatten() {
                headers.push((name.value.clone().unwrap_or_default(), value.value.unwrap_or_default()));
            }
        }
        Sse {
            status: v.get("statusCode").and_then(Value::as_u64).map(|c| c as u32).unwrap_or(200),
            headers,
            events: v
                .get("events")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .map(|e| SseEvent { event: text(e, "event"), data: text(e, "data"), id: text(e, "id"), retry: e.get("retry").and_then(Value::as_i64), delay: e.get("delay").and_then(delay) })
                .collect(),
            delay: v.get("delay").and_then(delay),
            template: v.get("templateType").and_then(Value::as_str).map(|t| crate::templates::Engine::parse(Some(t))),
            close_connection: v.get("closeConnection").and_then(Value::as_bool),
            format: crate::llm::codec::Format::Sse,
        }
    }
}

impl SseEvent {
    /// `formatSseEvent`: `id`, `event`, `retry`, then one `data:` line per line of data, and a blank line.
    /// `formatChunkBytes`: the event framed for `format`.
    pub fn framed(&self, format: crate::llm::codec::Format) -> Vec<u8> {
        match format {
            crate::llm::codec::Format::Sse => self.format().into_bytes(),
            crate::llm::codec::Format::Ndjson => format!("{}\n", self.data.as_deref().unwrap_or_default()).into_bytes(),
            crate::llm::codec::Format::JsonArray => self.data.as_deref().unwrap_or_default().as_bytes().to_vec(),
            crate::llm::codec::Format::AwsEventStream => crate::llm::codec::event_stream_chunk(self.data.as_deref().unwrap_or_default()),
            crate::llm::codec::Format::AwsConverseEventStream => crate::llm::converse::framed(self),
        }
    }

    pub fn format(&self) -> String {
        let clean = |v: &str| v.replace(['\n', '\r'], "");
        let mut out = String::new();
        if let Some(id) = &self.id {
            out.push_str(&format!("id: {}\n", clean(id)));
        }
        if let Some(event) = &self.event {
            out.push_str(&format!("event: {}\n", clean(event)));
        }
        if let Some(retry) = self.retry {
            out.push_str(&format!("retry: {retry}\n"));
        }
        if let Some(data) = &self.data {
            for line in data.split("\r\n").flat_map(|l| l.split(['\r', '\n'])) {
                out.push_str(&format!("data: {line}\n"));
            }
        }
        out.push('\n');
        out
    }
}

pub fn delay(v: &Value) -> Option<Delay> {
    let template = match (v.get("template").and_then(Value::as_str), v.get("templateType").and_then(Value::as_str)) {
        (Some(t), Some(kind)) => Some(crate::templates::Template { engine: crate::templates::Engine::parse(Some(kind)), source: t.to_string(), file: None, parameters: None }),
        _ => None,
    };
    let distribution = v.get("distribution").and_then(Distribution::from_json).map(|d| (d, v.get("timeUnit").and_then(Value::as_str).unwrap_or("MILLISECONDS").to_string()));
    let fixed = fixed_delay(v).unwrap_or_default();
    if template.is_none() && distribution.is_none() && fixed_delay(v).is_none() {
        return None;
    }
    Some(Delay { fixed, template, distribution })
}

fn fixed_delay(v: &Value) -> Option<Duration> {
    let value = v.get("value")?.as_u64()?;
    let d = match v.get("timeUnit").and_then(Value::as_str).unwrap_or("MILLISECONDS") {
        "DAYS" => Duration::from_secs(value * 86_400),
        "HOURS" => Duration::from_secs(value * 3_600),
        "MINUTES" => Duration::from_secs(value * 60),
        "SECONDS" => Duration::from_secs(value),
        "MICROSECONDS" => Duration::from_micros(value),
        "NANOSECONDS" => Duration::from_nanos(value),
        _ => Duration::from_millis(value),
    };
    Some(d)
}

/// A response action from `httpResponse` JSON (also used for callback clients' answers).
pub fn respond(v: &Value) -> Respond {
    let empty = Map::new();
    let o = v.as_object().unwrap_or(&empty);
    let mut reply = Reply::status(o.get("statusCode").and_then(Value::as_u64).map(|s| s as u32).unwrap_or(200));
    reply.reason = o.get("reasonPhrase").and_then(Value::as_str).map(str::to_string);

    // Headers in the order they were given (the model's), then cookies not already sent as `Set-Cookie`.
    if let Some(headers) = o.get("headers") {
        for (name, values) in crate::model::multi_values(headers) {
            let Some(name) = name.value else { continue };
            for value in values.into_iter().flatten().filter_map(|v| v.value) {
                reply.headers.push((name.clone(), value));
            }
        }
    }
    if let Some(trailers) = o.get("trailers") {
        for (name, values) in crate::model::multi_values(trailers) {
            let Some(name) = name.value else { continue };
            for value in values.into_iter().flatten().filter_map(|v| v.value) {
                reply.trailers.push((name.clone(), value));
            }
        }
    }
    if let Some(cookies) = o.get("cookies") {
        for (name, values) in crate::model::key_values(cookies) {
            let (Some(name), Some(value)) = (name.value, values.into_iter().flatten().next().map(|v| v.marked())) else { continue };
            // `HttpResponse.cookieHeaderDoesNotAlreadyExists`: every `Set-Cookie` value through `ClientCookieDecoder.LAX`
            let already_set = reply.headers.iter().any(|(k, v)| {
                k.eq_ignore_ascii_case("set-cookie")
                    && crate::request::client_cookie_decoder_lax(v).is_some_and(|(n, cv)| {
                        crate::dns::java_equals_ignore_case(&n, &name) && crate::dns::java_equals_ignore_case(&cv, &value)
                    })
            });
            if !already_set {
                reply.set_cookies.push(format!("{name}={value}"));
            }
        }
    }

    let (body, content_type) = o.get("body").map(|b| response_body(b, reply.header("content-type"))).unwrap_or_default();
    reply.default_content_type = content_type;
    reply.body = body;
    // `HttpResponseActionHandler.synthesizeSchemaResponse`: without a body, `generateFromSchema` fills it with a
    // schema-valid JSON example (the request plays no part, so it is generated once here).
    let mut generated = None;
    let mut generate_failure = None;
    if o.get("body").is_none_or(Value::is_null) && let Some(schema) = o.get("generateFromSchema").and_then(Value::as_str) {
        match crate::openapi_examples::synthesize_response(schema).map(|g| g.filter(|g| !g.trim().is_empty())) {
            Ok(Some(text)) => {
                reply.body = Bytes::from(text.clone());
                reply.default_content_type = Some("application/json".into());
                generated = Some(text);
            }
            Ok(None) => {}
            // The cause's message: Jackson's, without its class, where the input's shape has recorded wording.
            Err(message) => {
                generate_failure = Some(match crate::jnode::syntax_failure(schema) {
                    Some(named) => named.split_once(": ").map_or_else(|| named.clone(), |(_, m)| m.to_string()),
                    None => message,
                });
            }
        }
    }

    if let Some(options) = o.get("connectionOptions") {
        let flag = |k: &str| options.get(k).and_then(Value::as_bool);
        if flag("suppressContentLengthHeader") == Some(true) {
            reply.suppress_content_length = true;
        }
        reply.content_length_override = options.get("contentLengthHeaderOverride").and_then(Value::as_u64);
        reply.suppress_connection_header = flag("suppressConnectionHeader") == Some(true);
        reply.keep_alive_override = flag("keepAliveOverride");
        reply.close_socket = flag("closeSocket");
        reply.close_delay = options.get("closeSocketDelay").and_then(delay).map(|d| d.fixed);
        reply.chunk_delay = options.get("chunkDelay").and_then(delay).map(Box::new);
        reply.chunk_size = options.get("chunkSize").and_then(Value::as_u64).filter(|n| *n > 0).map(|n| n as usize);
    }
    let file = o
        .get("body")
        .and_then(Value::as_object)
        .filter(|b| canonical::response_body_type(b).is_some_and(|(kind, _)| kind == "FILE"))
        .map(FileBody::compile);
    Respond { reply, delay: o.get("delay").and_then(delay), file, generated, generate_failure }
}

/// `BodyDecoderEncoder.bodyToBytes`: a string-valued body is encoded in its own media type's charset, else in the
/// charset of the response's explicit `Content-Type` header, else UTF-8 without one (or a JSON / XML one) and
/// ISO-8859-1 under any other. A charset Java does not know counts as none.
fn string_body_charset(body_content_type: Option<&str>, content_type_header: Option<&str>) -> &'static str {
    let known = |ct: Option<&str>| crate::media_type::MediaType::parse(ct).charset().and_then(crate::media_type::canonical_charset);
    if let Some(charset) = known(body_content_type).or_else(|| known(content_type_header)) {
        return charset;
    }
    match content_type_header.filter(|h| !h.trim().is_empty()) {
        None => "utf-8",
        Some(h) => {
            let header = crate::media_type::MediaType::parse(Some(h));
            if header.is_json() || header.is_xml() { "utf-8" } else { "iso-8859-1" }
        }
    }
}

/// Bytes and default `Content-Type` of a response body (`MockServerHttpResponseToFullHttpResponse`), given the
/// response's first explicit `Content-Type` header.
pub fn response_body(v: &Value, content_type_header: Option<&str>) -> (Bytes, Option<String>) {
    let encode = |text: &str, body_content_type: Option<&str>| {
        Bytes::from(crate::media_type::encode(text, Some(string_body_charset(body_content_type, content_type_header))))
    };
    match v {
        Value::String(s) => (encode(s.as_str(), None), None),
        // A JSON value (not a string) is read into a Jackson tree, so its numbers print as Jackson prints them.
        Value::Array(_) => (Bytes::from(json::pretty(&crate::model::jackson_echo_tree(v))), Some("application/json; charset=utf-8".into())),
        Value::Object(o) => {
            // The body as `BodyWithContentTypeDTODeserializer` reads it: the type and payload its key-order scan
            // settles on; no type makes the whole object a JSON body.
            let Some((kind, payload)) = canonical::response_body_type(o) else {
                return (Bytes::from(json::pretty(&crate::model::jackson_echo_tree(v))), Some("application/json; charset=utf-8".into()));
            };
            // The body's media type: `contentType` (as `MediaType.parse(…).toString()`), else the type's default
            // content type with the `charset` field's charset.
            let charset = canonical::field(o, "charset").and_then(Value::as_str).and_then(crate::media_type::canonical_charset);
            let content_type = canonical::field(o, "contentType")
                .and_then(Value::as_str)
                .map(crate::media_type::normalise)
                .filter(|ct| !ct.is_empty())
                .or_else(|| match (kind, charset) {
                    ("JSON", Some(c)) => Some(format!("application/json; charset={c}")),
                    ("STRING", Some(c)) => Some(format!("text/plain; charset={c}")),
                    ("XML", Some(c)) => Some(format!("application/xml; charset={c}")),
                    _ => None,
                });
            // `String.valueOf` of the payload, a map written as JSON.
            let text = match payload {
                Some(Value::String(s)) => s.clone(),
                Some(map @ Value::Object(_)) => json::pretty(&crate::model::jackson_echo_tree(map)),
                Some(other) => other.to_string(),
                None => String::new(),
            };
            match kind {
                "JSON" => {
                    let body = match payload {
                        Some(Value::String(s)) => s.clone(),
                        Some(other) => json::pretty(&crate::model::jackson_echo_tree(other)),
                        None => String::new(),
                    };
                    let content_type = content_type.unwrap_or_else(|| "application/json; charset=utf-8".into());
                    (encode(body.as_str(), Some(content_type.as_str())), Some(content_type))
                }
                "STRING" => (encode(text.as_str(), content_type.as_deref()), content_type),
                "XML" => {
                    let content_type = content_type.unwrap_or_else(|| "application/xml; charset=utf-8".into());
                    (encode(text.as_str(), Some(content_type.as_str())), Some(content_type))
                }
                "BINARY" => {
                    let base64 = canonical::field(o, "base64Bytes").and_then(Value::as_str).unwrap_or_default();
                    (Bytes::from(base64::engine::general_purpose::STANDARD.decode(base64).unwrap_or_default()), content_type)
                }
                // Served from the file by `FileBody`.
                "FILE" => (Bytes::new(), content_type),
                // The deserializer builds no other type (PARAMETERS, REGEX, JSON_SCHEMA, …): `JsonBody.json("{ }")`.
                _ => (Bytes::from_static(b"{ }"), Some("application/json; charset=utf-8".into())),
            }
        }
        other => (Bytes::from(other.to_string()), None),
    }
}
