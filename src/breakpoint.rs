//! Breakpoints (`BreakpointMatcherRegistry`, `BreakpointCallbackDispatcher`): a client registers a request matcher
//! for some phases; a matching exchange is held and sent to the client over the callback WebSocket, which continues
//! it, modifies the request or response, or aborts with a response of its own.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::mpsc::Receiver;

use parking_lot::Mutex;
use serde_json::{Map, Value, json};

use crate::callback;
use crate::matcher::{Mode, RequestMatcher};
use crate::recorded::{Level, LogEntry};
use crate::reply::Reply;
use crate::request::HttpRequest;
use crate::state::State;

/// `BreakpointPhase`, in declaration order (the order `EnumSet` lists them).
pub const PHASES: [&str; 4] = ["REQUEST", "RESPONSE", "RESPONSE_STREAM", "INBOUND_STREAM"];

const BREAKPOINT_ID_HEADER: &str = "X-MockServer-BreakpointId";
const REQUEST_TIMESTAMP_HEADER: &str = "X-MockServer-RequestTimestamp";

/// `BreakpointMatcher`.
pub struct Matcher {
    pub id: String,
    definition: Value,
    matcher: RequestMatcher,
    phases: Vec<&'static str>,
    pub client_id: String,
    skip_count: Option<i64>,
    max_hits: Option<i64>,
    status_min: Option<i64>,
    status_max: Option<i64>,
    /// `responseBodyContains` and its `Pattern.compile`, searched with `find()`.
    body_contains: Option<(String, std::sync::Arc<crate::matcher::java_pattern::JavaRegex>)>,
    hits: AtomicI64,
    pauses: AtomicI64,
}

impl Matcher {
    fn has_response_condition(&self) -> bool {
        self.status_min.is_some() || self.status_max.is_some() || self.body_contains.is_some()
    }

    /// `responseConditionMatches`: the status range and a body regex found anywhere in the body.
    fn response_condition_matches(&self, status: u32, body: &str) -> bool {
        let status = status as i64;
        self.status_min.is_none_or(|m| status >= m) && self.status_max.is_none_or(|m| status <= m) && self.body_contains.as_ref().is_none_or(|(_, re)| re.find(body))
    }

    /// `shouldPause`: past the skipped hits, and within `maxHits` pauses.
    fn should_pause(&self) -> bool {
        let hit = self.hits.fetch_add(1, Ordering::SeqCst) + 1;
        if self.skip_count.is_some_and(|s| hit <= s) {
            return false;
        }
        let pauses = self.pauses.fetch_add(1, Ordering::SeqCst) + 1;
        self.max_hits.is_none_or(|m| pauses <= m)
    }

    fn exhausted(&self) -> bool {
        self.max_hits.is_some_and(|m| self.pauses.load(Ordering::SeqCst) >= m)
    }

    fn json(&self) -> Value {
        let mut o = Map::new();
        o.insert("id".into(), json!(self.id));
        o.insert("httpRequest".into(), crate::canonical::request_definition(&self.definition));
        self.options(&mut o);
        Value::Object(o)
    }

    fn options(&self, o: &mut Map<String, Value>) {
        o.insert("phases".into(), json!(self.phases));
        o.insert("clientId".into(), json!(self.client_id));
        let mut put = |k: &str, v: Option<i64>| {
            if let Some(v) = v {
                o.insert(k.into(), json!(v));
            }
        };
        put("skipCount", self.skip_count);
        put("maxHits", self.max_hits);
        put("responseStatusCodeMin", self.status_min);
        put("responseStatusCodeMax", self.status_max);
        if let Some((text, _)) = &self.body_contains {
            o.insert("responseBodyContains".into(), json!(text));
        }
    }
}

/// The server's breakpoint matchers, in registration order.
#[derive(Default)]
pub struct Breakpoints {
    matchers: Mutex<Vec<Arc<Matcher>>>,
}

impl Breakpoints {
    /// `findMatch` / `findResponseMatch`: the first matcher for `phase` matching the request (and response), if it
    /// pauses this time; an exhausted matcher leaves the registry.
    pub fn find(&self, request: &HttpRequest, phase: &str, response: Option<(u32, &str)>) -> Option<Arc<Matcher>> {
        let mut matchers = self.matchers.lock();
        if matchers.is_empty() {
            return None;
        }
        let index = matchers.iter().position(|m| {
            m.phases.contains(&phase)
                && m.matcher.matches(request, Mode::ControlPlane)
                && !(response.is_some() && m.has_response_condition() && !response.is_some_and(|(s, b)| m.response_condition_matches(s, b)))
        })?;
        let entry = matchers[index].clone();
        let pause = entry.should_pause();
        if entry.exhausted() {
            matchers.remove(index);
        }
        pause.then_some(entry)
    }

    pub fn remove_client(&self, client_id: &str) {
        self.matchers.lock().retain(|m| m.client_id != client_id);
    }

    pub fn clear(&self) -> usize {
        let mut matchers = self.matchers.lock();
        let count = matchers.len();
        matchers.clear();
        count
    }

    pub fn is_empty(&self) -> bool {
        self.matchers.lock().is_empty()
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Control plane
// ---------------------------------------------------------------------------------------------------------------

fn error(status: u32, message: &str) -> Reply {
    Reply::api_body(status, "application/json", crate::json::compact(&json!({"error": message})))
}

/// `PUT /mockserver/breakpoint/matcher[s|/remove|/clear]`, `GET /mockserver/breakpoint/matchers`.
pub fn route(state: &State, request: &HttpRequest, op: &str) -> Option<Reply> {
    Some(match (request.method.as_str(), op) {
        ("PUT", "/breakpoint/matcher") => register(state, request),
        ("PUT" | "GET", "/breakpoint/matchers") => {
            let matchers: Vec<Value> = state.breakpoints.matchers.lock().iter().map(|m| m.json()).collect();
            Reply::api_body(200, "application/json", crate::json::pretty(&json!({ "matchers": matchers })))
        }
        ("PUT", "/breakpoint/matcher/remove") => remove(state, request),
        ("PUT", "/breakpoint/matcher/clear") => {
            let count = state.breakpoints.clear();
            Reply::api_body(200, "application/json", crate::json::pretty(&json!({"status": "cleared", "count": count})))
        }
        _ => return None,
    })
}

/// The body as a JSON tree, or the Jackson error's message (the breakpoint error body's, with a 400).
fn read_body(request: &HttpRequest) -> Result<Value, String> {
    let body = request.body_json_or_xml_str();
    let lenient = jackson::json::ReadFeatures { allow_unquoted_field_names: true, allow_single_quotes: true, allow_non_numeric_numbers: true, ..Default::default() };
    if let Err(e) = jackson::json::read_tree(&body, lenient) {
        return Err(e.message);
    }
    crate::json::parse_lenient(body.as_bytes()).map_err(|e| e.to_string())
}

/// `JsonNode.isIntegralNumber() && canConvertToInt()`.
fn int_value(v: &Value) -> Option<i64> {
    v.as_i64().filter(|n| i32::try_from(*n).is_ok())
}

fn register(state: &State, request: &HttpRequest) -> Reply {
    if request.body_json_or_xml_str().trim().is_empty() {
        return error(400, "request body is required with 'httpRequest' and 'phases' fields");
    }
    let node = match read_body(request) {
        Ok(v) => v,
        Err(message) => return error(400, &message),
    };
    let definition = match node.get("httpRequest") {
        Some(Value::Object(o)) if !o.is_empty() => Value::Object(o.clone()),
        Some(v) if !v.is_null() && !v.is_object() => v.clone(),
        _ => return error(400, "'httpRequest' field is required and must not be empty"),
    };
    let Some(phase_names) = node.get("phases").and_then(Value::as_array).filter(|p| !p.is_empty()) else {
        return error(400, "'phases' field is required and must be a non-empty array");
    };
    let mut phases: Vec<&'static str> = Vec::new();
    for element in phase_names {
        let name = match element {
            Value::String(s) => s.clone(),
            Value::Null => String::new(),
            Value::Object(_) | Value::Array(_) => String::new(),
            other => other.to_string(),
        };
        if name.trim().is_empty() {
            return error(400, "each element in 'phases' must be a non-empty string");
        }
        match PHASES.iter().find(|p| **p == name) {
            Some(p) => {
                if !phases.contains(p) {
                    phases.push(p);
                }
            }
            None => return error(400, &format!("unknown phase '{}'; valid phases are: [{}]", name, PHASES.join(", "))),
        }
    }
    phases.sort_by_key(|p| PHASES.iter().position(|q| q == p));
    if let Err(report) = crate::schema::validate_request_definition(&definition) {
        return error(400, &crate::schema::incorrect_request_matcher(&definition.to_string(), &report));
    }
    let Some(client_id) = node.get("clientId").and_then(Value::as_str).filter(|c| !c.trim().is_empty()) else {
        return error(400, "'clientId' field is required (must be the callback WebSocket client id)");
    };
    let present = |k: &str| node.get(k).filter(|v| !v.is_null());
    let skip_count = match present("skipCount") {
        Some(v) => match int_value(v).filter(|n| *n >= 0) {
            Some(n) => (n > 0).then_some(n),
            None => return error(400, "'skipCount' must be a non-negative integer"),
        },
        None => None,
    };
    let max_hits = match present("maxHits") {
        Some(v) => match int_value(v).filter(|n| *n >= 1) {
            Some(n) => Some(n),
            None => return error(400, "'maxHits' must be a positive integer"),
        },
        None => None,
    };
    let bound = |k: &str| match present(k) {
        Some(v) => int_value(v).map(Some).ok_or_else(|| format!("'{k}' must be an integer")),
        None => Ok(None),
    };
    let status_min = match bound("responseStatusCodeMin") {
        Ok(v) => v,
        Err(message) => return error(400, &message),
    };
    let status_max = match bound("responseStatusCodeMax") {
        Ok(v) => v,
        Err(message) => return error(400, &message),
    };
    if let (Some(min), Some(max)) = (status_min, status_max) && min > max {
        return error(400, "'responseStatusCodeMin' must not be greater than 'responseStatusCodeMax'");
    }
    let body_contains = match present("responseBodyContains") {
        Some(Value::String(s)) if s.is_empty() => None,
        Some(Value::String(s)) => match crate::matcher::java_pattern::compile(s) {
            Ok(re) => Some((s.clone(), re)),
            Err(_) => return error(400, "'responseBodyContains' is not a valid regular expression"),
        },
        Some(_) => return error(400, "'responseBodyContains' must be a string"),
        None => None,
    };
    let entry = Matcher {
        id: uuid::Uuid::new_v4().to_string(),
        // SECURITY: carries the server's remote-`$ref` policy into the compile.
        matcher: crate::matcher::string::with_remote_refs_policy(state.json_schema_allow_remote_refs(), || RequestMatcher::compile(&definition)),
        definition,
        phases,
        client_id: client_id.to_string(),
        skip_count,
        max_hits,
        status_min,
        status_max,
        body_contains,
        hits: AtomicI64::new(0),
        pauses: AtomicI64::new(0),
    };
    let mut result = Map::new();
    result.insert("id".into(), json!(entry.id));
    entry.options(&mut result);
    state.breakpoints.matchers.lock().push(Arc::new(entry));
    Reply::api_body(201, "application/json", crate::json::pretty(&Value::Object(result)))
}

fn remove(state: &State, request: &HttpRequest) -> Reply {
    if request.body_json_or_xml_str().trim().is_empty() {
        return error(400, "request body is required with an 'id' field");
    }
    let node = match read_body(request) {
        Ok(v) => v,
        Err(message) => return error(400, &message),
    };
    let id = match node.get("id") {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Null) | None => String::new(),
        Some(other) if other.is_object() || other.is_array() => String::new(),
        Some(other) => other.to_string(),
    };
    if id.trim().is_empty() {
        return error(400, "'id' field is required");
    }
    let mut matchers = state.breakpoints.matchers.lock();
    let before = matchers.len();
    matchers.retain(|m| m.id != id);
    if matchers.len() == before {
        return Reply::api_body(404, "application/json", crate::json::pretty(&json!({"error": "breakpoint matcher not found", "id": id})));
    }
    Reply::api_body(200, "application/json", crate::json::pretty(&json!({"status": "removed", "id": id})))
}

// ---------------------------------------------------------------------------------------------------------------
// Holds
// ---------------------------------------------------------------------------------------------------------------

/// `BreakpointDecision`.
pub enum Decision {
    Continue,
    /// The request to go on with.
    ModifyRequest(Value),
    /// The response to write instead.
    ModifyResponse(Value),
    /// The response to answer with, the request going no further.
    Abort(Value),
}

fn timeout(state: &State) -> Duration {
    Duration::from_millis(state.config.property("breakpointTimeoutMillis").and_then(|v| v.trim().parse().ok()).unwrap_or(30_000))
}

fn max_held(state: &State) -> usize {
    state.config.property("breakpointMaxHeld").and_then(|v| v.trim().parse().ok()).unwrap_or(50)
}

fn hold_headers(matcher: &Matcher) -> Vec<(&'static str, String)> {
    let received = chrono::Utc::now().timestamp_millis();
    vec![(BREAKPOINT_ID_HEADER, matcher.id.clone()), (REQUEST_TIMESTAMP_HEADER, received.to_string())]
}

/// Removes the headers the hold added from a client's answer.
fn cleaned(mut value: Value) -> Value {
    let drop = |k: &str| [callback::CORRELATION_HEADER, BREAKPOINT_ID_HEADER, REQUEST_TIMESTAMP_HEADER].iter().any(|h| h.eq_ignore_ascii_case(k));
    match value.get_mut("headers") {
        Some(Value::Object(o)) => o.retain(|k, _| !drop(k)),
        Some(Value::Array(entries)) => entries.retain(|e| !e.get("name").and_then(Value::as_str).is_some_and(drop)),
        _ => {}
    }
    value
}

/// A REQUEST-phase hold (`attemptRequestBreakpoint`): `None` when no breakpoint pauses the request or it could not be
/// held (so the request goes on unheld).
pub async fn hold_request(state: &State, request: &HttpRequest) -> Option<Decision> {
    if state.breakpoints.is_empty() {
        return None;
    }
    let matcher = state.breakpoints.find(request, "REQUEST", None)?;
    Some(match dispatch(state, &matcher, request, None, "request").await? {
        Some(callback::Reply::Request(v)) => Decision::ModifyRequest(cleaned(v)),
        Some(callback::Reply::Message(v)) => Decision::Abort(cleaned(v)),
        Some(callback::Reply::Error(_)) | None => Decision::Continue,
    })
}

/// See [`hold_response`].
pub type Continued = Arc<std::sync::OnceLock<Value>>;

/// A RESPONSE-phase hold (`attemptResponseBreakpoint`) of `response` (the logged model) for `request`. `continued`,
/// once set, is that same response as the handler goes on to write it (with the hold's `timing`): the paused entry
/// shows it from then on, as upstream's entry holds the `HttpResponse` object `attachMockServedTiming` changes.
pub async fn hold_response(state: &State, request: &HttpRequest, response: &Value, continued: Option<Continued>) -> Option<Decision> {
    if state.breakpoints.is_empty() {
        return None;
    }
    let status = response.get("statusCode").and_then(Value::as_u64).unwrap_or(200) as u32;
    let body = crate::llm::report::logged_body(response);
    let matcher = state.breakpoints.find(request, "RESPONSE", Some((status, &body)))?;
    Some(match dispatch(state, &matcher, request, Some((response.clone(), continued)), "response to request").await? {
        Some(callback::Reply::Message(v)) => Decision::ModifyResponse(cleaned(v)),
        _ => Decision::Continue,
    })
}

/// `BreakpointCallbackDispatcher.dispatchRequest` / `dispatchResponse` (`what`: "request" or "response to request"
/// in their lines): `None` when the hold did not happen (the cap, a client not connected), `Some(None)` when it
/// ended unanswered (a timeout, a lost client), else the client's answer.
async fn dispatch(state: &State, matcher: &Matcher, request: &HttpRequest, response: Option<(Value, Option<Continued>)>, what: &str) -> Option<Option<callback::Reply>> {
    let event = |level: Level, format: String, arguments: Vec<crate::recorded::Arg>| {
        let entry = LogEntry::at(level, format).request(request).args(arguments);
        if level == Level::Warn { crate::log::warn_event_about(state, entry, request) } else { crate::log::info_event_about(state, entry, request) }
    };
    let shown = || crate::recorded::Arg::from(crate::recorded::logged(request));
    let (held, max) = (state.callbacks.held_count(), max_held(state));
    if held >= max {
        event(Level::Info, format!("breakpoint WS dispatch cap reached ({{}}/{{}}), skipping for {what}:{{}}"), vec![json!(held).into(), json!(max).into(), shown()]);
        return None;
    }
    let correlation = uuid::Uuid::new_v4().to_string();
    let headers = hold_headers(matcher);
    // the held request as the WebSocket serialiser writes it, an object callback's request too: a typed body (a JSON
    // body as `{contentType, type, json}`), not the log's bare one
    let sent = crate::recorded::ordered(request);
    // `HttpActionHandler`: once the dispatcher's future exists, the hold is logged as paused (oracle).
    let paused = || match &response {
        None => crate::log::info_event_about(state, LogEntry::at(Level::Info, "request paused at breakpoint, awaiting resolution for:{}").request(request).args([shown()]), request),
        Some((response, continued)) => {
            let mut entry = LogEntry::at(Level::Info, "upstream response paused at breakpoint, awaiting resolution for request:{}response:{}")
                .request(request)
                .response(response.clone())
                .args([shown(), crate::recorded::Arg::from(response.clone())]);
            if let Some(continued) = continued.clone() {
                entry = entry.live_arguments_unmemoised(move || continued.get().map(|r| vec![(1, crate::recorded::Arg::from(r.clone()))]).unwrap_or_default());
            }
            crate::log::info_event_about(state, entry, request)
        }
    };
    match state.callbacks.hold(&matcher.client_id, correlation.clone(), sent, &headers, response.as_ref().map(|(r, _)| r.clone()), timeout(state), paused).await {
        Ok(reply) => Some(Some(reply)),
        Err(callback::Unanswered::TimedOut) => {
            let millis = timeout(state).as_millis() as u64;
            event(Level::Info, format!("breakpoint WS dispatch auto-continued (timeout {{}}ms) for {what}:{{}}"), vec![json!(millis).into(), shown()]);
            Some(None)
        }
        Err(callback::Unanswered::NotConnected) => {
            // `WebSocketClientRegistry.sendClientMessage`: about the request as sent (the clone with the hold's headers).
            let mut clone = request.clone();
            clone.log_correlation_id.clear();
            clone.headers.push((callback::CORRELATION_HEADER.into(), vec![correlation]));
            clone.headers.extend(headers.iter().map(|(name, value)| ((*name).to_string(), vec![value.clone()])));
            let shown_clone = crate::recorded::logged(&clone);
            // The registry map (client id to channel), which holds no one the message could go to: its `toString` in
            // the message (`{}` when empty; the channels' own texts are not reproduced), its JSON as the argument.
            let ids = state.callbacks.client_ids();
            let text = format!("{{{}}}", ids.iter().map(|id| format!("{id}=")).collect::<Vec<_>>().join(", "));
            let registry: Map<String, Value> = ids.into_iter().map(|id| (id, json!({}))).collect();
            let format = format!("client {} not found for request{{}}client registry only contains{{}}", matcher.client_id);
            let entry = LogEntry::at(Level::Warn, format).request_json(shown_clone.clone()).args([shown_clone.into(), crate::recorded::Arg::with_text(Value::Object(registry), text)]);
            crate::log::warn_event(state, entry);
            event(Level::Warn, format!("breakpoint WS dispatch failed: client {{}} not connected for {what}:{{}}"), vec![(&matcher.client_id).into(), shown()]);
            None
        }
        Err(callback::Unanswered::Released) => Some(None),
    }
}

/// `StreamFrameDecision`.
enum FrameDecision {
    Continue,
    /// Replace the frame's bytes.
    Modify(Vec<u8>),
    Drop,
    /// The frame, then these bytes.
    Inject(Vec<u8>),
    /// End the stream.
    Close,
}

/// The stream-frame phases (`BreakpointPhase.RESPONSE_STREAM`, `INBOUND_STREAM`); each holds one direction.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum StreamPhase {
    /// What the server sends (`OUTBOUND`).
    Response,
    /// What the client sends (`INBOUND`).
    Inbound,
}

impl StreamPhase {
    fn name(self) -> &'static str {
        match self {
            StreamPhase::Response => "RESPONSE_STREAM",
            StreamPhase::Inbound => "INBOUND_STREAM",
        }
    }

    fn direction(self) -> &'static str {
        match self {
            StreamPhase::Response => "OUTBOUND",
            StreamPhase::Inbound => "INBOUND",
        }
    }
}

/// Upstream's `request.getLogCorrelationId()`, the prefix of a held stream's id (a fresh uuid when the request has
/// none, as upstream falls back to).
pub fn correlation(request: &HttpRequest) -> String {
    match request.log_correlation_id.as_str() {
        "" => uuid::Uuid::new_v4().to_string(),
        id => id.to_string(),
    }
}

/// A held stream: the matcher that holds its frames, what each held frame reports, and the frame counter
/// (`nextSequenceNumber`).
pub struct HeldStream {
    state: Arc<State>,
    matcher: Arc<Matcher>,
    pub id: String,
    phase: StreamPhase,
    /// `requestMethod` / `requestPath` of every frame (for gRPC bidi, `GRPC-INBOUND` and the method's full name).
    method: String,
    path: String,
    sequence: AtomicI64,
    /// Whether its dispatch lines carry no port: frames relayed off the server's event-loop threads (the default).
    portless: bool,
    /// Opened once the next frame's dispatch has gone out: see [`HeldStream::dispatched`].
    gate: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    /// Every frame's `requestTimestamp`, when the holder passes one (`HttpSseResponseActionHandler`'s
    /// `request.getReceivedTimestamp()`; the other holders pass `null`, which the DTO leaves out).
    request_timestamp: Option<i64>,
}

/// The breakpoint holding the frames of the stream `request` opens in `phase`, if any; the stream is named `id`.
pub fn stream(state: &Arc<State>, request: &HttpRequest, phase: StreamPhase, id: String, method: &str, path: &str) -> Option<HeldStream> {
    let matcher = state.breakpoints.find(request, phase.name(), None)?;
    Some(HeldStream { state: state.clone(), matcher, id, phase, method: method.to_string(), path: path.to_string(), sequence: AtomicI64::new(0), portless: true, gate: Mutex::new(None), request_timestamp: None })
}

impl HeldStream {
    /// A stream whose frames are dispatched on the connection's own event loop (an `httpSseResponse`'s events), so
    /// its dispatch lines carry the port.
    pub fn on_event_loop(mut self) -> HeldStream {
        self.portless = false;
        self
    }

    /// Frames that carry the request's received time as their `requestTimestamp` (epoch milliseconds).
    pub fn received_at(mut self, millis: i64) -> HeldStream {
        self.request_timestamp = Some(millis);
        self
    }

    /// Resolves once the next frame's dispatch has gone out: the paused-frame message sent to the client, or the lines
    /// for a client that is not connected (or a full cap) logged; also on [`HeldStream::open_gate`] or when the stream
    /// is dropped. Upstream dispatches an SSE stream's first undelayed event on the event loop right after flushing the
    /// head, so its lines precede anything a reader of that head logs (a streaming forward's drift pass);
    /// writing the head only once this resolves keeps that order here.
    pub fn dispatched(&self) -> tokio::sync::oneshot::Receiver<()> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        *self.gate.lock() = Some(tx);
        rx
    }

    /// Releases a [`HeldStream::dispatched`] wait (e.g. before a first frame that is due only after a delay).
    pub fn open_gate(&self) {
        if let Some(tx) = self.gate.lock().take() {
            let _ = tx.send(());
        }
    }

    /// A stream-frame dispatch line (`StreamFrameCallbackDispatcher`, `WebSocketClientRegistry`): a level-typed entry
    /// with its arguments.
    fn event(&self, level: Level, format: String, arguments: Vec<Value>) {
        let mut entry = LogEntry::at(level, format).args(arguments);
        if self.portless {
            entry = entry.without_port();
        }
        if level == Level::Warn { crate::log::warn_event(&self.state, entry) } else { crate::log::info_event(&self.state, entry) }
    }

    /// `dispatchFrame`: holds one frame until its client decides (a timeout or a lost client continues). Upstream's
    /// INBOUND_STREAM callers pass no logger, so only RESPONSE_STREAM holds log why a frame went on unheld; the
    /// registry's own line for a client that is not connected is written for both.
    async fn hold(&self, bytes: &[u8]) -> FrameDecision {
        use base64::Engine;
        let state = &*self.state;
        let seq = self.sequence.fetch_add(1, Ordering::SeqCst);
        let logged = self.phase == StreamPhase::Response;
        let (held, max) = (state.callbacks.held_count(), max_held(state));
        if held >= max {
            if logged {
                self.event(Level::Info, "stream frame WS dispatch cap reached ({}/{}), skipping for stream={} seq={}".into(), vec![json!(held), json!(max), json!(self.id), json!(seq)]);
            }
            self.open_gate();
            return FrameDecision::Continue;
        }
        let mut frame = Map::new();
        frame.insert("streamId".into(), json!(self.id));
        frame.insert("sequenceNumber".into(), json!(seq));
        frame.insert("direction".into(), json!(self.phase.direction()));
        frame.insert("phase".into(), json!(self.phase.name()));
        frame.insert("body".into(), json!(base64::engine::general_purpose::STANDARD.encode(bytes)));
        frame.insert("requestMethod".into(), json!(self.method));
        frame.insert("requestPath".into(), json!(self.path));
        frame.insert("breakpointId".into(), json!(self.matcher.id));
        if let Some(millis) = self.request_timestamp {
            frame.insert("requestTimestamp".into(), json!(millis));
        }
        let correlation = uuid::Uuid::new_v4().to_string();
        let client = &self.matcher.client_id;
        let decision = match state.callbacks.hold_frame(client, correlation.clone(), frame, timeout(state), || self.open_gate()).await {
            Ok(decision) => decision,
            Err(callback::Unanswered::TimedOut) if logged => {
                let millis = timeout(state).as_millis() as u64;
                self.event(Level::Info, "stream frame WS dispatch auto-continued (timeout {}ms) for stream={} seq={}".into(), vec![json!(millis), json!(self.id), json!(seq)]);
                return FrameDecision::Continue;
            }
            Err(callback::Unanswered::NotConnected) => {
                // `WebSocketClientRegistry.sendStreamFrameMessage`.
                self.event(Level::Warn, format!("client {client} not found for stream frame message{{}}"), vec![json!(correlation)]);
                if logged {
                    self.event(Level::Warn, "stream frame WS dispatch failed: client {} not connected for stream={} seq={}".into(), vec![json!(client), json!(self.id), json!(seq)]);
                }
                self.open_gate();
                return FrameDecision::Continue;
            }
            Err(_) => return FrameDecision::Continue,
        };
        let body = || decision.get("body").and_then(Value::as_str).and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok());
        match decision.get("action").and_then(Value::as_str) {
            Some("MODIFY") => body().map_or(FrameDecision::Continue, FrameDecision::Modify),
            Some("DROP") => FrameDecision::Drop,
            Some("INJECT") => body().map_or(FrameDecision::Continue, FrameDecision::Inject),
            Some("CLOSE") => FrameDecision::Close,
            _ => FrameDecision::Continue,
        }
    }
}

/// A frame through its stream's breakpoint (`held`, if any): the frames to go on with, or `None` when the client
/// closed the stream. CONTINUE keeps `frame`, MODIFY replaces it with `rebuild(frame, bytes)` (a frame of the same
/// kind around the client's bytes), DROP leaves nothing, INJECT keeps `frame` and adds the rebuilt injected one.
/// `payload` gives the bytes the client sees.
pub async fn pass<T, P: AsRef<[u8]>>(held: Option<&HeldStream>, frame: T, payload: impl FnOnce(&T) -> P, rebuild: impl Fn(&T, Vec<u8>) -> T) -> Option<Vec<T>> {
    let Some(held) = held else { return Some(vec![frame]) };
    Some(match held.hold(payload(&frame).as_ref()).await {
        FrameDecision::Continue => vec![frame],
        FrameDecision::Modify(bytes) => vec![rebuild(&frame, bytes)],
        FrameDecision::Drop => Vec::new(),
        FrameDecision::Inject(bytes) => {
            let injected = rebuild(&frame, bytes);
            vec![frame, injected]
        }
        FrameDecision::Close => return None,
    })
}

/// [`pass`] for frames that are plain bytes (HTTP chunks, gRPC messages).
pub async fn pass_bytes(held: Option<&HeldStream>, frame: Bytes) -> Option<Vec<Bytes>> {
    pass(held, frame, Bytes::clone, |_, bytes| Bytes::from(bytes)).await
}

/// `NettyResponseWriter.writeStreamingResponse` under a RESPONSE_STREAM breakpoint: each chunk of a relayed (streaming
/// proxy) body is held before it is written, the next one taken only once it is decided; INJECT writes the injected
/// bytes as a chunk of their own, and CLOSE ends the body there (the returned flag is set: HTTP/1.1 closes the
/// connection after the last chunk). Once the client is gone, or after CLOSE, the rest is drained unheld, so the relay
/// still captures and logs the whole upstream body as upstream's does.
pub fn hold_chunks(held: HeldStream, mut chunks: Receiver<Bytes>) -> (Receiver<Bytes>, Arc<AtomicBool>) {
    let (tx, rx) = tokio::sync::mpsc::channel(16);
    let cut = Arc::new(AtomicBool::new(false));
    let flag = cut.clone();
    tokio::spawn(async move {
        let mut tx = Some(tx);
        while let Some(chunk) = chunks.recv().await {
            let Some(out) = tx.as_ref().filter(|t| !t.is_closed()) else { continue };
            match pass_bytes(Some(&held), chunk).await {
                Some(frames) => {
                    for frame in frames {
                        let _ = out.send(frame).await;
                    }
                }
                None => {
                    flag.store(true, Ordering::SeqCst);
                    tx = None;
                }
            }
        }
    });
    (rx, cut)
}

