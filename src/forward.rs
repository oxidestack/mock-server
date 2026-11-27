//! `httpForward` and `httpOverrideForwardedRequest` (§2.5), `httpForwardWithFallback` and
//! `httpForwardValidateAction`, with MockServer's logging of forwarded exchanges and the recorded expectations they
//! produce.

use std::time::Instant;

use serde_json::{Map, Value, json};

use crate::client::{self, Outbound, Upstream};
use crate::recorded::{self, BodyForm};
use crate::reply::Reply;
use crate::request::{self, HttpRequest, MultiMap};
use crate::state::State;
use crate::templates::{self, PathMatch, Template};
use crate::{action, canonical};

#[derive(Debug)]
pub enum Forward {
    To { target: Target, delay: Option<action::Delay> },
    Override {
        request_override: Option<Value>,
        request_modifier: Option<Value>,
        response_override: Option<Value>,
        response_modifier: Option<Value>,
        /// `responseTemplate`: renders the response from the request and the upstream's (overridden) response.
        response_template: Option<Template>,
        delay: Option<action::Delay>,
    },
    /// `httpForwardTemplate`: the request to send is rendered from the received one.
    Template { template: Template, response_override: Option<Value>, response_modifier: Option<Value>, delay: Option<action::Delay> },
    /// `httpForwardObjectCallback`: a WebSocket client returns the request to send and, with `responseCallback`,
    /// the response to return for it (`HttpForwardObjectCallbackActionHandler`).
    Callback { client_id: String, response_callback: bool, delay: Option<action::Delay> },
    /// `httpForwardClassCallback`: a callback class returns the request to send and, when it implements
    /// `ExpectationForwardAndResponseCallback`, the response to return (`HttpForwardClassCallbackActionHandler`).
    ClassCallback { class: String, delay: Option<action::Delay> },
    /// `httpForwardWithFallback` (`HttpForwardWithFallbackActionHandler`): forwarded as `httpForward` is, but an
    /// upstream answering one of `status_codes` (5xx when empty) or failing (when `on_timeout`) is answered with
    /// `fallback` (its input JSON) instead.
    WithFallback { target: Target, fallback: Value, status_codes: Vec<i64>, on_timeout: bool, delay: Option<action::Delay> },
    /// `httpForwardValidateAction` (`HttpForwardValidateActionHandler`): the request is checked against the OpenAPI
    /// spec before it goes to `host:port`, and the upstream's response after; `strict` answers a failure with 400
    /// (request) or 502 (response) instead of only logging it.
    Validate { spec: String, target: Target, validate_request: bool, validate_response: bool, strict: bool, delay: Option<action::Delay> },
}

/// Where an `HttpForward` (or `httpForwardValidateAction`) sends the request: its host (none when not given), port
/// (80 by default) and scheme.
#[derive(Debug, Clone)]
pub struct Target {
    pub host: Option<String>,
    pub port: i64,
    pub secure: bool,
}

impl Target {
    fn compile(v: &Value) -> Target {
        Target {
            host: v.get("host").and_then(Value::as_str).map(str::to_string),
            port: v.get("port").and_then(Value::as_i64).unwrap_or(80),
            secure: v.get("scheme").and_then(Value::as_str) == Some("HTTPS"),
        }
    }

    /// The `Host` header naming it, as Java builds it: without a host, a null header value (written empty) on the
    /// default port, else `null:<port>`.
    fn host_header(&self) -> String {
        let default_port = (self.secure && self.port == 443) || (!self.secure && self.port == 80);
        match (self.host.as_deref(), default_port) {
            (host, true) => host.unwrap_or_default().to_string(),
            (host, false) => format!("{}:{}", host.unwrap_or("null"), self.port),
        }
    }

    /// `InetSocketAddress.createUnresolved(host, port)`: the address, or why it cannot be made.
    fn address(&self) -> Result<(&str, u16), String> {
        let host = self.host.as_deref().ok_or_else(|| "hostname can't be null".to_string())?;
        let port = u16::try_from(self.port).map_err(|_| format!("port out of range:{}", self.port))?;
        Ok((host, port))
    }
}

/// The `Host` header value for `host:port`: the port is left out when it is the scheme's default.
pub fn host_header(host: &str, port: u16, secure: bool) -> String {
    Target { host: Some(host.to_string()), port: i64::from(port), secure }.host_header()
}

/// `replaceHeader(new Header("Host", …))`: the request's `Host` header replaced by `value`, appended last.
pub fn set_host(request: &mut HttpRequest, value: String) {
    request.headers.retain(|(k, _)| !k.eq_ignore_ascii_case("host"));
    request.headers.push(("Host".into(), vec![value]));
}

#[derive(Default)]
pub struct Forwarded {
    pub reply: Reply,
    /// The request as MockServer logs it (for `httpForward`, with `Host` rewritten).
    pub logged_request: HttpRequest,
    pub logged_response: Value,
    /// The recorded expectation (`retrieve?type=RECORDED_EXPECTATIONS`) when the upstream answered: canonical,
    /// and in input form.
    pub recorded: Option<(Value, Value)>,
    /// Why the upstream gave no response (`handleExceptionDuringForwardingRequest`).
    pub error: Option<client::Error>,
    /// The upstream's body is being relayed as it arrives; `reply` is its head.
    pub streaming: Option<Streaming>,
    /// What the forwarding client measured, when the upstream answered.
    pub timing: Option<client::Timing>,
    /// The request as sent, when it is not the logged one: its JSON model and its curl command.
    pub sent: Option<(Value, String)>,
    /// The handler threw before anything was sent (`handleAnyException`): the exception's message; the reply is 404.
    pub threw: Option<String>,
    /// The upstream call went through `ForwardRetryPolicy`'s retry chain (an idempotent method, retries configured),
    /// whose failed future carries Netty's exception itself: a refused connection is reported with its class name.
    pub retried: bool,
    /// The `responseOverride`'s `FILE` body could not be read (`materialiseFileBodyResponse`): the response is the
    /// clean 500, and the caller logs the error.
    pub file_error: Option<action::FileBodyError>,
    /// The forward loop guard answered `508` in place of the upstream ([`client::Upstream::loop_detected`]).
    pub loop_detected: bool,
}

/// Sees each chunk of a streamed body as it is relayed.
pub type ChunkObserver = Box<dyn FnMut(&[u8]) + Send>;

/// A streamed upstream response: the head's parts, the chunks still to come, and what the completed exchange is
/// logged with.
pub struct Streaming {
    pub status: u32,
    pub reason: String,
    pub headers: Vec<(String, String)>,
    pub chunks: tokio::sync::mpsc::Receiver<bytes::Bytes>,
    pub response_override: Option<Value>,
    pub response_modifier: Option<Value>,
    /// What the forwarding client measured for the head (the logged `timing`).
    pub timing: client::Timing,
    /// When the forward was sent: the logged response time is the whole stream's.
    pub started: Instant,
    /// The client's `Upstream::stream_end`: the stream ended by an error (the capture is truncated), or its connection
    /// was closed for idling.
    pub end: std::sync::Arc<client::StreamEnd>,
    /// `StreamingBody.observeChunks`: sees each chunk as it is relayed (the LLM usage scanner).
    pub observer: Option<ChunkObserver>,
}

impl Streaming {
    /// `StreamingBody.observeChunks`.
    pub fn observe_chunks(&mut self, observer: impl FnMut(&[u8]) + Send + 'static) {
        self.observer = Some(Box::new(observer));
    }

    /// Relays the chunks to the returned receiver while capturing them (`StreamingBody`: at most
    /// `maxStreamingCaptureBytes`, with each chunk's arrival time until the capture is truncated); `done` gets the
    /// exchange as logged once the stream has ended (`setCapturedStreamingBody`, `attachStreamingHeaders`).
    pub fn relay(self, state: &std::sync::Arc<State>, logged_request: HttpRequest, done: impl FnOnce(Forwarded) + Send + 'static) -> tokio::sync::mpsc::Receiver<bytes::Bytes> {
        let max_capture = state.config.int_property("maxStreamingCaptureBytes", 262_144).max(0) as usize;
        let (tx, rx) = tokio::sync::mpsc::channel(64);
        let Streaming { status, reason, headers, mut chunks, response_override, response_modifier, timing, started, end, mut observer } = self;
        let state = state.clone();
        tokio::spawn(async move {
            let mut capture = Capture::new(max_capture);
            loop {
                // a client that has gone is noticed at once, not at the next chunk: a quiet upstream sends none (a
                // stream reset for a write stall, `ResponseWriteStallTimeoutIntegrationTest`)
                let chunk = tokio::select! {
                    chunk = chunks.recv() => chunk,
                    _ = tx.closed() => {
                        capture.truncated = true;
                        break;
                    }
                };
                let Some(chunk) = chunk else { break };
                capture.add(&chunk);
                if let Some(observe) = observer.as_mut() {
                    observe(&chunk);
                }
                if tx.send(chunk).await.is_err() {
                    // the client has gone: the upstream's connection is closed with its reader rather than read to the
                    // end for nobody, an endless one included (`StreamedResponseAbandonIntegrationTest`)
                    capture.truncated = true;
                    break;
                }
            }
            drop(chunks);
            drop(tx);
            if let Some(channel) = end.idle_channel() {
                // `StreamIdleTimeoutHandler`, before the closed channel ends the stream.
                if !matches!(state.log_level.as_str(), "OFF" | "ERROR") {
                    let text = format!("streaming response idle timeout - closing channel {channel}");
                    crate::log::warn(&state, &text);
                    state.log.message(recorded::LogEntry::at(recorded::Level::Warn, text));
                }
            }
            if let Some(reason) = end.header_limit() {
                // `ForwardHeaderLimit.Http1Response` refused the trailers and closed the connection (a78886b4d).
                crate::dataplane::log_forward_header_limit(&state, &logged_request, reason);
            }
            if end.is_aborted() {
                // `StreamingBody.error`: truncated, and the chunk timestamps are dropped. Since c9fb69fd5 (adopted) the idle timeout fails the body too, so a close-delimited body it cuts is truncated.
                capture.truncated = true;
                capture.arrivals = None;
            }
            let headers = match end.h2_stream() {
                Some(id) => std::iter::once(("x-http2-stream-id".to_string(), id.to_string())).chain(headers).collect(),
                None => headers,
            };
            let head = Head { status, reason, headers, response_override, response_modifier, timing };
            done(Streaming::completed(head, logged_request, capture, started.elapsed().as_millis() as i64));
        });
        rx
    }

    fn completed(head: Head, logged_request: HttpRequest, capture: Capture, response_time: i64) -> Forwarded {
        let Head { status, reason, headers, response_override, response_modifier, timing } = head;
        let content_type = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("content-type")).map(|(_, v)| v.clone()).filter(|v| !v.is_empty());
        // `attachStreamingHeaders`, appended to the head as the override function left it (the response time last,
        // by `finish`).
        let mut streamed_headers = vec![("x-mockserver-streamed".to_string(), "true".to_string())];
        if capture.truncated {
            streamed_headers.push(("x-mockserver-stream-truncated".into(), "true".into()));
        }
        if let Some(delays) = capture.delays().filter(|d| !d.is_empty()) {
            streamed_headers.push(("x-mockserver-chunk-delays-ms".into(), delays.iter().map(u64::to_string).collect::<Vec<_>>().join(",")));
        }
        // `setCapturedStreamingBody`: a textual content type logs the bytes decoded in its charset as a plain string
        // body, any other one binary; with none, the bytes are sniffed.
        let captured = capture.bytes.freeze();
        let text = match &content_type {
            Some(ct) => {
                let media = crate::media_type::MediaType::parse(Some(ct));
                media.is_string().then(|| crate::media_type::decode(&captured, media.charset_or_default()))
            }
            None => probably_utf8_text(&captured).then(|| String::from_utf8_lossy(&captured).into_owned()),
        };
        let text_body = text.is_some();
        let body = match text {
            Some(text) => bytes::Bytes::from(text.into_bytes()),
            None => captured,
        };
        let upstream = Upstream { status, reason, headers, body: body.clone(), timing, text_body, response_time: Some(response_time), streamed_headers, ..Default::default() };
        let mut forwarded = finish(None, logged_request, Ok(upstream), response_override.as_ref(), response_modifier.as_ref());
        if !text_body && !body.is_empty() {
            // A `BinaryBody` without a content type, whatever the header says.
            use base64::Engine;
            let binary = json!({"type": "BINARY", "base64Bytes": base64::engine::general_purpose::STANDARD.encode(&body)});
            forwarded.logged_response["body"] = binary.clone();
            if let Some((canonical, input)) = forwarded.recorded.as_mut() {
                canonical["httpResponse"]["body"] = binary.clone();
                input["httpResponse"]["body"] = binary;
            }
        }
        forwarded
    }
}

/// The head of a streamed response, kept until the stream ends.
struct Head {
    status: u32,
    reason: String,
    headers: Vec<(String, String)>,
    response_override: Option<Value>,
    response_modifier: Option<Value>,
    timing: client::Timing,
}

/// `StreamingBody`'s bounded capture: the first `max` bytes, and each chunk's arrival until the capture is full.
struct Capture {
    max: usize,
    bytes: bytes::BytesMut,
    arrivals: Option<Vec<Instant>>,
    truncated: bool,
}

impl Capture {
    fn new(max: usize) -> Self {
        Capture { max, bytes: bytes::BytesMut::new(), arrivals: Some(Vec::new()), truncated: false }
    }

    fn add(&mut self, chunk: &[u8]) {
        if !self.truncated && let Some(a) = self.arrivals.as_mut() {
            a.push(Instant::now());
        }
        if self.truncated || chunk.is_empty() {
            return;
        }
        let remaining = self.max.saturating_sub(self.bytes.len());
        if remaining > 0 {
            self.bytes.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
            if self.bytes.len() >= self.max {
                self.truncate();
            }
        } else {
            self.truncate();
        }
    }

    fn truncate(&mut self) {
        self.truncated = true;
        self.arrivals = None;
    }

    /// `interChunkDelaysMillis`: 0, then each gap between consecutive arrivals, in whole milliseconds.
    fn delays(&self) -> Option<Vec<u64>> {
        let a = self.arrivals.as_ref().filter(|a| !a.is_empty())?;
        Some(std::iter::once(0).chain(a.windows(2).map(|w| w[1].duration_since(w[0]).as_millis() as u64)).collect())
    }
}

/// `isProbablyUtf8Text`: no NUL or other C0 control byte but tab, CR and LF, and at most one replacement character
/// once decoded (a multi-byte character cut by capture truncation).
fn probably_utf8_text(bytes: &[u8]) -> bool {
    !bytes.is_empty()
        && bytes.iter().all(|&c| !(c == 0 || (c < 0x20 && c != b'\t' && c != b'\n' && c != b'\r')))
        && String::from_utf8_lossy(bytes).matches('\u{fffd}').count() <= 1
}

impl Forward {
    pub fn compile(expectation: &Map<String, Value>) -> Option<Forward> {
        if let Some(f) = expectation.get("httpForward") {
            return Some(Forward::To { target: Target::compile(f), delay: f.get("delay").and_then(action::delay) });
        }
        if let Some(t) = expectation.get("httpForwardTemplate") {
            let get = |k: &str| t.get(k).cloned().filter(|v| !v.is_null());
            return Some(Forward::Template {
                template: Template::compile(t),
                response_override: get("responseOverride"),
                response_modifier: get("responseModifier"),
                delay: t.get("delay").and_then(action::delay),
            });
        }
        if let Some(c) = expectation.get("httpForwardObjectCallback") {
            return Some(Forward::Callback {
                client_id: c.get("clientId").and_then(Value::as_str).unwrap_or_default().to_string(),
                response_callback: c.get("responseCallback").and_then(Value::as_bool).unwrap_or(false),
                delay: c.get("delay").and_then(action::delay),
            });
        }
        if let Some(c) = expectation.get("httpForwardClassCallback") {
            return Some(Forward::ClassCallback {
                class: c.get("callbackClass").and_then(Value::as_str).unwrap_or_default().to_string(),
                delay: c.get("delay").and_then(action::delay),
            });
        }
        if let Some(f) = expectation.get("httpForwardWithFallback").filter(|f| f.is_object()) {
            return Some(Forward::WithFallback {
                target: Target::compile(f.get("httpForward").unwrap_or(&Value::Null)),
                fallback: f.get("fallbackResponse").cloned().unwrap_or(Value::Null),
                status_codes: f.get("fallbackOnStatusCodes").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_i64).collect(),
                on_timeout: f.get("fallbackOnTimeout").and_then(Value::as_bool).unwrap_or(true),
                delay: f.get("delay").and_then(action::delay),
            });
        }
        if let Some(v) = expectation.get("httpForwardValidateAction").filter(|v| v.is_object()) {
            return Some(Forward::Validate {
                spec: v.get("specUrlOrPayload").and_then(Value::as_str).unwrap_or_default().to_string(),
                target: Target::compile(v),
                validate_request: v.get("validateRequest").and_then(Value::as_bool).unwrap_or(true),
                validate_response: v.get("validateResponse").and_then(Value::as_bool).unwrap_or(true),
                strict: v.get("validationMode").and_then(Value::as_str).unwrap_or("STRICT") == "STRICT",
                delay: v.get("delay").and_then(action::delay),
            });
        }
        let o = expectation.get("httpOverrideForwardedRequest")?;
        let get = |k: &str| o.get(k).cloned().filter(|v| !v.is_null());
        Some(Forward::Override {
            request_override: get("requestOverride").or_else(|| get("httpRequest")),
            request_modifier: get("requestModifier"),
            response_override: get("responseOverride").or_else(|| get("httpResponse")),
            response_modifier: get("responseModifier"),
            response_template: o.get("responseTemplate").filter(|t| t.is_object()).map(Template::compile),
            delay: o.get("delay").and_then(action::delay),
        })
    }

    pub fn delay(&self) -> Option<&action::Delay> {
        match self {
            Forward::To { delay, .. }
            | Forward::Override { delay, .. }
            | Forward::Template { delay, .. }
            | Forward::Callback { delay, .. }
            | Forward::ClassCallback { delay, .. }
            | Forward::WithFallback { delay, .. }
            | Forward::Validate { delay, .. } => delay.as_ref(),
        }
    }

    /// For `httpForward` and `httpForwardWithFallback`, the request with `Host` rewritten to the target and the
    /// forward's scheme (what upstream logs: the handler changes the received request itself).
    pub fn rewritten(&self, request: &HttpRequest) -> Option<HttpRequest> {
        let (Forward::To { target, .. } | Forward::WithFallback { target, .. }) = self else { return None };
        let mut forwarded = request.clone();
        forwarded.secure = target.secure;
        set_host(&mut forwarded, target.host_header());
        Some(forwarded)
    }

    /// The failed connection is reported as Netty's exception itself (`AnnotatedConnectException`), class name
    /// included, rather than by the client's message: the override and validate handlers' futures carry it.
    pub fn reports_exception_class(&self) -> bool {
        matches!(self, Forward::Override { .. } | Forward::Validate { .. })
    }

    /// Sends the forwarded request; `Err` when a template failed to render (answered 404).
    pub async fn execute(&self, state: &State, request: &HttpRequest, path: &PathMatch) -> Result<Forwarded, templates::Failed> {
        self.execute_queued(state, request, path, None).await
    }

    /// [`Forward::execute`] for an expectation's `httpForwardTemplate` admitted to the template queue: its render waits
    /// for a template thread (`scheduleTemplateAction`); the forward itself does not hold one.
    /// Boxed: its future is large ([`crate::boxed`]). A plain `httpForward` is entered on its own, so that it does not
    /// pay for the other actions' poll frame.
    pub fn execute_queued<'a>(&'a self, state: &'a State, request: &'a HttpRequest, path: &'a PathMatch, queued: Option<crate::overload::QueuedRender>) -> crate::boxed::Boxed<'a, Result<Forwarded, templates::Failed>> {
        match self {
            Forward::To { target, .. } => Box::pin(async move { Ok(self.forward_to(state, request, target).await) }),
            _ => Box::pin(self.execute_queued_inline(state, request, path, queued)),
        }
    }

    /// `httpForward`: the request rewritten for its target and sent there.
    async fn forward_to(&self, state: &State, request: &HttpRequest, target: &Target) -> Forwarded {
        let forwarded = self.rewritten(request).expect("httpForward");
        // `HttpForwardActionHandler` rewrites the received request itself: the guard counts and logs it as rewritten
        let out = Outbound { http2: matched_http2(state, request, target.secure), may_stream: may_stream(state, None), ..outbound_marked(state, &forwarded, &forwarded) };
        match send_to(state, "forward", target, &forwarded, &forwarded, &out).await {
            Sent::Blocked(sent) => bad_gateway_answer(forwarded, sent),
            Sent::Threw(message) => threw(forwarded, message),
            Sent::Done(result, sent) => Forwarded { sent: Some(sent), retried: retries_apply(state, &forwarded.method), ..finish(None, forwarded, result, None, None) },
        }
    }

    async fn execute_queued_inline(&self, state: &State, request: &HttpRequest, path: &PathMatch, queued: Option<crate::overload::QueuedRender>) -> Result<Forwarded, templates::Failed> {
        Ok(match self {
            Forward::To { target, .. } => self.forward_to(state, request, target).await,
            Forward::Template { template, response_override, response_modifier, .. } => {
                let thread = match queued {
                    Some(queued) => Some(queued.start(&state.overload).await),
                    None => None,
                };
                let generated = crate::blocking::off_worker(|| templates::execute(state, &state.velocity_engines.forward, template, request, path, None, templates::Role::Forward));
                drop(thread);
                let generated = match generated {
                    Ok(generated) => generated,
                    // without `templateFailureAsServerError`, output that is not a request is `badGatewayFuture`
                    // `badGatewayFuture(originalRequest)`: logged as the forward's response to the received request
                    Err(failed) if failed.invalid_output && !templates::failure_as_server_error(state) => {
                        return Ok(bad_gateway_answer(request.clone(), (crate::recorded::logged(request), crate::curl::to_curl(request, None))));
                    }
                    Err(failed) => return Err(failed),
                };
                let mut target = HttpRequest { method: String::new(), ..HttpRequest::default() };
                apply_request_override(&mut target, &generated);
                let as_generated = target.clone();
                // `HttpForwardTemplateActionHandler`: unless the template chose its own `Host`, a socket address
                // decides it (`adjustHostHeader`). `getFirstHeader` answers "" for an absent header, so a template
                // without a `Host` "chose" none unless the request had none either: it is sent without.
                let templated_host = target.first_header("host").unwrap_or("").to_string();
                if templated_host == request.first_header("host").unwrap_or("") && let Some(host) = socket_address_host(&generated) {
                    target.headers.retain(|(k, _)| !k.eq_ignore_ascii_case("host"));
                    target.headers.push(("Host".into(), vec![host]));
                }
                if let Some(forward_host) = template_forward_host(&target, &generated) && let Some(reason) = crate::ws_relay::blocked(state, &forward_host).await {
                    let entry = recorded::LogEntry::new(recorded::Kind::Warn, "forward template action blocked by SSRF policy:{}").args([reason]);
                    log_about(state, LogLevel::Warn, entry, request);
                    // `badGatewayFuture(templatedRequest)` (`HttpForwardAction.sendRequest`): logged as the forward's
                    // response to the generated request, with no remote address for its curl.
                    let sent = (crate::canonical::request_definition(&generated), crate::curl::to_curl(&as_generated, None));
                    return Ok(bad_gateway_answer(request.clone(), sent));
                }
                let (host, port, secure) = destination(&target, Some(&generated));
                // `sendRequest(templatedRequest, null, fn)`: streaming stays enabled whatever the override or
                // modifier does (no `isHeaderOnlyResponseModification` here).
                let out = Outbound { http2: matched_http2(state, request, secure), may_stream: may_stream(state, None), ..outbound_marked(state, request, &target) };
                let result = send_forward(state, request, &target.method, &host, port, secure, &out).await;
                let sent = (crate::canonical::request_definition(&generated), crate::curl::to_curl(&target, Some(&format!("{host}:{port}"))));
                Forwarded { sent: Some(sent), retried: retries_apply(state, &target.method), ..state.scenarios().scope(|| finish(Some(state), request.clone(), result, response_override.as_ref(), response_modifier.as_ref())) }
            }
            Forward::Callback { client_id, response_callback, .. } => {
                let generated = match state.callbacks.call_forward(client_id, crate::recorded::ordered_with_path_parameters(request, &path.parameters)).await {
                    Some(crate::callback::Reply::Message(v) | crate::callback::Reply::Request(v)) => crate::callback::strip_correlation(v),
                    // `handleError`: the client's error message answered as a 404.
                    Some(crate::callback::Reply::Error(message)) => {
                        let mut reply = Reply::status(404);
                        reply.body = message.clone().into();
                        return Ok(Forwarded { reply, logged_request: request.clone(), logged_response: json!({"statusCode": 404, "body": message}), recorded: None, error: None, streaming: None, ..Default::default() });
                    }
                    None => return Ok(bad_gateway(request.clone())),
                };
                let mut target = HttpRequest { method: String::new(), ..HttpRequest::default() };
                apply_request_override(&mut target, &generated);
                let (host, port, secure) = destination(&target, Some(&generated));
                // `sendRequest(callbackRequest, null, null)` streams; a response callback needs the whole response.
                let out = Outbound { http2: matched_http2(state, request, secure), may_stream: may_stream(state, None) && !*response_callback, ..outbound_marked(state, request, &target) };
                let result = send_forward(state, request, &target.method, &host, port, secure, &out).await;
                let upstream_answered = result.is_ok();
                let forwarded = Forwarded { retried: retries_apply(state, &target.method), ..finish(None, target.clone(), result, None, None) };
                if !*response_callback || !upstream_answered {
                    return Ok(forwarded);
                }
                // The response as the client sees it: the model, without the log-only response-time header.
                let mut upstream_response = forwarded.logged_response.clone();
                if let Some(Value::Object(h)) = upstream_response.get_mut("headers") {
                    h.remove("x-mockserver-response-time-ms");
                }
                match state.callbacks.call_with_response(client_id, crate::recorded::ordered(&target), upstream_response).await {
                    Some(crate::callback::Reply::Message(v)) => {
                        let v = crate::callback::strip_correlation(v);
                        Forwarded { reply: action::respond(&v).reply, logged_request: target, logged_response: canonical::response(&v), recorded: None, error: None, streaming: None, ..Default::default() }
                    }
                    _ => bad_gateway(target),
                }
            }
            Forward::ClassCallback { class, .. } => {
                use crate::class_callback;
                let resolved = class_callback::resolve(state, class);
                // `instantiateCallback`, once per interface, each logging why it found none.
                let forwarding = implemented(state, class, resolved.as_ref(), "ExpectationForwardCallback", |c| {
                    // An `ExpectationForwardAndResponseCallback` is an `ExpectationForwardCallback` too.
                    c.forward().map(ForwardHalf::Forward).or_else(|| c.forward_and_response().map(ForwardHalf::WithResponse))
                });
                let with_response = implemented(state, class, resolved.as_ref(), "ExpectationForwardAndResponseCallback", |c| c.forward_and_response());
                let Some(forwarding) = forwarding else {
                    // Neither interface: the request goes out unchanged, to its `Host`.
                    let (host, port, secure) = destination(request, None);
                    let out = Outbound { http2: matched_http2(state, request, secure), may_stream: may_stream(state, None), ..outbound_marked(state, request, request) };
                    let result = send_forward(state, request, &request.method, &host, port, secure, &out).await;
                    return Ok(Forwarded { retried: retries_apply(state, &request.method), ..finish(None, request.clone(), result, None, None) });
                };
                let model = crate::recorded::ordered_with_path_parameters(request, &path.parameters);
                let handler = forwarding.clone();
                let generated = match class_callback::run(move || handler.handle(&model)).await {
                    Ok(generated) => generated,
                    Err(error) => {
                        class_callback::callback_threw(state, class, &error, request);
                        return Ok(bad_gateway(request.clone()));
                    }
                };
                let mut target = HttpRequest { method: String::new(), ..HttpRequest::default() };
                apply_request_override(&mut target, &generated);
                // The callback's `HttpRequest` keeps its headers in the order it added them.
                if let Some(Value::Object(order)) = generated.get("headers") {
                    target.headers.edit(|h| h.sort_by_key(|(k, _)| order.keys().position(|o| o.eq_ignore_ascii_case(k)).unwrap_or(usize::MAX)));
                }
                let (host, port, secure) = destination(&target, Some(&generated));
                // A forward-only class streams (`sendRequest(request, null, fn)` with the identity); a response
                // callback builds a new response from the whole upstream one, which is then answered buffered.
                let out = Outbound { http2: matched_http2(state, request, secure), may_stream: may_stream(state, None) && with_response.is_none(), ..outbound_marked(state, request, &target) };
                let result = send_forward(state, request, &target.method, &host, port, secure, &out).await;
                let upstream_answered = result.is_ok();
                let mut forwarded = Forwarded { retried: retries_apply(state, &target.method), ..finish(None, request.clone(), result, None, None) };
                forwarded.sent = Some((crate::canonical::request_definition(&generated), crate::curl::to_curl(&target, Some(&format!("{host}:{port}")))));
                let (Some(callback), true) = (with_response, upstream_answered && !forwarded.loop_detected) else { return Ok(forwarded) };
                let mut upstream_response = forwarded.logged_response.clone();
                if let Some(Value::Object(h)) = upstream_response.get_mut("headers") {
                    h.remove("x-mockserver-response-time-ms");
                }
                let sent = crate::recorded::ordered(&target);
                match class_callback::run(move || callback.handle_response(&sent, &upstream_response)).await {
                    Ok(v) if !v.is_null() => {
                        // The log keeps the forward's timing header among the callback's headers (the model's
                        // descending key order), and the callback's response is what gets recorded.
                        let ms = forwarded.logged_response.pointer("/headers/x-mockserver-response-time-ms").cloned();
                        let mut timed = v.clone();
                        if let (Some(ms), Some(o)) = (&ms, timed.as_object_mut()) {
                            match o.entry("headers").or_insert_with(|| json!({})) {
                                Value::Object(h) => {
                                    h.insert("x-mockserver-response-time-ms".into(), ms.clone());
                                }
                                Value::Array(items) => items.push(json!({"name": "x-mockserver-response-time-ms", "values": ms})),
                                _ => {}
                            }
                        }
                        let logged = canonical::response(&timed);
                        let response_time = ms.as_ref().and_then(|m| m.get(0)).and_then(Value::as_str).unwrap_or("0").to_string();
                        let recorded = Some(answered_record(&logged, &v, &response_time, &forwarded.logged_request));
                        Forwarded { reply: action::respond(&v).reply, logged_response: logged, recorded, timing: None, ..forwarded }
                    }
                    Ok(_) => forwarded,
                    Err(error) => {
                        class_callback::callback_threw(state, class, &error, request);
                        forwarded
                    }
                }
            }
            Forward::WithFallback { target, fallback, status_codes, on_timeout, .. } => {
                let forwarded = self.rewritten(request).expect("httpForwardWithFallback");
                let fallback = Some(fallback).filter(|f| !f.is_null());
                // The status decides on the response's head, so a streamed body is relayed as `httpForward`'s is.
                let out = Outbound { http2: matched_http2(state, request, target.secure), may_stream: may_stream(state, None), ..outbound_marked(state, &forwarded, &forwarded) };
                match send_to(state, "forward-with-fallback", target, &forwarded, &forwarded, &out).await {
                    Sent::Threw(message) => threw(forwarded, message),
                    Sent::Blocked(sent) => match fallback.filter(|_| *on_timeout) {
                        Some(fallback) => Forwarded { sent: Some(sent), ..fallback_response(fallback, forwarded) },
                        None => bad_gateway_answer(forwarded, sent),
                    },
                    Sent::Done(Err(error), sent) => match fallback.filter(|_| *on_timeout) {
                        Some(fallback) => {
                            let message = error.exception_message().unwrap_or_default();
                            let entry = recorded::LogEntry::new(recorded::Kind::Info, "forward-with-fallback: upstream request failed ({}), returning fallback response").without_port().args([message]);
                            log_about(state, LogLevel::Info, entry, &forwarded);
                            Forwarded { sent: Some(sent), ..fallback_response(fallback, forwarded) }
                        }
                        None => bad_gateway_answer(forwarded, sent),
                    },
                    Sent::Done(Ok(upstream), sent) => match fallback.filter(|_| should_fallback(Some(upstream.status), status_codes)) {
                        Some(fallback) => {
                            let status = upstream.status;
                            // `setHttpResponse(response)`: the upstream's response, as the forward would have logged it.
                            let seen = finish(None, forwarded.clone(), Ok(upstream), None, None);
                            let response = upstream_as_seen(&seen);
                            // Logged from the response future's callback, which stamps no port.
                            let entry = recorded::LogEntry::new(recorded::Kind::Info, "forward-with-fallback: upstream returned status {}, returning fallback response")
                                .without_port()
                                .response(response)
                                .args([recorded::Arg::with_text(json!(status), status.to_string())]);
                            log_about(state, LogLevel::Info, entry, &forwarded);
                            Forwarded { sent: Some(sent), ..fallback_response(fallback, forwarded) }
                        }
                        None => Forwarded { sent: Some(sent), ..finish(None, forwarded, Ok(upstream), None, None) },
                    },
                }
            }
            Forward::Validate { spec, target, validate_request, validate_response, strict, .. } => {
                use crate::openapi_validation as validation;
                let as_received = || (crate::recorded::logged(request), crate::curl::to_curl(request, None));
                if *validate_request {
                    let errors = validation::validate_request(spec, request, None);
                    if !errors.is_empty() {
                        let errors = errors.join("; ");
                        let entry = recorded::LogEntry::new(recorded::Kind::OpenapiResponseValidationFailed, "OpenAPI request validation failed for request{}errors:{}")
                            .args([recorded::Arg::from(crate::recorded::logged(request)), errors.clone().into()]);
                        log_about(state, LogLevel::Warn, entry, request);
                        if *strict {
                            return Ok(Forwarded { sent: Some(as_received()), ..rejected(request.clone(), 400, &format!("OpenAPI request validation failed: {errors}")) });
                        }
                    }
                }
                // The clone that goes out carries its socket address, and `adjustHostHeader` names it in `Host`.
                let mut sent_request = request.clone();
                adjust_host_header(state, &mut sent_request, target);
                let out = Outbound { http2: matched_http2(state, request, target.secure), may_stream: may_stream(state, None), ..outbound_marked(state, request, &sent_request) };
                let (result, sent) = match send_to(state, "forward-validate", target, request, &sent_request, &out).await {
                    // `badGatewayFuture(request)` on the clone that would have gone out.
                    Sent::Blocked((logged_sent, curl)) => return Ok(bad_gateway_answer(request.clone(), (with_socket_address(logged_sent, target), curl))),
                    Sent::Threw(message) => return Ok(threw(request.clone(), message)),
                    Sent::Done(result, (logged_sent, curl)) => (result, (with_socket_address(logged_sent, target), curl)),
                };
                let forwarded = Forwarded { sent: Some(sent.clone()), retried: retries_apply(state, &request.method), ..finish(None, request.clone(), result, None, None) };
                // A streamed upstream body is relayed as it arrives, unvalidated: the validator sees only the head,
                // and the oracle neither rejects nor logs an invalid streamed body (forward_validate_streamed).
                if !*validate_response || forwarded.error.is_some() || forwarded.streaming.is_some() {
                    return Ok(forwarded);
                }
                let headers: MultiMap = forwarded.reply.headers.iter().fold(MultiMap::new(), |mut m, (k, v)| {
                    request::push(&mut m, k, v.clone());
                    m
                });
                let body = String::from_utf8_lossy(&forwarded.reply.body).into_owned();
                let operation = validation::forward_operation_id(spec, request);
                let errors = validation::validate_response(spec, &operation, &validation::Response { status: forwarded.reply.status, headers: &headers, body: &body });
                if errors.is_empty() {
                    return Ok(forwarded);
                }
                let errors = errors.join("; ");
                let seen = upstream_as_seen(&forwarded);
                let entry = recorded::LogEntry::new(recorded::Kind::OpenapiResponseValidationFailed, "OpenAPI response validation failed for request{}response{}errors:{}")
                    .without_port()
                    .response(seen.clone())
                    .args([recorded::Arg::from(crate::recorded::logged(request)), (&seen).into(), errors.clone().into()]);
                log_about(state, LogLevel::Warn, entry, request);
                if !*strict {
                    return Ok(forwarded);
                }
                Forwarded { sent: Some(sent), ..rejected(request.clone(), 502, &format!("OpenAPI response validation failed: {errors}")) }
            }
            Forward::Override { request_override, request_modifier, response_override, response_modifier, response_template, .. } => {
                let mut target = request.clone();
                if let Some(o) = request_override {
                    apply_request_override(&mut target, o);
                }
                if let Some(m) = request_modifier {
                    apply_request_modifier(&mut target, m);
                }
                // `HttpForwardAction.sendRequest` checks `forwardProxyBlockPrivateNetworks` for every forward action,
                // this one too: its socket address, else its `Host`.
                if let Some(forward_host) = request_override.as_ref().and_then(|o| template_forward_host(&target, o)).or_else(|| template_forward_host(&target, &Value::Null)) && let Some(reason) = crate::ws_relay::blocked(state, &forward_host).await {
                    let entry = recorded::LogEntry::new(recorded::Kind::Warn, "override forwarded request action blocked by SSRF policy:{}").args([reason]);
                    log_about(state, LogLevel::Warn, entry, &target);
                    let sent = (crate::recorded::logged(&target), crate::curl::to_curl(&target, None));
                    return Ok(bad_gateway_answer(request.clone(), sent));
                }
                let (host, port, secure) = destination(&target, request_override.as_ref());
                // `requestToSend`: the override's socket address set and, unless the override names its own `Host`,
                // `adjustHostHeader` applied to it, as sent and as logged (an IPv6 literal unbracketed: `::1:1080`)
                let addressed = request_override.as_ref().filter(|o| o.get("socketAddress").is_some_and(|a| !a.is_null())).map(|o| {
                    let address = Target { host: Some(host.clone()), port: i64::from(port), secure };
                    if !names_host(o) {
                        adjust_host_header(state, &mut target, &address);
                    }
                    address
                });
                let out = Outbound { http2: matched_http2(state, request, secure), may_stream: may_stream(state, None) && header_only(response_override.as_ref(), response_modifier.as_ref(), response_template.is_some()), ..outbound_marked(state, request, &target) };
                let result = send_forward(state, request, &target.method, &host, port, secure, &out).await;
                let sent = match addressed {
                    Some(address) => (with_socket_address(crate::recorded::logged(&target), &address), crate::curl::to_curl(&target, Some(&format!("{host}:{port}")))),
                    None => sent_as(&target, &host, port),
                };
                let forwarded = Forwarded { sent: Some(sent), ..state.scenarios().scope(|| finish(Some(state), request.clone(), result, response_override.as_ref(), response_modifier.as_ref())) };
                match response_template {
                    Some(t) if forwarded.recorded.is_some() && !forwarded.loop_detected => apply_response_template(state, t, request, path, forwarded)?,
                    _ => forwarded,
                }
            }
        })
    }
}

/// The request half of a forward callback class.
#[derive(Clone)]
enum ForwardHalf {
    Forward(std::sync::Arc<dyn crate::class_callback::ForwardCallback>),
    WithResponse(std::sync::Arc<dyn crate::class_callback::ForwardAndResponseCallback>),
}

impl ForwardHalf {
    fn handle(&self, request: &Value) -> Result<Value, crate::class_callback::CallbackError> {
        match self {
            ForwardHalf::Forward(f) => f.handle(request),
            ForwardHalf::WithResponse(f) => f.handle(request),
        }
    }
}

/// `HttpForwardClassCallbackActionHandler.instantiateCallback` for one interface: the implementation, or `None`
/// after logging why there is none.
fn implemented<T>(
    state: &State,
    class: &str,
    resolved: Option<&crate::class_callback::CallbackClass>,
    interface: &str,
    get: impl Fn(&crate::class_callback::CallbackClass) -> Option<T>,
) -> Option<T> {
    match resolved {
        None => {
            crate::class_callback::log_error_with(state, &format!("ClassNotFoundException - while trying to instantiate {interface} class \"{class}\""), None, Some(&format!("java.lang.ClassNotFoundException: {class}")));
            None
        }
        Some(c) => {
            let found = get(c);
            if found.is_none() {
                let text = format!("{class} does not implement org.mockserver.mock.action.{interface} required for forwarded requests with class callback");
                crate::log::warn(state, &text);
                // `setHttpRequest(null)`: the entry carries the default request.
                state.log.message(recorded::LogEntry::at(recorded::Level::Warn, text).default_request());
            }
            found
        }
    }
}

/// `streamingResponsesEnabled` (default on), unless a response override replaces the body.
fn may_stream(state: &State, response_override: Option<&Value>) -> bool {
    state.config.bool_property("streamingResponsesEnabled", true) && response_override.is_none_or(|o| o.get("body").is_none())
}

/// `HttpOverrideForwardedRequestActionHandler.isHeaderOnlyResponseModification`: a forward keeps streaming unless a
/// template, an override body or `generateFromSchema`, or a modifier's (chain-aware) JSON body patch needs the whole
/// response.
fn header_only(response_override: Option<&Value>, response_modifier: Option<&Value>, templated: bool) -> bool {
    let present = |o: &Value, k: &str| o.get(k).is_some_and(|v| !v.is_null());
    !templated && response_override.is_none_or(|o| !present(o, "body") && !present(o, "generateFromSchema")) && response_modifier.is_none_or(|m| modifier_leaves(m).iter().all(|l| !present(l, "jsonPatch") && !present(l, "jsonMergePatch")))
}

/// The modifiers `HttpResponseModifier.applyTo` runs, in order: a non-empty `modifiers` chain runs its children (each
/// by the same rule) instead of the modifier's own edits.
fn modifier_leaves(m: &Value) -> Vec<&Value> {
    match m.get("modifiers").and_then(Value::as_array).filter(|c| !c.is_empty()) {
        Some(chain) => chain.iter().filter(|c| !c.is_null()).flat_map(modifier_leaves).collect(),
        None => vec![m],
    }
}

/// The modifiers `HttpResponseModifier.applyTo` actually runs on a response, in order: a modifier whose `condition`
/// does not match is skipped with its whole chain. A condition reads the status, the response's headers as earlier
/// modifiers left them (so `headers` gets each run modifier's header edits; cookie edits never add a header) and the
/// received request.
fn applied_leaves<'a>(m: &'a Value, status: u32, headers: &mut MultiMap, request: &HttpRequest, out: &mut Vec<&'a Value>) {
    if let Some(c) = m.get("condition").filter(|c| !c.is_null())
        && !condition_matches(c, status, headers, request)
    {
        return;
    }
    if let Some(chain) = m.get("modifiers").and_then(Value::as_array).filter(|c| !c.is_empty()) {
        for child in chain.iter().filter(|c| !c.is_null()) {
            applied_leaves(child, status, headers, request, out);
        }
        return;
    }
    if let Some(h) = m.get("headers") {
        modify_map(headers, h);
    }
    out.push(m);
}

/// `HttpResponseModifierCondition.matches`: every configured criterion holds. Blank strings are not criteria
/// (`StringUtils.isNotBlank`); `statusCodeRange` matches only a status class such as `2XX` (`^\s*([0-9])[xX]{2}\s*$`),
/// anything else is a clean non-match.
fn condition_matches(c: &Value, status: u32, headers: &MultiMap, request: &HttpRequest) -> bool {
    let not_blank = |k: &str| c.get(k).and_then(Value::as_str).filter(|s| !s.chars().all(char::is_whitespace));
    let has = |map: &MultiMap, name: &str| map.iter().any(|(k, _)| k.eq_ignore_ascii_case(name));
    if let Some(code) = c.get("statusCode").filter(|v| !v.is_null())
        && code.as_u64() != Some(status as u64)
    {
        return false;
    }
    if let Some(range) = not_blank("statusCodeRange") {
        let class = range.trim_matches(|ch: char| matches!(ch, ' ' | '\t' | '\n' | '\x0b' | '\x0c' | '\r')).as_bytes();
        let matched = class.len() == 3 && class[0].is_ascii_digit() && class[1..].iter().all(|b| matches!(b, b'x' | b'X')) && status / 100 == u32::from(class[0] - b'0');
        if !matched {
            return false;
        }
    }
    if let Some(name) = not_blank("responseHasHeader")
        && !has(headers, name)
    {
        return false;
    }
    if let Some(name) = not_blank("requestHasHeader")
        && !has(&request.headers.to_multimap(), name)
    {
        return false;
    }
    true
}

/// `HttpForwardAction.sendRequest`'s protocol for an expectation's forward: HTTP/2 under
/// `forwardProxyHttp2Upgrade` for a secure forward, else the inbound protocol under `forwardProxyHttp2Enabled`,
/// else HTTP/1.1 (HTTP/2 only ever goes out over TLS).
fn matched_http2(state: &State, inbound: &HttpRequest, secure: bool) -> bool {
    secure
        && ((state.config.bool_property("forwardProxyHttp2Upgrade", false))
            || (state.config.bool_property("forwardProxyHttp2Enabled", false) && inbound.protocol == "HTTP_2"))
}

/// The unmatched (proxy) and proxy-pass paths keep the inbound protocol, upgraded under `forwardProxyHttp2Upgrade`.
pub fn unmatched_http2(state: &State, inbound: &HttpRequest, secure: bool) -> bool {
    secure && (state.config.bool_property("forwardProxyHttp2Upgrade", false) || inbound.protocol == "HTTP_2")
}

/// The `Host` a template's `socketAddress` implies (`adjustHostHeader`): the port only when not the scheme's default.
fn socket_address_host(generated: &Value) -> Option<String> {
    let sa = generated.get("socketAddress")?;
    let host = sa.get("host").and_then(Value::as_str).filter(|h| !h.trim().is_empty())?;
    let https = sa.get("scheme").and_then(Value::as_str) == Some("HTTPS");
    Some(match sa.get("port").and_then(Value::as_u64) {
        None => host.to_string(),
        Some(443) if https => host.to_string(),
        Some(80) if !https => host.to_string(),
        Some(p) => format!("{host}:{p}"),
    })
}

/// `HttpForwardTemplateActionHandler.resolveForwardHost`: the templated `socketAddress`'s host, else the host part
/// of its `Host` header (`HttpRequest.splitHostPort`), the target `InetAddressValidator` checks.
fn template_forward_host(target: &HttpRequest, generated: &Value) -> Option<String> {
    let sa_host = generated.pointer("/socketAddress/host").and_then(Value::as_str).filter(|h| !h.trim().is_empty());
    if let Some(host) = sa_host {
        return Some(host.to_string());
    }
    let header = target.first_header("host").filter(|h| !h.trim().is_empty())?;
    let host = match header.strip_prefix('[').and_then(|rest| rest.split_once(']')) {
        Some((host, _)) => host,
        None => header.split(':').next().unwrap_or_default(),
    };
    Some(host.to_string()).filter(|h| !h.trim().is_empty())
}

/// The request as sent (`responseFuture.getHttpRequest()`), as the forward's log line prints it: its JSON and its curl
/// command to the upstream.
/// Whether a request override sets `Host` itself (`containsHeader("Host")`), in the map or the list form.
fn names_host(request_override: &Value) -> bool {
    match request_override.get("headers") {
        Some(Value::Object(h)) => h.keys().any(|k| k.eq_ignore_ascii_case("host")),
        Some(Value::Array(items)) => items.iter().any(|i| i.get("name").and_then(Value::as_str).is_some_and(|n| n.eq_ignore_ascii_case("host"))),
        _ => false,
    }
}

fn sent_as(target: &HttpRequest, host: &str, port: u16) -> (Value, String) {
    (crate::recorded::logged(target), crate::curl::to_curl(target, Some(&format!("{host}:{port}"))))
}

/// `HttpForwardWithFallbackActionHandler.shouldFallback`: a missing status always falls back; otherwise the configured
/// codes, or any 5xx when none are.
pub fn should_fallback(status: Option<u32>, status_codes: &[i64]) -> bool {
    let Some(status) = status else { return true };
    if !status_codes.is_empty() {
        return status_codes.contains(&i64::from(status));
    }
    (500..=599).contains(&status)
}

/// What [`send_to`] made of a forward: blocked by the SSRF policy, not sendable (`handleAnyException`'s 404 with
/// the exception's message), or sent; with the request as sent (its JSON and curl command) when it got that far.
enum Sent {
    Blocked((Value, String)),
    Threw(String),
    Done(Result<Upstream, client::Error>, (Value, String)),
}

/// `InetAddressValidator.validateForwardTarget`, then `sendRequest` to `target`'s unresolved address: the shared
/// path of `httpForward`, `httpForwardWithFallback` and `httpForwardValidateAction`. A blocked target is logged
/// (WARN) as `<action> action blocked by SSRF policy:…` about `request`.
/// Boxed: its future is large ([`crate::boxed`]).
fn send_to<'a>(state: &'a State, action: &'a str, target: &'a Target, received: &'a HttpRequest, request: &'a HttpRequest, out: &'a Outbound) -> crate::boxed::Boxed<'a, Sent> {
    Box::pin(send_to_inline(state, action, target, received, request, out))
}

async fn send_to_inline(state: &State, action: &str, target: &Target, received: &HttpRequest, request: &HttpRequest, out: &Outbound) -> Sent {
    let (address, port) = match target.address() {
        Ok(a) => a,
        Err(message) => {
            let blocked = match target.host.as_deref() {
                Some(host) => crate::ws_relay::blocked(state, host).await,
                None => None,
            };
            return match blocked {
                Some(reason) => ssrf_blocked(state, action, &reason, request, target),
                None => Sent::Threw(message),
            };
        }
    };
    let sent = sent_as(request, address, port);
    if let Some(reason) = crate::ws_relay::blocked(state, address).await {
        return ssrf_blocked(state, action, &reason, request, target);
    }
    Sent::Done(send_forward(state, received, &request.method, address, port, target.secure, out).await, sent)
}

fn ssrf_blocked(state: &State, action: &str, reason: &str, request: &HttpRequest, target: &Target) -> Sent {
    let entry = recorded::LogEntry::new(recorded::Kind::Warn, format!("{action} action blocked by SSRF policy:{{}}")).args([reason]);
    log_about(state, LogLevel::Warn, entry, request);
    let remote = target.host.as_deref().map(|h| format!("{h}:{}", target.port));
    Sent::Blocked((crate::recorded::logged(request), crate::curl::to_curl(request, remote.as_deref())))
}

/// `HttpForwardAction.adjustHostHeader`: `forwardDefaultHostHeader` when set, else (under `forwardAdjustHostHeader`,
/// on by default) the socket address the request goes to.
fn adjust_host_header(state: &State, request: &mut HttpRequest, target: &Target) {
    if let Some(default_host) = state.config.property("forwardDefaultHostHeader").filter(|h| !h.trim().is_empty()) {
        set_host(request, default_host);
    } else if state.config.bool_property("forwardAdjustHostHeader", true) && target.host.as_deref().is_some_and(|h| !h.trim().is_empty()) {
        set_host(request, target.host_header());
    }
}

/// The forward could not be sent at all (an exception inside the handler): answered 404 by the dataplane, which logs
/// the message.
fn threw(logged_request: HttpRequest, message: String) -> Forwarded {
    Forwarded { reply: Reply::status(404), logged_request, logged_response: json!({"statusCode": 404, "reasonPhrase": "Not Found"}), threw: Some(message), ..Default::default() }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LogLevel {
    Info,
    Warn,
}

/// A WARN event-log entry about `request` ([`log_about`]).
pub(crate) fn log_warn_about(state: &State, entry: recorded::LogEntry, request: &HttpRequest) {
    log_about(state, LogLevel::Warn, entry, request)
}

/// An event-log entry about `request` at `level`, gated by the log level.
fn log_about(state: &State, level: LogLevel, entry: recorded::LogEntry, request: &HttpRequest) {
    let enabled = match level {
        LogLevel::Info => state.info_enabled(),
        LogLevel::Warn => !matches!(state.log_level.as_str(), "OFF" | "ERROR"),
    };
    if !enabled {
        return;
    }
    // the console line is redacted against the request the entry is about (`LogEntry.redactedView`, c76143e4a)
    let entry = entry.request(request);
    let entry = match level {
        LogLevel::Info => {
            crate::log::entry_as(state, recorded::Level::Info, &entry);
            entry
        }
        LogLevel::Warn => {
            crate::log::entry_as(state, recorded::Level::Warn, &entry);
            // An entry of no type of its own is a WARN one.
            if entry.kind == recorded::Kind::Info { entry.kind(recorded::Kind::Warn).level(recorded::Level::Warn) } else { entry.level(recorded::Level::Warn) }
        }
    };
    state.log.message_about(entry, recorded::Subject::Request(std::sync::Arc::new(request.clone())));
}

/// The upstream's response as the action handler sees it: without the log's timing header, with the client's timing.
fn upstream_as_seen(forwarded: &Forwarded) -> Value {
    let mut seen = crate::recorded::logged_response(&forwarded.logged_response);
    if let Some(Value::Object(h)) = seen.get_mut("headers") {
        h.shift_remove("x-mockserver-response-time-ms");
        if h.is_empty() {
            seen.as_object_mut().map(|o| o.shift_remove("headers"));
        }
    }
    if let (Some(timing), Some(o)) = (forwarded.timing, seen.as_object_mut()) {
        o.insert("timing".into(), timing.json());
    }
    seen
}

/// The request as logged with its `socketAddress` (`withSocketAddress`), which the serialiser writes after `secure`.
fn with_socket_address(logged: Value, target: &Target) -> Value {
    let Value::Object(o) = logged else { return logged };
    let address = json!({"host": target.host, "port": target.port, "scheme": if target.secure { "HTTPS" } else { "HTTP" }});
    let mut out = Map::new();
    let mut placed = false;
    for (k, v) in o {
        if !placed && ["protocol", "localAddress", "remoteAddress", "body"].contains(&k.as_str()) {
            out.insert("socketAddress".into(), address.clone());
            placed = true;
        }
        out.insert(k, v);
    }
    if !placed {
        out.insert("socketAddress".into(), address);
    }
    Value::Object(out)
}

/// A response the action answers itself as its forward's result (`response().withStatusCode(…).withBody(…)`):
/// logged, and recorded, as a forwarded response with the timing header.
fn rejected(logged_request: HttpRequest, status: u32, body: &str) -> Forwarded {
    fallback_response(&json!({"statusCode": status, "body": body}), logged_request)
}

/// `HttpResponse.badGatewayResponse()` as a forward's result (not a failed forward).
fn bad_gateway_answer(logged_request: HttpRequest, sent: (Value, String)) -> Forwarded {
    Forwarded { sent: Some(sent), ..fallback_response(&json!({"statusCode": 502, "reasonPhrase": "Bad Gateway"}), logged_request) }
}

/// A model response (input JSON) returned as a forward's result: served as `httpResponse` would be, logged with the
/// forward's timing header ahead of its own headers, and recorded.
fn fallback_response(response: &Value, logged_request: HttpRequest) -> Forwarded {
    let reply = action::respond(response).reply;
    let canonical = canonical::response(response);
    let timing = ("x-mockserver-response-time-ms".to_string(), Value::Array(vec![Value::String("0".into())]));
    let mut logged = Map::new();
    for key in ["statusCode", "reasonPhrase"] {
        if let Some(v) = canonical.get(key) {
            logged.insert(key.into(), v.clone());
        }
    }
    let mut headers = Map::new();
    headers.insert(timing.0.clone(), timing.1.clone());
    if let Some(Value::Object(h)) = canonical.get("headers") {
        headers.extend(h.clone());
    }
    logged.insert("headers".into(), Value::Object(headers));
    for (k, v) in canonical.as_object().into_iter().flatten().filter(|(k, _)| !["statusCode", "reasonPhrase", "headers"].contains(&k.as_str())) {
        logged.insert(k.clone(), v.clone());
    }
    let logged = Value::Object(logged);
    let (recorded_expectation, recorded_input) = answered_record(&logged, response, "0", &logged_request);
    Forwarded { reply, logged_request, logged_response: logged, recorded: Some((recorded_expectation, recorded_input)), ..Default::default() }
}

/// The recorded expectation, canonical and in input form, of a response the action produced itself (`logged`, with
/// the timing header; `response` as given), answered to `logged_request`.
fn answered_record(logged: &Value, response: &Value, response_time: &str, logged_request: &HttpRequest) -> (Value, Value) {
    let timing = "x-mockserver-response-time-ms";
    // A recorded expectation's body is always typed; a string body carries its bytes.
    let mut recorded_response = logged.clone();
    match recorded_response.get("body").cloned() {
        Some(Value::String(text)) => {
            use base64::Engine;
            recorded_response["body"] = json!({"type": "STRING", "string": text, "rawBytes": base64::engine::general_purpose::STANDARD.encode(text.as_bytes())});
        }
        Some(b @ (Value::Object(_) | Value::Array(_))) if b.get("type").is_none() => recorded_response["body"] = json!({"type": "JSON", "json": b}),
        _ => {}
    }
    let mut input_response = response.as_object().cloned().unwrap_or_default();
    let mut input_headers = match input_response.get("headers") {
        Some(h) => recorded::list_form(&entries(h)),
        None => json!([]),
    };
    if let Value::Array(items) = &mut input_headers {
        items.push(json!({"name": timing, "values": [response_time]}));
    }
    input_response.insert("headers".into(), input_headers);
    let recorded_input = json!({
        "httpRequest": recorded::input_request(logged_request),
        "httpResponse": Value::Object(input_response),
        "times": {"remainingTimes": 1},
        "timeToLive": {"unlimited": true},
    });
    let recorded_expectation = json!({
        "httpRequest": recorded::ordered_with(logged_request, BodyForm::Recorded),
        "httpResponse": recorded_response,
        "id": uuid::Uuid::new_v4().to_string(),
        "priority": 0,
        "timeToLive": {"unlimited": true},
        "times": {"remainingTimes": 1},
    });
    (recorded_expectation, recorded_input)
}

fn bad_gateway(logged_request: HttpRequest) -> Forwarded {
    Forwarded { reply: Reply::status(502), logged_request, logged_response: json!({"statusCode": 502, "reasonPhrase": "Bad Gateway"}), recorded: None, error: None, streaming: None, ..Default::default() }
}

/// `responseTemplate`: the rendered response replaces the upstream's; an invalid output keeps the upstream's.
fn apply_response_template(state: &State, template: &Template, request: &HttpRequest, path: &PathMatch, forwarded: Forwarded) -> Result<Forwarded, templates::Failed> {
    let upstream = input_response(&forwarded);
    let rendered = crate::recorded::portless_sync(|| templates::execute(state, &state.velocity_engines.override_forward, template, request, path, Some(&upstream), templates::Role::ForwardResponse));
    let generated = match rendered {
        Ok(generated) => generated,
        // without `templateFailureAsServerError`, output that is not a response leaves the upstream's
        Err(failed) if failed.invalid_output && !templates::failure_as_server_error(state) => return Ok(forwarded),
        Err(failed) => return Err(failed),
    };
    let reply = action::respond(&generated).reply;
    // The log keeps the forward's timing header, appended to the generated response's headers.
    let timing = forwarded.logged_response.pointer("/headers/x-mockserver-response-time-ms").cloned();
    let mut logged = canonical::response(&generated);
    if let (Some(timing), Some(o)) = (timing, logged.as_object_mut()) {
        let mut headers = o.get("headers").and_then(Value::as_object).cloned().unwrap_or_default();
        headers.insert("x-mockserver-response-time-ms".into(), timing);
        o.insert("headers".into(), Value::Object(headers));
        let fields = std::mem::take(o);
        *o = ["statusCode", "reasonPhrase", "headers", "cookies", "body"]
            .iter()
            .filter_map(|k| fields.get(*k).map(|v| (k.to_string(), v.clone())))
            .chain(fields.iter().filter(|(k, _)| !["statusCode", "reasonPhrase", "headers", "cookies", "body"].contains(&k.as_str())).map(|(k, v)| (k.clone(), v.clone())))
            .collect();
    }
    Ok(Forwarded { reply, logged_response: logged, ..forwarded })
}

/// The forwarded response in input JSON form, as the template's `response` object reads it.
fn input_response(forwarded: &Forwarded) -> Value {
    forwarded.recorded.as_ref().and_then(|(_, input)| input.get("httpResponse").cloned()).unwrap_or(Value::Null)
}

/// Where an overridden request goes and whether over TLS: its `socketAddress` (with its scheme), else its `Host`
/// header, secure when the request is (inherited from the received one unless the override sets `secure`).
fn destination(target: &HttpRequest, request_override: Option<&Value>) -> (String, u16, bool) {
    if let Some(sa) = request_override.and_then(|o| o.get("socketAddress")) {
        let https = sa.get("scheme").and_then(Value::as_str) == Some("HTTPS");
        let host = sa.get("host").and_then(Value::as_str).unwrap_or("localhost").to_string();
        let port = sa.get("port").and_then(Value::as_u64).and_then(|p| u16::try_from(p).ok()).unwrap_or(if https { 443 } else { 80 });
        return (host, port, https);
    }
    let host = target.first_header("host").unwrap_or("localhost");
    match host.rsplit_once(':') {
        Some((h, p)) if p.parse::<u16>().is_ok() && !h.is_empty() => (h.to_string(), p.parse().unwrap_or(80), target.secure),
        _ => (host.to_string(), if target.secure { 443 } else { 80 }, target.secure),
    }
}

/// The request upstream's client writes (`MockServerHttpRequestToFullHttpRequest`): the request's headers in
/// order except framing, `host` and `accept-encoding`, then `host`, `accept-encoding`, `content-length` and
/// `connection`, and finally the cookies re-encoded into one `cookie` header.
/// `HopByHopHeaderFilter.onRequest`.
const HOP_BY_HOP_REQUEST: &[&str] =
    &["proxy-connection", "connection", "keep-alive", "transfer-encoding", "te", "trailer", "proxy-authorization", "proxy-authenticate", "upgrade"];

/// `handleUnmatchedProxyForward` in port-forwarding mode: an unmatched request goes to the remote socket without its
/// hop-by-hop headers and with the loop-prevention header, which is dropped again from the response. `Host` is
/// replaced by `forwardDefaultHostHeader`, else (not exploratory) by a set `proxyRemoteHost`. The flag says the response carried that header back (an echo of
/// the request), which upstream logs as no match.
/// An exploratory forward (to a non-local `Host`, `potentiallyHttpProxy`) gives up connecting after a second.
pub async fn unmatched(state: &State, request: &HttpRequest, host: &str, port: u16, exploratory: bool) -> (Forwarded, bool) {
    let mut forwarded = request.clone();
    forwarded.headers.retain(|(k, _)| !HOP_BY_HOP_REQUEST.iter().any(|h| k.eq_ignore_ascii_case(h)));
    forwarded.headers.push((LOOP_HEADER.into(), vec![state.forwarded_by.clone()]));
    if let Some(default_host) = state.config.property("forwardDefaultHostHeader").filter(|h| !h.trim().is_empty()) {
        set_host(&mut forwarded, default_host);
    } else if let Some(remote_host) = state.config.property("proxyRemoteHost").filter(|h| !exploratory && !h.trim().is_empty()) {
        // `adjustHostHeaderForUnmatchedRequest`: with a remote socket and a `proxyRemoteHost`, `Host` names it, the
        // port appended unless it is unset, 80 or 443 (scenario `proxy_remote_host_runtime`)
        let port = state.config.property("proxyRemotePort").and_then(|p| p.trim().parse::<i64>().ok());
        let value = match port {
            None | Some(80) | Some(443) => remote_host,
            Some(port) => format!("{remote_host}:{port}"),
        };
        set_host(&mut forwarded, value);
    }
    let identity = request.secure.then(|| state.forward_identity(host)).flatten();
    let mut echoed = false;
    let out = Outbound { http2: unmatched_http2(state, request, request.secure), may_stream: may_stream(state, None), ..outbound(&forwarded) };
    let result = send_via(state, host, port, request.secure, &out, identity, if exploratory { EXPLORATORY_CONNECT_TIMEOUT } else { client::connect_timeout(&state.config) }).await.inspect(|upstream| {
        echoed = upstream.headers.iter().any(|(k, v)| k.eq_ignore_ascii_case(LOOP_HEADER) && *v == state.forwarded_by);
    });
    let mut finished = finish(None, request.clone(), result, None, None);
    // The loop header comes off the response model after `HopByHopHeaderFilter`, which counted it: framing headers an
    // echo also returned are then recomputed by the writer, not kept as the upstream sent them (an echo of a request
    // without `Host` through a SOCKS4 tunnel, `NettyHttpProxySOCKS4IntegrationTest`).
    if echoed {
        finished.reply.headers.retain(|(k, _)| !k.eq_ignore_ascii_case(LOOP_HEADER));
    }
    (finished, echoed)
}

/// A `ProxyPassMapping` (`mockserver.proxyPass`, a JSON array): requests under `pathPrefix` are forwarded to
/// `targetUri` with the prefix replaced by its path.
pub struct ProxyPass {
    pub target_uri: String,
    host: String,
    port: u16,
    secure: bool,
    path: String,
    prefix: String,
    preserve_host: bool,
}

/// `Configuration.proxyPassMappings()` as text: the list set on the instance (even an empty one), else `proxyPass`;
/// `None` when blank. Asked of every unmatched request, twice: nothing is copied while neither is set.
fn proxy_pass_text(state: &State) -> Option<String> {
    use crate::config::Hot;
    let set = |hot: Hot| state.config.read_hot(hot, |v| v.is_some());
    if !set(Hot::ProxyPassMappings) && !set(Hot::ProxyPass) {
        return None;
    }
    state.config.property("proxyPassMappings").or_else(|| state.config.property("proxyPass")).filter(|v| !v.trim().is_empty())
}

/// The first mapping whose prefix the request path starts with.
pub fn proxy_pass_mapping(state: &State, request: &HttpRequest) -> Option<ProxyPass> {
    // `Configuration.proxyPassMappings()`: the list set on the instance (even an empty one), else `proxyPass`
    let mappings = proxy_pass_text(state)?;
    let mappings: Value = serde_json::from_str(&mappings).ok()?;
    mappings.as_array()?.iter().find_map(|m| {
        let prefix = m.get("pathPrefix")?.as_str()?;
        if !request.path.starts_with(prefix) {
            return None;
        }
        let target_uri = m.get("targetUri")?.as_str()?.to_string();
        let (scheme, rest) = target_uri.split_once("://")?;
        let secure = scheme.eq_ignore_ascii_case("https");
        let (authority, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) if !h.is_empty() => (h.to_string(), p.parse().ok()?),
            _ => (authority.to_string(), if secure { 443 } else { 80 }),
        };
        let path = path.trim_end_matches('/').to_string();
        Some(ProxyPass {
            target_uri: target_uri.clone(),
            host: host.trim_start_matches('[').trim_end_matches(']').to_string(),
            port,
            secure,
            path,
            prefix: prefix.to_string(),
            preserve_host: m.get("preserveHost").and_then(Value::as_bool).unwrap_or(false),
        })
    })
}

/// The target and the `URISyntaxException` message of the first mapping the request path falls under, when
/// `URI.create` refuses its `targetUri`: `handleProxyPass` throws there, before anything is forwarded.
pub fn proxy_pass_refusal(state: &State, request: &HttpRequest) -> Option<(String, String)> {
    let mappings = proxy_pass_text(state)?;
    let mappings: Value = serde_json::from_str(&mappings).ok()?;
    let first = mappings.as_array()?.iter().find(|m| m.get("pathPrefix").and_then(Value::as_str).is_some_and(|prefix| request.path.starts_with(prefix)))?;
    let target = first.get("targetUri")?.as_str()?;
    crate::java_uri::parse(target).err().map(|message| (target.to_string(), message))
}

impl ProxyPass {
    pub fn address(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    /// The target's port.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The target's host.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The path a request under this mapping's prefix is sent to: the prefix replaced by the target's path.
    pub fn target_path(&self, path: &str) -> String {
        let remainder = &path[self.prefix.len()..];
        if remainder.is_empty() {
            if self.path.is_empty() { "/".to_string() } else { self.path.clone() }
        } else if remainder.starts_with('/') || self.path.ends_with('/') {
            format!("{}{remainder}", self.path)
        } else {
            format!("{}/{remainder}", self.path)
        }
    }

    /// `handleProxyPass`: the rewritten request (prefix replaced, hop-by-hop headers dropped, `Host` adjusted unless
    /// preserved) sent to the target.
    pub async fn forward(&self, state: &State, request: &HttpRequest) -> Forwarded {
        let path = self.target_path(&request.path);
        let mut forwarded = request.clone();
        forwarded.headers.retain(|(k, _)| !HOP_BY_HOP_REQUEST.iter().any(|h| k.eq_ignore_ascii_case(h)));
        forwarded.path = path;
        forwarded.secure = self.secure;
        if !self.preserve_host && state.config.bool_property("forwardAdjustHostHeader", true) {
            set_host(&mut forwarded, host_header(&self.host, self.port, self.secure));
        }
        let identity = self.secure.then(|| state.forward_identity(&self.host)).flatten();
        let mut marked = forwarded.clone();
        crate::forward_loop::mark(state, request, &mut marked);
        let out = Outbound {
            http2: unmatched_http2(state, request, self.secure),
            may_stream: may_stream(state, None),
            ..outbound(&marked)
        };
        let result = send_via(state, &self.host, self.port, self.secure, &out, identity, client::connect_timeout(&state.config)).await;
        // `handleProxyPassFailure` answers a header-limit refusal and, on master, a failure upstream names (7a8b8c424;
        // `returnedUpstreamFailureReason`) with the reason as the body, as the forward route does.
        finish(None, forwarded, result, None, None)
    }
}

/// `HttpForwardAction.sendRequest`'s upstream call for a matched forward action: the circuit breaker of `host:port`
/// first (open: its own 503, sending nothing), then [`send_via`], again after a transient failure for an idempotent
/// `method` (`ForwardRetryPolicy`: up to `forwardProxyRetryCount` retries, the n-th after n back-offs), the final
/// outcome fed back into the breaker. `method` is the request's own (`getMethod("")`): one without a method goes
/// out as GET but is not retried.
/// `ForwardRetryPolicy.execute` chains retries (rather than returning the first attempt's future) for `method`.
fn retries_apply(state: &State, method: &str) -> bool {
    crate::forward_breaker::retry_count(&state.config) > 0 && crate::forward_breaker::is_idempotent(method)
}

async fn send_forward(
    state: &State,
    received: &HttpRequest,
    method: &str,
    host: &str,
    port: u16,
    secure: bool,
    out: &Outbound,
) -> Result<Upstream, client::Error> {
    use crate::forward_breaker as breaker;
    let identity = || secure.then(|| state.forward_identity(host)).flatten();
    let timeout = client::connect_timeout(&state.config);
    // `ForwardCircuitBreaker.keyFor`: no key (and no breaker) without a host.
    let key = (!host.is_empty()).then(|| format!("{host}:{port}"));
    let breakers = &state.forward_connections.breaker;
    // `HttpForwardAction.sendRequest`: a forward back to this server is refused before the breaker is asked
    if let Some(body) = crate::forward_loop::refuse(state, received, crate::forward_loop::Route::Forward) {
        return Ok(crate::forward_loop::loop_detected(body));
    }
    if let Some(key) = &key && !breakers.allow(&state.config, key) {
        return Ok(breaker::open_response(key));
    }
    let retries = if breaker::is_idempotent(method) { breaker::retry_count(&state.config) } else { 0 };
    let (mut result, mut unreachable) = send_via_reporting(state, host, port, secure, out, identity(), timeout).await;
    let mut attempt = 1;
    while attempt <= retries && breaker::is_transient(&result, unreachable) {
        drop(result);
        let delay = breaker::retry_backoff(&state.config) * attempt;
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
        (result, unreachable) = send_via_reporting(state, host, port, secure, out, identity(), timeout).await;
        attempt += 1;
    }
    if let Some(key) = &key {
        if breaker::is_neutral(&result, unreachable) {
            breakers.neutral(&state.config, key);
        } else if breaker::is_transient(&result, unreachable) {
            breakers.failure(state, key);
        } else {
            breakers.success(state, key);
        }
    }
    result
}

/// `client::send_pooled`, with a gRPC request converted to JSON (`GrpcForwardTranslator`) re-encoded for the
/// upstream and its response decoded back.
async fn send_via(
    state: &State,
    host: &str,
    port: u16,
    secure: bool,
    out: &Outbound,
    identity: Option<crate::tls::ForwardIdentity>,
    timeout: std::time::Duration,
) -> Result<Upstream, client::Error> {
    send_via_reporting(state, host, port, secure, out, identity, timeout).await.0
}

/// [`send_via`], and whether the forward failed to reach its upstream proxy (`UpstreamProxyUnreachableException`,
/// told by the client as [`client::ClientEvent::ProxyUnreachable`]), which is neither retried nor counted by the
/// circuit breaker.
async fn send_via_reporting(
    state: &State,
    host: &str,
    port: u16,
    secure: bool,
    out: &Outbound,
    identity: Option<crate::tls::ForwardIdentity>,
    timeout: std::time::Duration,
) -> (Result<Upstream, client::Error>, bool) {
    // the property that set the upstream proxy that could not be reached
    let proxy_unreachable: std::sync::Mutex<Option<&'static str>> = std::sync::Mutex::new(None);
    // `Scheduler.boundedForwardResponse` (upstream 89d8a61c9, after 8.0.0): the wait for the response head is bounded
    // by `maxFutureTimeoutInMillis` whatever the read timeout (none for `maxSocketTimeout` 0), then a `TimeoutException`.
    let backstop = std::time::Duration::from_millis(state.config.int_property("maxFutureTimeoutInMillis", 90_000).max(1) as u64);
    let on_tls = |event: &client::ClientEvent| match event {
        // The client's TLS context, built with its first TLS channel (`HttpClientInitializer.initChannel`, before it
        // connects), loads the CA and logs the leaf its factory generated.
        client::ClientEvent::TlsConnecting => {
            if let Some(tls) = state.tls.as_ref() {
                tls.client_context_needed(state);
            }
        }
        // `recordForwardUpstreamProtocol`'s DEBUG entry for each new upstream connection
        client::ClientEvent::Negotiated { host, http2 } => {
            if crate::log::debug_enabled(state) {
                let entry = crate::recorded::LogEntry::at(crate::recorded::Level::Debug, "forward upstream connection to {} negotiated {}")
                    .args([crate::recorded::Arg::from(host.to_string()), crate::recorded::Arg::from(if *http2 { "http2" } else { "http1_1" }.to_string())]);
                crate::log::entry(state, &entry);
                state.log.message(entry);
            }
        }
        // `NettyHttpClient.proxyFailure`: an upstream proxy that could not be reached is a configuration problem,
        // logged once per proxy address for the server's lifetime, however many forwards through it fail.
        client::ClientEvent::ProxyUnreachable { proxy, property, cause } => {
            *proxy_unreachable.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(property);
            proxy_failure(state, proxy, property, cause);
        }
    };
    let result = match crate::grpc_plane::forward_request(state, out, secure) {
        // Boxed: the client's future is large, and a forward served inside a CONNECT tunnel nests it deep.
        Some((encoded, service, method)) => tokio::time::timeout(backstop, client::on_tls(&on_tls, client::send_pooled(&state.config, &state.forward_connections, host, port, secure, &encoded, identity, timeout)))
            .await
            .unwrap_or(Err(client::Error::FutureTimeout))
            .map(|upstream| crate::grpc_plane::forward_response(state, upstream, &service, &method)),
        None => tokio::time::timeout(backstop, client::on_tls(&on_tls, client::send_pooled(&state.config, &state.forward_connections, host, port, secure, out, identity, timeout))).await.unwrap_or(Err(client::Error::FutureTimeout)),
    };
    // `NettyHttpClient` slow-request flagging: a forward that took longer than `slowRequestThresholdMillis` (read live,
    // so a runtime update counts) bumps the counter and warns about the method and path it was sent with.
    if let Ok(upstream) = &result {
        let threshold = state.config.int_property("slowRequestThresholdMillis", 0);
        let total = upstream.timing.response_received - upstream.timing.request_started;
        if threshold > 0 && total > threshold {
            if crate::metrics::enabled(&state.config) {
                state.config.metrics.slow_request();
            }
            let path = out.target.split('?').next().unwrap_or_default();
            let entry = recorded::LogEntry::new(recorded::Kind::Warn, "slow forwarded request {} took {}ms (threshold {}ms)")
                .args([format!("{} {path}", out.method), total.to_string(), threshold.to_string()]);
            crate::log::warn_event(state, entry);
        }
    }
    // `StreamingAwareHttpObjectAggregator.switchToStreamingMode`: a forward's client relays a streaming response as it
    // arrives (seen at DEBUG beside a streamed forward over the direct-memory limit)
    if let Ok(upstream) = &result && upstream.stream.is_some() && crate::log::debug_enabled(state) {
        let entry = recorded::LogEntry::at(recorded::Level::Debug, "switching response to streaming relay (relayOnly={})").args([recorded::Arg::from(serde_json::json!(false))]);
        crate::log::entry(state, &entry);
        state.log.message(entry);
    }
    // `HttpClientHandler.exceptionCaught`: the read timeout reaches the client's pipeline, which logs it (about no
    // request) before the response future fails.
    // A content the decompressor cannot decode closes the channel mid-aggregation, which the handler logs first.
    let caught = match &result {
        Err(error @ client::Error::ReadTimeout) => Some(error.exception_message().unwrap_or_else(|| "null".into())),
        Err(client::Error::Decode(_)) => Some("Channel closed while still aggregating message".to_string()),
        _ => None,
    };
    // Netty's direct-memory limit: the pool's own ERROR, the `OutOfDirectMemoryError` as the client's
    // pipeline and then the scheduler log it, before the aggregator's closed channel.
    if let Err(error @ client::Error::DirectMemory { channel, .. }) = &result {
        let reached = format!("direct memory limit (io.netty.maxDirectMemory) reached - raise it with -XX:MaxDirectMemorySize or -Dio.netty.maxDirectMemory - closing connection {channel} - {}", error.exception_message().unwrap_or_default());
        crate::log::error_event(state, recorded::LogEntry::at(recorded::Level::Error, &reached));
        for _ in 0..2 {
            let thrown = error.exception_string();
            crate::log::error(state, &thrown);
            state.log.message(recorded::LogEntry::new(recorded::Kind::Exception, &thrown));
        }
    }
    let caught = match (&result, caught) {
        (Err(client::Error::DirectMemory { .. }), _) => Some("Channel closed while still aggregating message".to_string()),
        (_, caught) => caught,
    };
    if let Some(caught) = caught && !matches!(state.log_level.as_str(), "OFF" | "ERROR") {
        let text = format!("exception caught by HTTP client handler - {caught}");
        crate::log::warn(state, &text);
        state.log.message(recorded::LogEntry::at(recorded::Level::Warn, text));
    }
    let proxy_unreachable = proxy_unreachable.into_inner().unwrap_or_else(std::sync::PoisonError::into_inner);
    // `UpstreamProxyUnreachableException` (upstream 48b7e14d2, 9.1.0): reads as its cause, and names the property in
    // the 502's reason
    let result = match (result, proxy_unreachable) {
        (Err(cause), Some(property)) => Err(client::Error::ProxyUnreachable { property, cause: Box::new(cause) }),
        (result, _) => result,
    };
    (result, proxy_unreachable.is_some())
}

/// `NettyHttpClient.proxyFailure`: an upstream proxy that could not be reached ([`client::ClientEvent::ProxyUnreachable`],
/// from a forward or a binary relay) is a configuration problem, a WARN once per proxy address for the server's lifetime.
pub fn proxy_failure(state: &State, proxy: &str, property: &str, cause: &client::Error) {
    if state.forward_connections.first_unreachable_report(proxy) {
        let entry = recorded::LogEntry::at(recorded::Level::Warn, "upstream proxy{}set by{}could not be reached, so forwards through it fail and are neither retried nor counted against their target's circuit breaker; check the proxy is running and its address is correct (logged once per proxy):{}")
            .args([recorded::Arg::from(proxy.to_string()), recorded::Arg::from(property.to_string()), recorded::Arg::from(cause.fault_description())]);
        crate::log::warn_event(state, entry);
    }
}

const LOOP_HEADER: &str = "x-forwarded-by";
const EXPLORATORY_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(1000);

/// A request in input JSON form (`HttpRequestDTO`) as the model object it describes.
pub fn request_from_json(v: &Value) -> HttpRequest {
    let mut request = HttpRequest { method: String::new(), ..HttpRequest::default() };
    apply_request_override(&mut request, v);
    request
}

/// `NettyHttpClient.sendRequest`: `request` (input JSON form) sent to its socket address, else its `Host`.
pub async fn send_json(state: &State, request: &Value) -> Result<client::Upstream, client::Error> {
    let (host, port, secure, out) = outbound_json(request);
    send_via(state, &host, port, secure, &out, secure.then(|| state.forward_identity(&host)).flatten(), client::connect_timeout(&state.config)).await
}

/// `HttpActionHandler.refusedWebhook`: why `InetAddressValidator.validateForwardTarget` refuses a webhook (input JSON
/// form), checked on the destination it names (`unresolvedSocketAddressFromHostHeader`: the socket address's host,
/// else the `Host` header's); a webhook that names none is not refused here. The refusal is logged (WARN) as
/// `<label> webhook blocked by SSRF policy:…` about `trigger`.
pub async fn refused_webhook(state: &State, webhook: &Value, trigger: &HttpRequest, label: &str) -> Option<String> {
    let socket_host = webhook.get("socketAddress").and_then(|s| s.get("host")).and_then(Value::as_str).map(str::to_string);
    let host = socket_host.or_else(|| {
        let request = request_from_json(webhook);
        request.first_header("host").filter(|h| !h.trim().is_empty()).map(|h| crate::replay::split_host_port(h).0)
    })?;
    let reason = crate::ws_relay::blocked(state, &host).await?;
    let entry = recorded::LogEntry::new(recorded::Kind::Warn, format!("{label} webhook blocked by SSRF policy:{{}}")).args([reason.clone()]);
    log_about(state, LogLevel::Warn, entry, trigger);
    Some(reason)
}

/// A request in input JSON form as `NettyHttpClient` sends it: its destination (the socket address, else its `Host`)
/// and the request as written.
pub fn outbound_json(request: &Value) -> (String, u16, bool, Outbound) {
    let target = request_from_json(request);
    let (host, port, secure) = destination(&target, Some(request));
    (host, port, secure, outbound(&target))
}

/// `outbound` for the request of a matched forward action: `HttpForwardAction.sendRequest` runs every one of them through
/// `HopByHopHeaderFilter.onRequest` first, and marks it with the forward loop guard's entries (`markForwarded`): those
/// `received` came with plus this instance's.
fn outbound_marked(state: &State, received: &HttpRequest, r: &HttpRequest) -> Outbound {
    let mut filtered = r.clone();
    crate::forward_loop::mark(state, received, &mut filtered);
    filtered.headers.retain(|(k, _)| !HOP_BY_HOP_REQUEST.iter().any(|h| k.eq_ignore_ascii_case(h)));
    outbound(&filtered)
}

fn outbound(r: &HttpRequest) -> Outbound {
    const REPLACED: &[&str] = &["content-length", "transfer-encoding", "host", "accept-encoding", "connection"];
    let mut headers: Vec<(String, String)> = Vec::new();
    for (name, values) in &r.headers {
        if REPLACED.iter().any(|h| name.eq_ignore_ascii_case(h)) || (!r.cookies.is_empty() && name.eq_ignore_ascii_case("cookie")) {
            continue;
        }
        for v in values {
            headers.push((name.to_string(), v.to_string()));
        }
    }
    if let Some(host) = r.first_header("host").filter(|h| !h.trim().is_empty()) {
        headers.push(("host".into(), host.to_string()));
    }
    // the client's codings, less any the forward client could not decode on the way back
    let accept_encoding: Vec<&str> = r
        .headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("accept-encoding"))
        .flat_map(|(_, values)| if values.is_empty() { vec![""] } else { values.iter().collect() })
        .collect();
    if let Some(forwarded) = forwarded_accept_encoding(&accept_encoding) {
        headers.push(("accept-encoding".into(), forwarded));
    }
    let body = encoded_body(r);
    let decoded_body = (body != r.body).then(|| r.body.clone());
    headers.push(("content-length".into(), body.len().to_string()));
    let close = r.first_header("connection").is_some_and(|c| c.eq_ignore_ascii_case("close"));
    headers.push(("connection".into(), if close { "close" } else { "keep-alive" }.into()));
    if !r.cookies.is_empty() {
        let encoded = r.cookies.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("; ");
        headers.push(("cookie".into(), encoded));
    }
    // `HttpRequestEncoder.encodeInitialLine`: an empty URI goes out as `/`.
    let mut target = request::uri(r);
    if target.is_empty() || target.starts_with('?') {
        target.insert(0, '/');
    }
    // `request.getMethod("GET")`: a request without a method (a template that set none) goes out as GET.
    let method = if r.method.trim().is_empty() { "GET".to_string() } else { r.method.clone() };
    Outbound { method, target, headers, body, http2: false, may_stream: false, decoded_body }
}

/// `ForwardedAcceptEncoding.forwarded`: the `Accept-Encoding` a forwarded request carries, from the client's field
/// values in order (an empty field counts as one empty value). `None` when there are none, so none is sent; else the
/// elements in order with their parameters, less those in a coding the forward client does not decode
/// (`BoundedZstdHttpContentDecompressor.decodes`: the image has zstd but not Brotli), with `*` replaced by the codings
/// it covers that are decoded and not named elsewhere, or `identity` when no element left has a q-value above zero.
fn forwarded_accept_encoding(values: &[&str]) -> Option<String> {
    // the registered codings a "*" can stand for; each is kept only if decoded and not named elsewhere
    const WILDCARD_CODINGS: &[&str] = &["gzip", "deflate", "br", "zstd", "identity"];
    fn coding(element: &str) -> String {
        element.split_once(';').map_or(element, |(c, _)| c).trim().to_lowercase()
    }
    // RFC 9110 section 8.4.1 has x-gzip and x-deflate mean gzip and deflate, so naming one covers the other for "*"
    fn canonical(coding: String) -> String {
        match coding.as_str() {
            "x-gzip" => "gzip".into(),
            "x-deflate" => "deflate".into(),
            _ => coding,
        }
    }
    fn kept(coding: &str) -> bool {
        matches!(coding, "identity" | "gzip" | "x-gzip" | "deflate" | "x-deflate" | "snappy" | "zstd")
    }
    // An element is acceptable when its q-value is above zero; an unreadable one is left for the upstream to judge.
    fn acceptable(parameters: &str) -> bool {
        for parameter in parameters.split(';') {
            let trimmed = parameter.trim();
            if trimmed.len() > 2 && trimmed.is_char_boundary(2) && trimmed[..2].eq_ignore_ascii_case("q=") {
                return java_parse_double(trimmed[2..].trim()).is_none_or(|q| q > 0.0);
            }
        }
        true
    }
    if values.is_empty() {
        return None;
    }
    let elements: Vec<&str> = values.iter().flat_map(|v| v.split(',')).map(str::trim).filter(|e| !e.is_empty()).collect();
    let named: std::collections::HashSet<String> = elements.iter().map(|e| canonical(coding(e))).collect();
    let mut forwarded: Vec<String> = Vec::new();
    let mut any_acceptable = false;
    for element in &elements {
        let coding = coding(element);
        let parameters = element.find(';').map_or("", |i| &element[i..]);
        if coding == "*" {
            for covered in WILDCARD_CODINGS.iter().filter(|c| !named.contains(**c) && kept(c)) {
                forwarded.push(format!("{covered}{parameters}"));
                any_acceptable |= acceptable(parameters);
            }
        } else if kept(&coding) {
            forwarded.push(element.to_string());
            any_acceptable |= acceptable(parameters);
        }
    }
    Some(if any_acceptable { forwarded.join(", ") } else { "identity".into() })
}

/// `Double.parseDouble`: surrounding whitespace, a sign, `Infinity`/`NaN`, a trailing `d`/`f`, decimal or exponent
/// notation (hexadecimal floats are not read). `None` is its `NumberFormatException`.
fn java_parse_double(text: &str) -> Option<f64> {
    let t = text.trim_matches(|c: char| c <= ' ');
    let (sign, body) = match t.as_bytes().first() {
        Some(b'-') => (-1.0, &t[1..]),
        Some(b'+') => (1.0, &t[1..]),
        _ => (1.0, t),
    };
    match body {
        "Infinity" => return Some(sign * f64::INFINITY),
        "NaN" => return Some(f64::NAN),
        _ => {}
    }
    let body = body.strip_suffix(['d', 'D', 'f', 'F']).unwrap_or(body);
    if body.is_empty() || !body.chars().all(|c| c.is_ascii_digit() || matches!(c, '.' | 'e' | 'E' | '+' | '-')) {
        return None;
    }
    body.parse::<f64>().ok().map(|n| sign * n)
}

/// The body as sent upstream in the request's `Content-Encoding` (upstream cc8fb880a, after 8.0.0; see
/// `docs/divergences.md`): the bytes as received while the body is the one decoded from them
/// (`markBodyAsReceived`), else the body encoded by the first `Content-Encoding` value, compared whole, when it is a
/// coding the server decodes (`BodyContentEncodingEncoder.encodeBody`); any other coding was never decoded, so the
/// body is still in it and goes out as it is.
fn encoded_body(r: &HttpRequest) -> bytes::Bytes {
    use std::io::Write;
    let coding = r.headers.first("content-encoding").map(|c| c.trim().to_ascii_lowercase());
    let Some(coding) = coding.filter(|_| !r.body.is_empty()) else { return r.body.clone() };
    if let Some(original) = &r.original_body {
        let mut headers = crate::request::Headers::new();
        headers.push_entry("content-encoding", [coding.as_str()]);
        let received = HttpRequest { headers, body: original.clone(), ..HttpRequest::default() };
        if crate::handler::decode(&received, usize::MAX).ok().flatten().is_some_and(|decoded| decoded == r.body) {
            return original.clone();
        }
    }
    let encoded = match coding.as_str() {
        "gzip" | "x-gzip" => {
            let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            encoder.write_all(&r.body).and_then(|_| encoder.finish())
        }
        "deflate" | "x-deflate" => {
            let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
            encoder.write_all(&r.body).and_then(|_| encoder.finish())
        }
        // snappy as one raw block (`SnappyBlock`, what remote-write senders use), unless the received body was framed.
        "snappy" if r.original_body.as_ref().is_some_and(|o| o.starts_with(b"\xff\x06\x00\x00sNaPpY")) => {
            let mut encoder = snap::write::FrameEncoder::new(Vec::new());
            encoder.write_all(&r.body).and_then(|_| encoder.into_inner().map_err(|e| std::io::Error::other(e.to_string())))
        }
        "snappy" => snap::raw::Encoder::new().compress_vec(&r.body).map_err(std::io::Error::other),
        // Netty's `ZstdEncoder()`: each 64 KiB block compressed on its own (`Zstd.compress`, level 3), one frame per
        // block.
        "zstd" => r.body.chunks(64 * 1024).map(|block| zstd::bulk::compress(block, 3)).collect::<Result<Vec<_>, _>>().map(|frames| frames.concat()),
        _ => return r.body.clone(),
    };
    encoded.map(bytes::Bytes::from).unwrap_or_else(|_| r.body.clone())
}

/// A response override as a streamed head takes it: without its `body` (`generateFromSchema` stays, as the log prints it).
fn head_only_override(o: &Value) -> Value {
    let mut o = o.clone();
    if let Some(m) = o.as_object_mut() {
        m.remove("body");
    }
    o
}

/// A response modifier as a streamed head takes it: without the JSON body patches, in its chain too.
fn head_only_modifier(m: &Value) -> Value {
    let mut m = m.clone();
    if let Some(o) = m.as_object_mut() {
        o.remove("jsonPatch");
        o.remove("jsonMergePatch");
        if let Some(Value::Array(chain)) = o.get_mut("modifiers") {
            for child in chain.iter_mut().filter(|c| !c.is_null()) {
                *child = head_only_modifier(child);
            }
        }
    }
    m
}

const FRAMING: &[&str] = &["content-length", "transfer-encoding", "connection", "keep-alive"];
/// `HopByHopHeaderFilter.responseHeadersToRemove`.
const HOP_BY_HOP: &[&str] = &["proxy-connection", "connection", "keep-alive", "transfer-encoding", "content-length", "te", "trailer", "upgrade"];

fn finish(state: Option<&State>, logged_request: HttpRequest, result: Result<Upstream, client::Error>, response_override: Option<&Value>, response_modifier: Option<&Value>) -> Forwarded {
    if result.as_ref().is_ok_and(|u| u.loop_detected) {
        return Forwarded { loop_detected: true, ..finish_inline(state, logged_request, result, None, None) };
    }
    finish_inline(state, logged_request, result, response_override, response_modifier)
}

fn finish_inline(state: Option<&State>, logged_request: HttpRequest, result: Result<Upstream, client::Error>, response_override: Option<&Value>, response_modifier: Option<&Value>) -> Forwarded {
    let mut result = result;
    if let Ok(upstream) = result.as_mut() && let Some(chunks) = upstream.stream.take() {
        // The override function runs on the streamed head (`StreamingBody`): its status and headers apply, a body
        // edit has nothing to act on and the relayed chunks are what the client gets and the log captures.
        let response_override = response_override.map(head_only_override);
        let response_modifier = response_modifier.map(head_only_modifier);
        let (response_override, response_modifier) = (response_override.as_ref(), response_modifier.as_ref());
        let head = Upstream { status: upstream.status, reason: upstream.reason.clone(), headers: upstream.headers.clone(), body: bytes::Bytes::new(), stream: None, timing: upstream.timing, ..Default::default() };
        let mut forwarded = finish(state, logged_request, Ok(head), response_override, response_modifier);
        // The head goes out chunked; the body follows as it arrives.
        forwarded.reply.chunk_size = Some(usize::MAX);
        forwarded.streaming = Some(Streaming {
            status: upstream.status,
            reason: upstream.reason.clone(),
            headers: upstream.headers.clone(),
            chunks,
            response_override: response_override.cloned(),
            response_modifier: response_modifier.cloned(),
            timing: upstream.timing,
            started: Instant::now() - std::time::Duration::from_millis((upstream.timing.response_received - upstream.timing.request_started).max(0) as u64),
            end: upstream.stream_end.clone(),
            observer: None,
        });
        return forwarded;
    }
    let started = Instant::now();
    let upstream = match result {
        Ok(u) => u,
        Err(e) => {
            // `badGatewayResponse().withBody(reason)` for a failure upstream names (after 8.0.0), else an empty 502.
            let (reply, logged_response) = match e.bad_gateway_body(true) {
                Some(reason) => (Reply { body: reason.clone().into(), ..Reply::status(502) }, json!({"statusCode": 502, "reasonPhrase": "Bad Gateway", "body": reason})),
                None => (Reply::status(502), json!({"statusCode": 502, "reasonPhrase": "Bad Gateway"})),
            };
            return Forwarded {
                reply,
                logged_request,
                logged_response,
                recorded: None,
                error: Some(e),
                ..Default::default()
            };
        }
    };
    // `HopByHopHeaderFilter.onResponse`: drop hop-by-hop headers, but when that leaves nothing the response
    // keeps all of its headers.
    let mut all: MultiMap = MultiMap::new();
    for (k, v) in &upstream.headers {
        request::push(&mut all, k, v.clone());
    }
    let filtered: MultiMap = all.iter().filter(|(k, _)| !HOP_BY_HOP.iter().any(|h| k.eq_ignore_ascii_case(h))).cloned().collect();
    let kept_all = filtered.is_empty();
    let mut headers = if kept_all { all } else { filtered };
    let mut status = upstream.status;
    let mut reason = upstream.reason.clone();
    let mut body = upstream.body.clone();
    // The override body's own content type, written by the encoder when the response has no `Content-Type`.
    let mut body_content_type = None;
    // `HttpResponse.update`: an override body replaces the response's body model, which the log then prints (in its
    // echoed form) instead of the bytes; `None` when the body is still the upstream's bytes.
    let mut body_model: Option<Value> = None;
    let mut file_error: Option<action::FileBodyError> = None;
    // The body as the model was given (`HttpResponse.withBody`), which the recorded expectation's input form keeps.
    let mut input_override: Option<Value> = None;
    // The upstream body's own content type, fixed when `bytesToBody` decoded it: later header edits (override or
    // modifier) change the response's `Content-Type`, never the body model's.
    let decoded_content_type = request::first(&headers, "content-type").map(str::to_string);
    if let Some(o) = response_override {
        // `HttpResponse.update`: each of the two only when the override sets it, so an override status keeps the
        // upstream's reason phrase.
        if let Some(s) = o.get("statusCode").and_then(Value::as_u64) {
            status = s as u32;
        }
        if let Some(r) = o.get("reasonPhrase").and_then(Value::as_str) {
            reason = r.to_string();
        }
        if let Some(h) = o.get("headers") {
            merge_map(&mut headers, h);
        }
        if let Some(b) = o.get("body").filter(|b| !b.is_null()) {
            // The stale upstream `content-length` goes, unless the override sets its own.
            if !o.get("headers").is_some_and(|h| entries(h).iter().any(|(k, vs)| k.eq_ignore_ascii_case("content-length") && vs.iter().any(|v| !v.trim().is_empty()))) {
                headers.retain(|(k, _)| !k.eq_ignore_ascii_case("content-length"));
            }
            let mut respond = action::respond(&json!({"body": b}));
            body_model = Some(canonical::response(&json!({"body": b})).get("body").cloned().unwrap_or(Value::Null));
            input_override = Some(b.clone());
            // Encoded against the merged response's `Content-Type` (`BodyDecoderEncoder.bodyToBytes`).
            let (bytes, content_type) = action::response_body(b, request::first(&headers, "content-type"));
            respond.reply.body = bytes;
            body_content_type = content_type.filter(|_| respond.file.is_none());
            body = match &respond.file {
                // A `FILE` body is served as the file's contents (`FileBodyMaterialiser`).
                Some(file) => match file.materialise(state, &logged_request) {
                    Ok(Ok((bytes, content_type))) => {
                        body_model = Some(materialised_file_model(file, &bytes));
                        // Written by the encoder, not part of the logged response's headers.
                        body_content_type = content_type;
                        bytes
                    }
                    Err(e) => {
                        file_error = Some(e);
                        respond.reply.body
                    }
                    _ => respond.reply.body,
                },
                None => respond.reply.body,
            };
        }
    }
    let mut leaves = Vec::new();
    if file_error.is_some() {
        // `writeForwardActionResponse` reads the file after the override and modifier have run, and its failure
        // replaces the whole response with `fileBodyErrorResponse()`
        status = 500;
        reason = "Internal Server Error".into();
        headers = MultiMap::new();
        body = bytes::Bytes::from_static(b"Error reading file for response body");
        body_content_type = None;
        body_model = None;
        input_override = None;
    } else if let Some(m) = response_modifier {
        applied_leaves(m, status, &mut headers.clone(), &logged_request, &mut leaves);
    }
    // The last patch's `JsonBody`: its text (what `getBodyAsString` returns) and charset, encoded once the chain is
    // done (`BodyDecoderEncoder.bodyToBytes`).
    let mut patched_body: Option<(String, Option<String>)> = None;
    for &m in &leaves {
        if let Some(h) = m.get("headers") {
            modify_map(&mut headers, h);
        }
        // `applyBodyPatch` reads `getBodyAsString()`: a binary body's is its base64, which never parses as JSON.
        let binary = match &body_model {
            Some(model) => model.get("type").and_then(Value::as_str) == Some("BINARY"),
            None => recorded::body_json(&body, decoded_content_type.as_deref(), BodyForm::Recorded).is_some_and(|b| b.get("type").and_then(Value::as_str) == Some("BINARY")),
        };
        // The body model's content type (`existingBody.getContentType()`): a patched body's charset, else the override
        // body model's, else the upstream body's as decoded; never the current `Content-Type` header.
        let charset = match (&patched_body, &body_model) {
            (Some((_, charset)), _) => charset.clone(),
            (None, model) => {
                let existing = match model {
                    Some(model) => model_content_type(model),
                    None => decoded_content_type.clone(),
                };
                existing.as_deref().and_then(|ct| crate::media_type::MediaType::parse(Some(ct)).charset_or_default().map(str::to_string))
            }
        };
        // A string body model's text is its value, whatever bytes it was encoded to.
        let string_model = body_model.as_ref().and_then(|model| match model {
            Value::String(s) => Some(s.clone()),
            _ if model.get("type").and_then(Value::as_str) == Some("STRING") => model.get("string").and_then(Value::as_str).map(str::to_string),
            _ => None,
        });
        let text = match (&patched_body, string_model) {
            (Some((text, _)), _) => text.clone(),
            (None, Some(text)) => text,
            (None, None) => crate::media_type::decode(&body, charset.as_deref().or(Some("utf-8"))),
        };
        if let Some(patched) = (!binary).then(|| apply_body_patches(&text, m)).flatten() {
            // `new JsonBody(patchedJson, charset, DEFAULT_MATCH_TYPE)`: `application/json` with the old body's
            // charset (none without a content type).
            let content_type = charset.as_ref().map(|c| format!("application/json; charset={c}"));
            let mut model = json!({"type": "JSON", "json": patched});
            if let Some(ct) = &content_type {
                model["contentType"] = ct.clone().into();
            }
            body_model = Some(canonical::response(&json!({"body": model})).get("body").cloned().unwrap_or(Value::Null));
            // No content type at all (not the JSON default, which the canonical form cannot tell apart): kept as
            // `null` in the input form, for the formats that print the body's content type.
            if content_type.is_none() {
                model["contentType"] = Value::Null;
            }
            input_override = Some(model);
            body_content_type = content_type;
            patched_body = Some((patched, charset));
        }
    }
    if let Some((text, charset)) = &patched_body {
        // `bodyToBytes`: the body's charset, else the final `Content-Type`'s (or its default), else ISO-8859-1.
        let header_charset = request::first(&headers, "content-type").and_then(|ct| crate::media_type::MediaType::parse(Some(ct)).charset_or_default().map(str::to_string));
        body = bytes::Bytes::from(crate::media_type::encode(text, Some(charset.as_deref().or(header_charset.as_deref()).unwrap_or("iso-8859-1"))));
    }
    let reason = if reason.is_empty() {
        crate::status::reason_phrase(status)
    } else {
        reason
    };

    let mut reply = Reply::status(status);
    reply.reason = Some(reason.clone());
    // Framing headers kept by the filter are recomputed by the writer, except a `content-length` the response model
    // still carries because the filter kept every header: the encoder writes it as it is, stale after a body patch
    // (`applyBodyPatch` leaves it), with the whole body after it. A `transfer-encoding` kept that way
    // (Netty's invalid message keeps one that is not exactly `chunked`) goes to the writer too, which
    // frames by it.
    let kept = |k: &str| {
        !FRAMING.iter().any(|f| k.eq_ignore_ascii_case(f)) || (kept_all && (k.eq_ignore_ascii_case("content-length") || k.eq_ignore_ascii_case("transfer-encoding")))
    };
    for (k, vs) in headers.iter().filter(|(k, _)| kept(k)) {
        for v in vs {
            reply.headers.push((k.clone(), v.clone()));
        }
    }
    reply.body = body.clone();
    reply.default_content_type = body_content_type;

    // A decoded gRPC response is a `StringBody`: recorded as text, not by its `application/grpc` content type.
    let content_type = request::first(&headers, "content-type").map(str::to_string).filter(|_| !upstream.text_body);
    // `effectiveForwardLatencyMs`: the client's measured round trip, else the time spent here.
    let total = upstream.timing.response_received - upstream.timing.request_started;
    let response_time = match upstream.response_time {
        // `fileBodyErrorResponse()` has no timing: the wait for the already completed future, 0 ms
        _ if file_error.is_some() => started.elapsed().as_millis() as i64,
        Some(ms) => ms,
        None if upstream.timing.request_started > 0 && total >= 0 => total,
        None => started.elapsed().as_millis() as i64,
    };
    let mut logged_headers = vec![("x-mockserver-response-time-ms".to_string(), vec![response_time.to_string()])];
    logged_headers.extend(headers.iter().cloned());
    for (k, v) in &upstream.streamed_headers {
        request::push(&mut logged_headers, k, v.clone());
    }
    // `FullHttpResponseToMockServerHttpResponse.setCookies`: the response model's cookies come from `Set-Cookie`
    // (its first pair) and `Cookie` (every pair) headers, in header order.
    let mut cookies: Vec<(String, String)> = Vec::new();
    for (name, values) in &headers {
        let pairs: Vec<(String, String)> = if name.eq_ignore_ascii_case("set-cookie") {
            values.iter().filter_map(|v| v.split(';').next()?.split_once('=').map(|(n, v)| (n.trim().to_string(), unwrap_cookie_value(v)))).collect()
        } else if name.eq_ignore_ascii_case("cookie") {
            // `ServerCookieDecoder`: each header's cookies as a set ordered by name, the first of a repeated name kept.
            values
                .iter()
                .flat_map(|v| {
                    let mut decoded: Vec<(String, String)> = Vec::new();
                    for (n, val) in v.split(';').filter_map(|p| p.split_once('=').map(|(n, v)| (n.trim().to_string(), unwrap_cookie_value(v)))) {
                        if !decoded.iter().any(|(k, _)| *k == n) {
                            decoded.push((n, val));
                        }
                    }
                    decoded.sort_by(|a, b| a.0.cmp(&b.0));
                    decoded
                })
                .collect()
        } else {
            continue;
        };
        for (n, v) in pairs {
            match cookies.iter_mut().find(|(k, _)| *k == n) {
                Some(existing) => existing.1 = v,
                None => cookies.push((n, v)),
            }
        }
    }
    for c in leaves.iter().filter_map(|m| m.get("cookies")) {
        modify_cookies(&mut cookies, c);
    }
    // `MockServerHttpResponseToFullHttpResponse.setCookies`: a cookie without a `Set-Cookie` header naming it
    // (with that value) gets one.
    for (n, v) in &cookies {
        let exists = reply.headers.iter().any(|(k, h)| {
            k.eq_ignore_ascii_case("set-cookie")
                && h.split(';').next().and_then(|p| p.split_once('=')).is_some_and(|(hn, hv)| hn.trim().eq_ignore_ascii_case(n) && unwrap_cookie_value(hv).eq_ignore_ascii_case(v))
        });
        if !exists {
            reply.headers.push(("set-cookie".into(), format!("{n}={v}")));
        }
    }
    let cookies_json = |list: bool| -> Option<Value> {
        (!cookies.is_empty()).then(|| {
            // An upstream's names and values are literal (upstream dc39a6a11, after 8.0.0).
            if list {
                Value::Array(cookies.iter().map(|(k, v)| json!({"name": recorded::literal_json(k), "value": recorded::literal_json(v)})).collect())
            } else {
                recorded::literal_cookies_value(&cookies)
            }
        })
    };
    // `HttpResponse.update` keeps an override's `generateFromSchema` on the response; a forward never synthesises from
    // it (the upstream's body stays), but the log and the recorded expectation print it.
    let generate_from_schema = response_override.and_then(|o| o.get("generateFromSchema")).filter(|g| !g.is_null() && file_error.is_none()).cloned();
    let response_json = |form: BodyForm| {
        let mut o = Map::new();
        o.insert("statusCode".into(), status.into());
        o.insert("reasonPhrase".into(), reason.clone().into());
        o.insert("headers".into(), recorded::literal_map_value(&logged_headers));
        if let Some(c) = cookies_json(false) {
            o.insert("cookies".into(), c);
        }
        let logged_body = match &body_model {
            Some(model) => typed_body_model(model, &body, form),
            None => recorded::body_json(&body, content_type.as_deref(), form),
        };
        if let Some(b) = logged_body {
            o.insert("body".into(), b);
        }
        if let Some(g) = &generate_from_schema {
            o.insert("generateFromSchema".into(), g.clone());
        }
        Value::Object(o)
    };
    let logged_response = response_json(BodyForm::Ordered);
    // Upstream appends the timing header to the headers it received.
    let mut input_headers = logged_headers[1..].to_vec();
    input_headers.push(logged_headers[0].clone());
    let mut input_response = Map::new();
    input_response.insert("statusCode".into(), status.into());
    input_response.insert("reasonPhrase".into(), reason.clone().into());
    input_response.insert("headers".into(), recorded::literal_list_form(&input_headers));
    if let Some(c) = cookies_json(true) {
        input_response.insert("cookies".into(), c);
    }
    let input_body = match (&body_model, &input_override) {
        (Some(model), Some(given)) => input_model_body(model, given, &body, content_type.as_deref()),
        _ => recorded::input_body(&body, content_type.as_deref()),
    };
    if let Some(b) = input_body {
        input_response.insert("body".into(), b);
    }
    if let Some(g) = &generate_from_schema {
        input_response.insert("generateFromSchema".into(), g.clone());
    }
    let recorded_input = json!({
        "httpRequest": recorded::input_request(&logged_request),
        "httpResponse": input_response,
        "times": {"remainingTimes": 1},
        "timeToLive": {"unlimited": true},
    });
    let recorded_expectation = json!({
        "httpRequest": recorded::ordered_with(&logged_request, BodyForm::Recorded),
        "httpResponse": response_json(BodyForm::Recorded),
        "id": uuid::Uuid::new_v4().to_string(),
        "priority": 0,
        "timeToLive": {"unlimited": true},
        "times": {"remainingTimes": 1},
    });
    Forwarded { reply, logged_request, logged_response, recorded: Some((recorded_expectation, recorded_input)), timing: (!upstream.untimed && file_error.is_none()).then_some(upstream.timing), file_error, ..Default::default() }
}

/// Netty's cookie decoders: a value wrapped in double quotes is unwrapped.
fn unwrap_cookie_value(value: &str) -> String {
    let value = value.trim();
    match value.strip_prefix('"').and_then(|v| v.strip_suffix('"')) {
        Some(inner) if value.len() >= 2 => inner.to_string(),
        _ => value.to_string(),
    }
}

/// `FileBodyMaterialiser.materialise` as a body model: a rendered template is a `StringBody` (with the file body's
/// content type, if any); a verbatim file is a `StringBody` under a string media type, else a `BinaryBody`.
fn materialised_file_model(file: &action::FileBody, bytes: &[u8]) -> Value {
    use base64::Engine;
    let content_type = file.content_type.as_deref().filter(|ct| !ct.trim().is_empty());
    let templated = matches!(file.template, Some(templates::Engine::Velocity | templates::Engine::Mustache));
    let mut body = if templated || (content_type.is_some() && crate::media_type::MediaType::parse(content_type).is_string()) {
        json!({"type": "STRING", "string": String::from_utf8_lossy(bytes)})
    } else {
        json!({"type": "BINARY", "base64Bytes": base64::engine::general_purpose::STANDARD.encode(bytes)})
    };
    if let Some(ct) = content_type {
        body["contentType"] = ct.into();
    }
    canonical::response(&json!({"body": body})).get("body").cloned().unwrap_or(Value::Null)
}

/// The content type of a body model (`BodyWithContentType.getContentType()`): its own, else a JSON or XML body's
/// default (`application/json; charset=utf-8`, `application/xml; charset=utf-8`); none for a string body.
fn model_content_type(model: &Value) -> Option<String> {
    match model.get("type").and_then(Value::as_str) {
        _ if model.get("contentType").and_then(Value::as_str).is_some() => model.get("contentType").and_then(Value::as_str).map(str::to_string),
        Some("JSON") => Some("application/json; charset=utf-8".into()),
        Some("XML") => Some("application/xml; charset=utf-8".into()),
        Some(t) if crate::model::BODY_TYPES.contains(&t) => None,
        _ if model.is_object() || model.is_array() => Some("application/json; charset=utf-8".into()),
        _ => None,
    }
}

/// An override (or patched) body in the recorded expectation's input form, which code formats and HAR/OpenAPI/
/// Postman/Bruno read: a JSON body keeps its text (as `JsonBody` does), a binary body its bytes, an empty string
/// body stays a body; other bodies are rendered from the bytes sent, typed by `Content-Type`.
fn input_model_body(model: &Value, given: &Value, sent: &[u8], content_type: Option<&str>) -> Option<Value> {
    if given.as_str() == Some("") {
        return Some(json!({"type": "STRING", "string": ""}));
    }
    let kind = model.get("type").and_then(Value::as_str).filter(|t| crate::model::BODY_TYPES.contains(t));
    match kind {
        Some("BINARY") => Some(model.clone()),
        // A JSON body: typed, or bare in its echoed form.
        Some("JSON") | None if model.is_object() || model.is_array() => {
            let text = match given.get("json") {
                Some(Value::String(text)) if given.get("type").and_then(Value::as_str) == Some("JSON") => text.clone(),
                _ => {
                    let charset = model_content_type(model).and_then(|ct| crate::media_type::MediaType::parse(Some(&ct)).charset_or_default().map(str::to_string));
                    crate::media_type::decode(sent, charset.as_deref().or(Some("utf-8")))
                }
            };
            let mut body = json!({"type": "JSON", "json": text});
            if let Some(ct) = model.get("contentType").filter(|_| kind.is_some()).or(given.get("contentType").filter(|ct| ct.is_null())) {
                body["contentType"] = ct.clone();
            }
            Some(body)
        }
        _ => recorded::input_body(sent, content_type),
    }
}

/// An override body model as the log prints it: its echoed form in `REQUEST_RESPONSES`; always typed in a recorded
/// expectation (a bare string as a `STRING` body with the bytes sent, any other bare value as a `JSON` body).
fn typed_body_model(model: &Value, sent: &[u8], form: BodyForm) -> Option<Value> {
    use base64::Engine;
    if model.is_null() {
        return None;
    }
    if form != BodyForm::Recorded {
        return Some(model.clone());
    }
    let typed = model.get("type").and_then(Value::as_str).is_some_and(|t| crate::model::BODY_TYPES.contains(&t));
    Some(match model {
        Value::String(s) => json!({"type": "STRING", "string": s, "rawBytes": base64::engine::general_purpose::STANDARD.encode(sent)}),
        _ if typed => model.clone(),
        _ => json!({"type": "JSON", "json": model}),
    })
}

fn entries(v: &Value) -> Vec<(String, Vec<String>)> {
    match canonical::multi_map(v) {
        Value::Object(o) => o
            .into_iter()
            .filter(|(k, _)| k != "keyMatchStyle")
            .map(|(k, vs)| (k, vs.as_array().into_iter().flatten().filter_map(|v| v.as_str().map(str::to_string)).collect()))
            .collect(),
        _ => Vec::new(),
    }
}

/// Override semantics: each named key replaces the existing one (in place) or is appended.
/// `replaceEntry`: an overridden key is removed and appended with its new values.
fn merge_map(map: &mut MultiMap, v: &Value) {
    for (k, vs) in entries(v) {
        map.retain(|(e, _)| !e.eq_ignore_ascii_case(&k));
        map.push((k, vs));
    }
}

/// Modifier semantics: `add` appends values, `replace` swaps existing keys' values, `remove` drops keys.
fn modify_map(map: &mut MultiMap, v: &Value) {
    if let Some(add) = v.get("add") {
        for (k, vs) in entries(add) {
            match map.iter_mut().find(|(e, _)| e.eq_ignore_ascii_case(&k)) {
                Some((_, existing)) => existing.extend(vs),
                None => map.push((k, vs)),
            }
        }
    }
    if let Some(replace) = v.get("replace") {
        for (k, vs) in entries(replace) {
            if let Some(existing) = map.iter_mut().find(|(e, _)| e.eq_ignore_ascii_case(&k)) {
                *existing = (k, vs);
            }
        }
    }
    if let Some(remove) = v.get("remove").and_then(Value::as_array) {
        for name in remove.iter().filter_map(Value::as_str) {
            map.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
        }
    }
}

/// `HttpResponseModifier.apply()`'s `jsonPatch`/`jsonMergePatch` fields: RFC 6902 JSON Patch, then RFC 7386 JSON
/// Merge Patch, applied to a forwarded response's body. A body that is empty or not valid JSON is left byte for
/// byte unchanged (the patch never runs). Both run in one try (`applyBodyPatch`): a JSON Patch that fails (a failing
/// RFC 6902 `test`, a missing path) leaves the body unchanged and the merge patch never runs.
/// Returns the patched body's JSON text (Jackson's compact form) when a patch ran, `None` when the body stays.
fn apply_body_patches(body: &str, m: &Value) -> Option<String> {
    let json_patch = m.get("jsonPatch").and_then(Value::as_array);
    let merge_patch = m.get("jsonMergePatch");
    if json_patch.is_none() && merge_patch.is_none() {
        return None;
    }
    if body.is_empty() {
        return None;
    }
    let Ok(mut node) = serde_json::from_str::<Value>(body) else {
        return None;
    };
    // A failed JSON Patch leaves the body untouched down to its original formatting.
    if let Some(ops) = json_patch {
        node = apply_json_patch(&node, ops)?;
    }
    if let Some(merge) = merge_patch {
        node = apply_merge_patch(node, merge);
    }
    serde_json::to_string(&node).ok()
}

/// RFC 6901 JSON Pointer resolution (`~1` -> `/`, `~0` -> `~`), read-only.
fn pointer_get<'a>(root: &'a Value, pointer: &str) -> Option<&'a Value> {
    if pointer.is_empty() {
        return Some(root);
    }
    let mut cur = root;
    for raw in pointer.trim_start_matches('/').split('/') {
        let tok = raw.replace("~1", "/").replace("~0", "~");
        cur = match cur {
            Value::Object(o) => o.get(&tok)?,
            Value::Array(a) => {
                if tok == "-" {
                    return None;
                }
                a.get(tok.parse::<usize>().ok()?)?
            }
            _ => return None,
        };
    }
    Some(cur)
}

/// Removes and returns the value at `pointer` (RFC 6902 `remove`/`move`'s source half).
fn pointer_remove(root: &mut Value, pointer: &str) -> Option<Value> {
    let (parent_ptr, last) = pointer.rsplit_once('/')?;
    let last = last.replace("~1", "/").replace("~0", "~");
    let parent = if parent_ptr.is_empty() { root } else { pointer_get_mut(root, parent_ptr)? };
    match parent {
        Value::Object(o) => o.shift_remove(&last),
        Value::Array(a) => {
            let idx: usize = last.parse().ok()?;
            (idx < a.len()).then(|| a.remove(idx))
        }
        _ => None,
    }
}

/// Inserts `value` at `pointer` (RFC 6902 `add`/`replace`/`move`/`copy`'s destination half): `add` into an object
/// sets the key, into an array inserts before the index (or appends on `-`); `replace` overwrites in place.
fn pointer_set(root: &mut Value, pointer: &str, value: Value, replace: bool) -> Option<()> {
    if pointer.is_empty() {
        *root = value;
        return Some(());
    }
    let (parent_ptr, last) = pointer.rsplit_once('/')?;
    let last = last.replace("~1", "/").replace("~0", "~");
    let parent = if parent_ptr.is_empty() { root } else { pointer_get_mut(root, parent_ptr)? };
    match parent {
        // `replace` needs the target to exist (json-patch's "no such path in target JSON document").
        Value::Object(o) => {
            if replace && !o.contains_key(&last) {
                return None;
            }
            o.insert(last, value);
        }
        Value::Array(a) => {
            if last == "-" {
                if replace {
                    return None;
                }
                a.push(value);
            } else {
                let idx: usize = last.parse().ok()?;
                if replace {
                    if idx >= a.len() {
                        return None;
                    }
                    a[idx] = value;
                } else {
                    if idx > a.len() {
                        return None;
                    }
                    a.insert(idx, value);
                }
            }
        }
        _ => return None,
    }
    Some(())
}

fn pointer_get_mut<'a>(root: &'a mut Value, pointer: &str) -> Option<&'a mut Value> {
    let mut cur = root;
    for raw in pointer.trim_start_matches('/').split('/') {
        let tok = raw.replace("~1", "/").replace("~0", "~");
        cur = match cur {
            Value::Object(o) => o.get_mut(&tok)?,
            Value::Array(a) => a.get_mut(tok.parse::<usize>().ok()?)?,
            _ => return None,
        };
    }
    Some(cur)
}

/// RFC 6902 JSON Patch: `add`, `remove`, `replace`, `move`, `copy`, `test`, applied in order against a working
/// copy. Any operation that cannot be applied (a `test` mismatch, a missing path, an out-of-range array index)
/// rejects the whole document — `None` — leaving the original untouched, matching the Java library's
/// all-or-nothing `JsonPatch.apply` (used by `HttpResponseModifier.apply()`).
fn apply_json_patch(original: &Value, ops: &[Value]) -> Option<Value> {
    let mut doc = original.clone();
    for op in ops {
        let kind = op.get("op").and_then(Value::as_str)?;
        let path = op.get("path").and_then(Value::as_str)?;
        match kind {
            "add" => {
                let value = op.get("value")?.clone();
                pointer_set(&mut doc, path, value, false)?;
            }
            "remove" => {
                pointer_remove(&mut doc, path)?;
            }
            "replace" => {
                let value = op.get("value")?.clone();
                pointer_set(&mut doc, path, value, true)?;
            }
            "move" => {
                let from = op.get("from").and_then(Value::as_str)?;
                let value = pointer_remove(&mut doc, from)?;
                pointer_set(&mut doc, path, value, false)?;
            }
            "copy" => {
                let from = op.get("from").and_then(Value::as_str)?;
                let value = pointer_get(&doc, from)?.clone();
                pointer_set(&mut doc, path, value, false)?;
            }
            "test" => {
                let expected = op.get("value")?;
                if pointer_get(&doc, path)? != expected {
                    return None;
                }
            }
            _ => return None,
        }
    }
    Some(doc)
}

/// RFC 7386 JSON Merge Patch: recurses into nested objects; a `null` leaf deletes the matching key; any other
/// value (including a non-object patch, or a non-object target merged with an object patch) replaces outright.
fn apply_merge_patch(target: Value, patch: &Value) -> Value {
    let Value::Object(patch_obj) = patch else {
        return patch.clone();
    };
    let mut result = match target {
        Value::Object(o) => o,
        _ => Map::new(),
    };
    for (k, v) in patch_obj {
        if v.is_null() {
            result.shift_remove(k);
        } else {
            let merged = apply_merge_patch(result.get(k).cloned().unwrap_or(Value::Null), v);
            result.insert(k.clone(), merged);
        }
    }
    Value::Object(result)
}

fn apply_request_override(r: &mut HttpRequest, o: &Value) {
    if let Some(m) = o.get("method").and_then(Value::as_str) {
        r.method = m.to_string();
    }
    if let Some(p) = o.get("path").and_then(Value::as_str) {
        r.path = p.to_string();
    }
    if let Some(h) = o.get("headers") {
        r.headers.edit(|headers| merge_map(headers, h));
    }
    if let Some(q) = o.get("queryStringParameters") {
        merge_map(&mut r.query, q);
        r.raw_query = None;
    }
    if let Some(c) = o.get("cookies") && let Value::Object(map) = canonical::single_map(c) {
        for (k, v) in map {
            let v = v.as_str().unwrap_or_default().to_string();
            match r.cookies.iter_mut().find(|(e, _)| *e == k) {
                Some(existing) => existing.1 = v,
                None => r.cookies.push((k, v)),
            }
        }
    }
    if let Some(b) = o.get("body") {
        r.body = action::respond(&json!({"body": b})).reply.body;
    }
    if let Some(s) = o.get("secure").and_then(Value::as_bool) {
        r.secure = s;
    }
}

fn apply_request_modifier(r: &mut HttpRequest, m: &Value) {
    if let Some(p) = m.get("path") {
        let regex = p.get("regex").and_then(Value::as_str).unwrap_or_default();
        let substitution = p.get("substitution").and_then(Value::as_str).unwrap_or_default();
        if let Ok(re) = fancy_regex::Regex::new(regex) {
            r.path = re.replace_all(&r.path, substitution).into_owned();
        }
    }
    if let Some(h) = m.get("headers") {
        r.headers.edit(|headers| modify_map(headers, h));
    }
    if let Some(q) = m.get("queryStringParameters") {
        modify_map(&mut r.query, q);
        r.raw_query = None;
    }
    if let Some(c) = m.get("cookies") {
        modify_cookies(&mut r.cookies, c);
    }
}

/// `CookiesModifier.apply` on the request's cookies (a `LinkedHashMap`): `replaceEntryIfExists` removes and
/// re-adds an existing cookie, moving it to the end; `add` puts (in place when present); `remove` drops by name.
fn modify_cookies(cookies: &mut Vec<(String, String)>, m: &Value) {
    let entries = |v: Option<&Value>| -> Vec<(String, String)> {
        match v {
            Some(Value::Object(o)) => o.iter().map(|(k, v)| (k.clone(), v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string()))).collect(),
            Some(Value::Array(items)) => items
                .iter()
                .filter_map(|i| Some((i.get("name")?.as_str()?.to_string(), i.get("value")?.as_str()?.to_string())))
                .collect(),
            _ => Vec::new(),
        }
    };
    for (name, value) in entries(m.get("replace")) {
        if let Some(i) = cookies.iter().position(|(k, _)| *k == name) {
            cookies.remove(i);
            cookies.push((name, value));
        }
    }
    for (name, value) in entries(m.get("add")) {
        match cookies.iter_mut().find(|(k, _)| *k == name) {
            Some(existing) => existing.1 = value,
            None => cookies.push((name, value)),
        }
    }
    if let Some(Value::Array(names)) = m.get("remove") {
        for name in names.iter().filter_map(Value::as_str) {
            cookies.retain(|(k, _)| k != name);
        }
    }
}

