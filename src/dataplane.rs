//! Data-plane requests: match an expectation and run its action, or fall back to MockServer's no-match
//! behaviour (§3.8).

use std::sync::Arc;

use bytes::Bytes;

use crate::action::{self, Action};
use crate::callback;
use crate::handler::Outcome;
use crate::reply::Reply;
use crate::request::HttpRequest;
use crate::state::State;
use crate::templates;

const FORWARDED_BY: &str = "x-forwarded-by";

tokio::task_local! {
    /// `HttpActionHandler.processEarlyAction`: the expectation `EarlyMatchingHandler` already matched (and logged) for
    /// the request's head, served instead of matching again.
    static EARLY_MATCH: std::cell::RefCell<Option<crate::store::Found>>;
}

/// Runs `f` (the dispatch of an early, `respondBeforeBody`, request) with `found` as the expectation it serves.
pub fn with_early_match<F: std::future::Future>(found: crate::store::Found, f: F) -> impl std::future::Future<Output = F::Output> {
    EARLY_MATCH.scope(std::cell::RefCell::new(Some(found)), f)
}

/// Whether this dispatch serves an early (`respondBeforeBody`) match: `EarlyMatchingHandler` hands it to
/// `HttpActionHandler.processEarlyAction` directly, past `HttpState.handle`.
pub fn serving_early_match() -> bool {
    EARLY_MATCH.try_with(|m| m.borrow().is_some()).unwrap_or(false)
}

/// `firstMatchingEarlyExpectation`'s log: each `respondBeforeBody` expectation it tried against the request's head,
/// matched or not, the mismatches without differences (it matches with no `MatchDifference` context).
pub fn log_early_evaluations(state: &State, head: &HttpRequest, evaluated: &[crate::store::Evaluated]) {
    if state.info_enabled() {
        log_evaluations(state, head, evaluated, None, false);
    }
}

/// What an action's arm, entered through a function of its own so that its poll frame is not part of
/// [`handle_inline`]'s, hands back: the response `handle_inline` goes on with (the response breakpoint,
/// the writer headers, the response entry), or an outcome it returns as it is.
// the served reply is the common arm, and boxing it would cost an allocation for nothing
#[allow(clippy::large_enum_variant)]
enum Arm {
    /// The reply and the response as logged: shared with the expectation when it is the expectation's own response,
    /// so a static response is not copied for each request that logs it.
    Served(Reply, Arc<serde_json::Value>),
    Done(Outcome),
}

/// The response, or `return` with the arm's outcome.
macro_rules! served {
    ($arm:expr) => {
        match $arm {
            Arm::Served(reply, logged) => (reply, logged),
            Arm::Done(outcome) => return outcome,
        }
    };
}

/// `DataPlaneAuthenticationGate.unauthorizedResponse`: the `401` refusing a request without data-plane credentials,
/// its `WWW-Authenticate` challenge (`challenge`, from [`crate::auth::data_plane_unauthenticated`]) and the
/// `AUTHENTICATION_FAILED` entry logged; a caller answering in its own protocol (gRPC) frames it itself.
pub(crate) fn unauthorized_response(state: &State, request: &HttpRequest, challenge: Option<String>) -> Reply {
    let mut reply = Reply::status(401);
    reply.reason = Some("Unauthorized".into());
    let mut logged = serde_json::json!({"statusCode": 401, "reasonPhrase": "Unauthorized"});
    if let Some(challenge) = &challenge {
        reply.headers.push(("www-authenticate".into(), challenge.clone()));
        logged["headers"] = serde_json::json!({"www-authenticate": [challenge]});
    }
    reply.headers.push(("content-type".into(), "text/plain".into()));
    reply.content_type_from_body = true;
    reply.body = bytes::Bytes::from_static(b"Unauthorized for data plane");
    logged["body"] = "Unauthorized for data plane".into();
    if state.info_enabled() {
        let entry = crate::recorded::LogEntry::new(crate::recorded::Kind::AuthenticationFailed, "data plane authentication failed so returning response:{}for request:{}")
            .request(request)
            .response(logged.clone())
            .args([crate::recorded::Arg::from(&logged), crate::recorded::logged(request).into()]);
        state.log.message_about(entry, crate::recorded::Subject::Request(Arc::new(request.clone())));
    }
    reply
}

/// What an action's arm sets for the response entry [`handle_inline`] logs after it.
#[derive(Default)]
struct ArmLog {
    /// The action a plain response was served for (`returning response … for action`), or `None` for no match.
    served_action: Option<Arc<serde_json::Value>>,
    /// The empty body (`""`, or `null` for a blank JSON one) the log prints for a response whose echo leaves it out,
    /// and whether the action shows it too (a plain response; not a template).
    empty_body: Option<(serde_json::Value, bool)>,
    /// The WARN a failed template logs once the 404 is written (`handleAnyException`), after the response entry.
    after_warn: Option<Box<crate::recorded::LogEntry>>,
}

/// What the arm of a matched expectation's action reads from [`handle_inline`].
#[derive(Clone, Copy)]
struct Matched<'a> {
    state: &'a Arc<State>,
    request: &'a HttpRequest,
    /// What the action is generated from (templates and callbacks see a modified request).
    generation: &'a HttpRequest,
    expectation: &'a crate::store::Expectation,
    injection: Option<&'a crate::chaos::http::Injection>,
    breakpoint_eligible: bool,
    match_count: u32,
    rotation: u32,
}

impl Matched<'_> {
    /// The declarative `rateLimit` (`rateLimitResponseOrNull`, which counts the request).
    fn rate_limit(&self) -> Option<Reply> {
        self.expectation.has(crate::store::Rare::RateLimit).then(|| crate::rate_limit::rejection(self.state, &self.expectation.input, &self.expectation.id)).flatten()
    }
}

/// A data-plane request's handling, a layer of the request path ([`crate::boxed::layer`]).
pub fn handle(state: &Arc<State>, request: Arc<HttpRequest>) -> impl std::future::Future<Output = Outcome> + Send + '_ {
    crate::boxed::layer(handle_inline(state, request))
}

async fn handle_inline(state: &Arc<State>, mut request: Arc<HttpRequest>) -> Outcome {
    if request.log_correlation_id.is_empty() {
        Arc::make_mut(&mut request).log_correlation_id = crate::request::new_correlation_id();
    }
    let looped = request.first_header(FORWARDED_BY).is_some_and(|v| v == state.forwarded_by);
    if let Some(challenge) = crate::auth::data_plane_rejection(&state.config, &request) {
        let reply = unauthorized_response(state, &request, challenge);
        return Outcome::respond(reply.finalize(&request, &state.config));
    }
    // `HttpRequestHandler`: with `tlsMutualAuthenticationRequired`, a plain-HTTP data-plane request is told to upgrade.
    if !request.secure && state.config.hot_bool(crate::config::Hot::TlsMutualAuthenticationRequired, false) {
        let mut reply = Reply::status(426);
        reply.reason = Some("Upgrade Required".into());
        reply.headers.push(("Upgrade".into(), "TLS/1.2, HTTP/1.1".into()));
        reply.headers.push(("Connection".into(), "Upgrade".into()));
        if state.info_enabled() {
            let logged = serde_json::json!({
                "statusCode": 426,
                "reasonPhrase": "Upgrade Required",
                "headers": {"Upgrade": ["TLS/1.2, HTTP/1.1"], "Connection": ["Upgrade"]},
            });
            let entry = crate::recorded::LogEntry::new(crate::recorded::Kind::Info, "no tls for data plane request:{}returning response:{}")
                .args([crate::recorded::Arg::from(crate::recorded::logged(&request)), (&logged).into()]);
            state.log.message_about(entry, crate::recorded::Subject::Request(request.clone()));
        }
        return Outcome::respond(reply.finalize(&request, &state.config));
    }
    // `processAction`: a preflight for a request the control plane serves is answered under the control-plane origin
    // policy before CRUD and expectation matching (9.1.0, `isControlPlaneRoutePreflight`).
    if is_preflight(&request) && crate::cors_origin::is_control_plane_request(&request, &state.config) {
        let reply = Reply::api(200).finalize(&request, &state.config);
        if !looped {
            state.log.received(HttpRequest::clone(&request));
        }
        if state.info_enabled() {
            state.log.message(crate::recorded::LogEntry::new(crate::recorded::Kind::Info, "returning CORS response for OPTIONS request").correlation(request.log_correlation_id.clone()));
        }
        return Outcome::respond(reply);
    }
    // `processAction`: a registered CRUD resource answers before any expectation is tried.
    if let Some(reply) = state.crud.dispatch(&request) {
        let reply = reply.finalize(&request, &state.config);
        // only `RECEIVED_REQUEST` is skipped for the server's own looped request (`processActionAfterFilter`)
        if !looped {
            state.log.received(HttpRequest::clone(&request));
        }
        let response = crud_response_json(&reply);
        let message = crate::recorded::LogEntry::new(crate::recorded::Kind::ExpectationResponse, "returning CRUD response:{}for request:{}")
            .args([crate::recorded::Arg::from(crate::recorded::logged_response(&response)), crate::recorded::logged(&request).into()]);
        // an `EXPECTATION_RESPONSE` its caller logs without asking a level (`HttpActionHandler.processAction`)
        state.log.record_with_message(request, response, None, message);
        return Outcome::respond(reply);
    }
    let namespace = crate::namespace::of_request(state, &request);
    let early = EARLY_MATCH.try_with(|m| m.borrow_mut().take()).ok().flatten();
    // The scan's regex timeouts are logged from the evaluated expectations' re-evaluation (`log_evaluated`), or
    // as they are when INFO is off.
    // the evaluations are listed only for the INFO entries that log them
    let traced = state.info_enabled();
    let ((found, evaluated), scan_timeouts) = match early {
        Some(found) => ((Some(found), Vec::new()), Vec::new()),
        None => crate::matcher::regex_timeouts(regex_timeout_millis(state), || state.store.first_match_traced_if(&request, namespace.as_deref(), traced)),
    };
    let (matched, match_count, rotation) = match found {
        Some(f) => (Some(f.expectation), f.match_count, f.rotation),
        None => (None, 0, 0),
    };
    // `HttpActionHandler`: the expectation's own chaos; a forward without one takes its `Host`'s service chaos.
    let injection = matched.as_ref().and_then(|e| {
        let forward = matches!(e.action, Action::Forward(_));
        let service = || if forward && e.chaos.is_none() { request.first_header("host").and_then(|h| state.chaos.service.get(h)) } else { None };
        let profile = e.effective_chaos().or_else(service)?;
        Some(crate::chaos::http::Injection { profile, match_count })
    });
    let injection = injection.as_ref();
    // `withPathParameters`: the match sets the path parameters the expectation extracted on the request, which the
    // entries logged before it hold too (`unmatched` keeps the request as it was for those).
    let path_parameters = matched.as_ref().map(|e| e.matcher.path_match(&request).parameters).unwrap_or_default();
    let unmatched = (!path_parameters.is_empty()).then(|| HttpRequest::clone(&request));
    if !path_parameters.is_empty() {
        // set in place: nothing shares the request yet
        Arc::make_mut(&mut request).path_parameters = path_parameters;
    }
    // From here on the request no longer changes: it is shared with the log entries that hold it, not copied.
    // The request as its log lines show it, built once for its received, matching and response entries.
    let mut logged_request = None;
    // The closest-match scan the unmatched request's log entries made, which `returnNotFound`'s hint reuses when
    // nothing it read has changed.
    let mut closest_scan = None;
    // whether the request the log holds is the request as it is now (`httpForward` rewrites `Host` on the logged one)
    let logged_is_request = !matches!(matched.as_ref().map(|e| &e.action), Some(Action::Forward(_)));
    {
        // Logged on arrival, before any delay (upstream's RECEIVED_REQUEST, which the server's own looped request
        // skips and nothing else: `processActionAfterFilter`); `httpForward` rewrites `Host`
        // on the logged request before it is serialised. An upgrade it relays never reaches `HttpForwardActionHandler`,
        // so its `Host` stays as it arrived.
        let rewritten = match matched.as_ref().map(|e| &e.action) {
            Some(action @ Action::Forward(f)) if forward_relay_target(state, action, &request).is_none() => f.rewritten(&request),
            _ => None,
        };
        let shown_is_request = rewritten.is_none();
        let logged = rewritten.map_or_else(|| request.clone(), Arc::new);
        // The entries render the request they hold when the log is read (upstream's event log ring after 8.0.0), so
        // they show the path parameters the match set (oracle, scenario `path_parameters_log_entries`) and the `Host`
        // and scheme `httpForward` set (`log_ca_load_client_refused_forward`).
        let shown = logged_request.insert(crate::recorded::LoggedRequest::shared(logged));
        if !looped {
            state.log.received_logged(shown, &request);
        }
        if traced {
            closest_scan = crate::blocking::off_worker_when_large(request.body.len(), || {
                let subject = shown_is_request.then_some(&shown.request);
                log_evaluations_logged(state, &request, shown, subject, unmatched.as_ref(), &evaluated, matched.is_none().then_some(namespace.as_deref()), true)
            });
        } else {
            log_regex_timeouts(state, scan_timeouts);
        }
        if matched.is_none() {
            log_namespace_silence(state, &request, namespace.as_deref());
        }
    }
    crate::control::log_lazy_removals(state, None);
    // `RequestMatchers.firstMatchingExpectation`'s counts.
    if crate::metrics::enabled(&state.config) {
        use crate::metrics::Count;
        let count = match matched.as_ref().map(|e| &e.action) {
            None => Count::ExpectationsNotMatched,
            Some(Action::Forward(_)) => Count::ForwardExpectationsMatched,
            Some(_) => Count::ResponseExpectationsMatched,
        };
        state.config.metrics.increment(count);
        // The opt-in per-expectation counter.
        if let Some(e) = matched.as_ref().filter(|_| crate::metrics::per_expectation_enabled(&state.config)) {
            state.config.metrics.expectation_matched(&e.id);
        }
    }
    if matched.as_ref().is_some_and(|e| e.canonical["times"].get("remainingTimes").is_some()) {
        // A counted use changes what is persisted (`notifyListeners` on `remainingMatchesDecremented`).
        crate::persistence::changed(state, None);
    }
    // `processAction` asks the match for its action (`getAction()`), which throws for several action types without
    // exactly one primary: a data-plane fault, before steps, captures, before-actions and `postProcess`.
    if let Some(error) = matched.as_ref().and_then(|e| crate::control::primary_action_error(e)) {
        let reply = crate::control::data_plane_failure(state, &request, &crate::recorded::Failure::illegal(error));
        return Outcome::respond(reply.finalize(&request, &state.config));
    }
    // `postProcess`: once the response is out, an expectation this request used up is removed (and logged).
    let _post = PostProcess { state: &**state, expectation: matched.clone() };
    if let Some(expectation) = &matched {
        if expectation.has(crate::store::Rare::Capture) {
            crate::capture::process(state, expectation.input.get("capture"), &request, &expectation.matcher.path_match(&request));
        }
        if expectation.has(crate::store::Rare::CrossProtocol) {
            state.bus().fire_for_http_request(&expectation.input, &request);
        }
    }
    // `beforeActions` / pre-responder `steps` first; the after-actions fire when `_after` drops, whichever way the
    // response went out.
    let _after = match matched.as_ref().filter(|e| e.has(crate::store::Rare::SideActions)) {
        Some(e) => {
            let trigger = crate::side_actions::Trigger { state: state.clone(), request: HttpRequest::clone(&request), path: e.matcher.path_match(&request) };
            if let Err(body) = crate::side_actions::before(&trigger, &e.input).await {
                crate::side_actions::after(&trigger, &e.input, false);
                return Outcome::respond(crate::side_actions::bad_gateway(body).finalize(&request, &state.config));
            }
            crate::side_actions::secondary(&trigger, &e.input);
            Some(crate::side_actions::After { trigger, expectation: e.input.clone() })
        }
        None => None,
    };
    // `dispatchPrimaryActionInternal`: a WebSocket upgrade matched by a plain `httpForward` is relayed to its host
    // and port (or, without a host, where an unmatched one would go) before rate limits, breakpoints and chaos.
    if let Some((host, port, tls)) = matched.as_ref().and_then(|e| forward_relay_target(state, &e.action, &request)) {
        return Outcome::WebSocketRelay { request: Box::new(Arc::unwrap_or_clone(request)), host, port, tls, guarded: true };
    }
    let served_by = matched.as_ref().map(|e| e.id.clone());
    // What the action's arm sets for the response entry logged below.
    let mut log = ArmLog::default();
    // The declarative `rateLimit` (`rateLimitResponseOrNull`, which counts the request): the write funnels take it
    // for mock responses (`writeResponseActionResponse`, after the response is generated and the connection not
    // dropped) and forwards (`writeForwardActionResponse`, after the upstream answered); the streaming protocols take
    // it here, before anything is served. Object callbacks and errors have none.
    let rate_limit = |e: &crate::store::Expectation| e.has(crate::store::Rare::RateLimit).then(|| crate::rate_limit::rejection(state, &e.input, &e.id)).flatten();
    let funnelled = |action: &Action| {
        matches!(
            action,
            Action::Respond(_) | Action::Responses(_) | Action::ResponseTemplate { .. } | Action::ResponseClassCallback { .. } | Action::Forward(_) | Action::Error { .. } | Action::ResponseCallback { .. }
        )
    };
    let rate_limited = matched.as_ref().filter(|e| !funnelled(&e.action)).and_then(|e| rate_limit(e));
    // A stored OpenAI Responses API answer for `GET …/responses/{id}`, served before any breakpoint.
    let stored = matched.is_none().then(|| stored_retrieval(state, &request, looped)).flatten();
    // Breakpoints hold mock responses (`RESPONSE`, `RESPONSE_TEMPLATE`, `RESPONSE_CLASS_CALLBACK`), forwards and
    // the not-found answer; the other protocols' write paths are not intercepted, nor is a stored answer.
    let breakpoint_eligible = stored.is_none()
        && matches!(
            matched.as_ref().map(|e| &e.action),
            None | Some(Action::Respond(_) | Action::Responses(_) | Action::ResponseTemplate { .. } | Action::ResponseClassCallback { .. } | Action::Forward(_))
        );
    // `attemptRequestBreakpoint`: the held request goes on (maybe modified), or the client answers it.
    let mut modified: Option<HttpRequest> = None;
    if breakpoint_eligible {
        match crate::breakpoint::hold_request(state, &request).await {
            Some(crate::breakpoint::Decision::Abort(v)) => {
                let respond = respond_logged(state, &v);
                let reply = materialise(state, &respond, &request).unwrap_or_else(|fallback| fallback.0);
                return Outcome::respond(reply.finalize(&request, &state.config));
            }
            Some(crate::breakpoint::Decision::ModifyRequest(v)) => {
                let mut changed = crate::forward::request_from_json(&v);
                changed.secure = request.secure;
                changed.protocol = request.protocol;
                changed.keep_alive = request.keep_alive;
                changed.local_address = request.local_address.clone();
                changed.remote_address = request.remote_address.clone();
                changed.log_correlation_id = request.log_correlation_id.clone();
                modified = Some(changed);
            }
            _ => {}
        }
    }
    // What the action is generated from (templates and callbacks see a modified request); logging keeps the original.
    let generation = modified.as_ref().unwrap_or(&request);
    // `returnNotFound`'s closest-match diagnostics, logged after its `NO_MATCH_RESPONSE` entry.
    let mut after_not_found: Vec<crate::recorded::LogEntry> = Vec::new();
    // The `EXPECTATION_RESPONSE` a stored OpenAI Responses API answer is logged with, in place of a mock's.
    let mut stored_entry: Option<crate::recorded::LogEntry> = None;
    // A static file answers the request: no response breakpoint holds it (`serveStaticFile` writes it directly).
    let mut static_served = false;
    // Whether a response breakpoint may hold the response: decided once, so a not-found answer nothing else logs is
    // not built for it.
    let response_holds = !state.breakpoints.is_empty();
    // `validateOpenAPIResponse`: the OpenAPI operation a mock response is checked against before it is written,
    // a response list's (`httpResponses`) and a rate limit's 429 included (oracle).
    let mock_validation = matched
        .as_ref()
        .filter(|e| matches!(e.action, Action::Respond(_) | Action::Responses(_) | Action::ResponseTemplate { .. } | Action::ResponseClassCallback { .. }))
        .and_then(|e| mock_response_operation(state, e));
    let (mut reply, mut logged_response) = match matched {
        Some(expectation) if rate_limited.is_some() => {
            let reply = rate_limited.expect("checked");
            let logged = rate_limit_logged(&reply);
            // SSE, WebSocket and gRPC stream write their 429 through `writeResponseActionResponse`, logged as
            // `returning response … for action` with the streaming action (oracle).
            let key = match &expectation.action {
                Action::Sse(_) => Some("httpSseResponse"),
                Action::WebSocket(_) => Some("httpWebSocketResponse"),
                Action::GrpcStream(_) => Some("grpcStreamResponse"),
                _ => None,
            };
            log.served_action = key.map(|k| Arc::new(expectation.canonical.get(k).cloned().unwrap_or_default()));
            // that overload passes no chaos and no rate limit (already taken, so not counted as chaos), but still
            // applies `globalResponseDelayMillis` and logs its `timing` (oracle)
            match chaos_and_delay(state, None, reply, Arc::new(logged), || None, || None).await {
                Ok(done) => done,
                Err(cut) => return cut.outcome(state, &request),
            }
        }
        Some(expectation) => {
            let m = Matched { state, request: &request, generation, expectation: &expectation, injection, breakpoint_eligible, match_count, rotation };
            match &expectation.action {
                Action::Respond(respond) => served!(respond_action(&m, respond, &mut log).await),
                Action::Responses(responses) => served!(responses_action(&m, responses, &mut log).await),
                Action::Error { delay, drop_connection, reset_connection, response_bytes, stream_error } => {
                    if let Err(cut) = action_dispatch_delay(state, delay.as_ref().map(|d| d.resolve(state, &request))).await {
                        return cut.outcome(state, &request);
                    }
                    // `returning error:` names the action twice: as the response and as the action served.
                    let action = expectation.canonical.get("httpError").cloned().unwrap_or_default();
                    let mut message = crate::recorded::LogEntry::new(crate::recorded::Kind::ExpectationResponse, "returning error:{}for request:{}for action:{}from expectation:{}").args([
                        (&action).into(),
                        crate::recorded::Arg::from(crate::recorded::logged(&request)),
                        (&action).into(),
                        (&expectation.id).into(),
                    ]);
                    // `setHttpError(httpError)`: the entry's `httpError`
                    message.error = Some(action.clone());
                    // kept whatever the `logLevel` (`HttpActionHandler.dispatchErrorAction` asks none)
                    state.log.record_with_message(request, serde_json::Value::Null, Some(expectation.id.clone()), message);
                    // precedence: `resetConnection` > `streamError` > `dropConnection`; `responseBytes` first
                    if *reset_connection {
                        return Outcome::ResetConnection { bytes: response_bytes.clone() };
                    }
                    if let Some(code) = stream_error {
                        return Outcome::Reset(*code);
                    }
                    return match response_bytes {
                        Some(bytes) => Outcome::Raw { bytes: bytes.clone(), close: *drop_connection },
                        None if *drop_connection => Outcome::DropConnection,
                        None => Outcome::Hang,
                    };
                }
                Action::Forward(forward) => served!(forward_action(&m, forward, &mut log).await),
                Action::ResponseTemplate { template, delay } => served!(template_action(&m, template, delay.as_ref(), &mut log).await),
                Action::ResponseCallback { client_id, delay } => served!(callback_action(&m, client_id, delay.as_ref(), &mut log).await),
                Action::ResponseClassCallback { class, delay } => served!(class_callback_action(&m, class, delay.as_ref(), &mut log).await),
                Action::NonHttp(kind) => {
                    // `HttpActionHandler` BINARY_RESPONSE / DNS_RESPONSE: an HTTP request must still be answered.
                    let body = format!("the matched expectation's {kind} action cannot answer an HTTP request");
                    if !matches!(state.log_level.as_str(), "OFF" | "ERROR") {
                        let entry = crate::recorded::LogEntry::new(crate::recorded::Kind::Warn, "the matched expectation's{}action cannot answer an HTTP request, so returning 501 for request:{}")
                            .level(crate::recorded::Level::Warn)
                            .request(&request)
                            .expectation_id(expectation.id.clone())
                            .args([crate::recorded::Arg::from(kind.to_string()), crate::recorded::Arg::from(crate::recorded::logged(&request))]);
                        crate::log::entry_as(state, crate::recorded::Level::Warn, &entry);
                        state.log.message_about(entry, crate::recorded::Subject::Request(request.clone()));
                    }
                    let key = if *kind == "DNS_RESPONSE" { "dnsResponse" } else { "binaryResponse" };
                    log.served_action = Some(Arc::new(expectation.canonical.get(key).cloned().unwrap_or_default()));
                    let mut reply = Reply::status(501);
                    reply.reason = Some("Not Implemented".into());
                    reply.body = bytes::Bytes::from(body.clone());
                    (reply, Arc::new(serde_json::json!({"statusCode": 501, "reasonPhrase": "Not Implemented", "body": body})))
                }
                Action::GrpcBidi(_) => {
                    let body = "gRPC bidi streaming requires the multiplex pipeline (grpcBidiStreamingEnabled=true)";
                    let mut reply = Reply::status(501);
                    reply.body = bytes::Bytes::from_static(body.as_bytes());
                    (reply, Arc::new(serde_json::json!({"statusCode": 501, "body": body})))
                }
                Action::GrpcStream(response) => {
                    let delay = response.get("delay").filter(|d| !d.is_null()).and_then(action::delay);
                    if let Err(cut) = action_dispatch_delay(state, delay.map(|d| d.resolve(state, &request))).await {
                        return cut.outcome(state, &request);
                    }
                    let action = expectation.canonical.get("grpcStreamResponse").cloned().unwrap_or_default();
                    // `HttpActionHandler` names the transport when the response writer is `Http3GrpcResponseWriter`.
                    // `Http3GrpcResponseWriter` serves gRPC requests only; any other request's stream goes through
                    // the plain HTTP/3 writer, which logs no transport (upstream 18b3a36e7).
                    let grpc_request = crate::grpc_plane::is_grpc_content_type(request.headers.content_type());
                    let format = match request.protocol {
                        "HTTP_3" if grpc_request => "returning gRPC stream response over HTTP/3 for request:{}for action:{}from expectation:{}",
                        _ => "returning gRPC stream response for request:{}for action:{}from expectation:{}",
                    };
                    let message = crate::recorded::LogEntry::new(crate::recorded::Kind::ExpectationResponse, format)
                        .args([crate::recorded::Arg::from(crate::recorded::logged(&request)), (&action).into(), (&expectation.id).into()]);
                    // kept whatever the `logLevel` (`HttpActionHandler`'s GRPC_STREAM_RESPONSE asks none)
                    state.log.record_with_message(request.clone(), serde_json::Value::Null, Some(expectation.id.clone()), message);
                    return crate::grpc_plane::stream(state, &request, response);
                }
                // `HttpActionHandler` (upstream 18b3a36e7): a WebSocket over HTTP/3 needs RFC 9220 extended CONNECT, so
                // it is answered `501` at once, the action's delay not waited out, with a WARN naming the expectation.
                Action::WebSocket(_) if request.transport() == crate::request::Protocol::Http3 => {
                    const UNSUPPORTED: &str = "WebSocket mocking is not supported over HTTP/3 (it needs RFC 9220 extended CONNECT, which MockServer does not implement); send the request over HTTP/1.1";
                    if !matches!(state.log_level.as_str(), "OFF" | "ERROR") {
                        let entry = crate::recorded::LogEntry::new(crate::recorded::Kind::Warn, format!("{UNSUPPORTED} for request:{{}}from expectation:{{}}"))
                            .level(crate::recorded::Level::Warn)
                            .request(&request)
                            .expectation_id(expectation.id.clone())
                            .args([crate::recorded::Arg::from(crate::recorded::logged(&request)), (&expectation.id).into()]);
                        crate::log::entry_as(state, crate::recorded::Level::Warn, &entry);
                        state.log.message_about(entry, crate::recorded::Subject::Request(request.clone()));
                    }
                    // `writeResponseActionResponse(…, action, …)`: logged as returned for the WebSocket action
                    log.served_action = Some(Arc::new(expectation.canonical.get("httpWebSocketResponse").cloned().unwrap_or_default()));
                    let mut reply = Reply::status(501);
                    reply.body = bytes::Bytes::from_static(UNSUPPORTED.as_bytes());
                    (reply, Arc::new(serde_json::json!({"statusCode": 501, "body": UNSUPPORTED})))
                }
                Action::WebSocket(response) => {
                    let delay = response.get("delay").filter(|d| !d.is_null()).and_then(action::delay);
                    if let Err(cut) = action_dispatch_delay(state, delay.map(|d| d.resolve(state, &request))).await {
                        return cut.outcome(state, &request);
                    }
                    let action = expectation.canonical.get("httpWebSocketResponse").cloned().unwrap_or_default();
                    let message = crate::recorded::LogEntry::new(crate::recorded::Kind::ExpectationResponse, "returning WebSocket response for request:{}for action:{}from expectation:{}")
                        .args([crate::recorded::Arg::from(crate::recorded::logged(&request)), (&action).into(), (&expectation.id).into()]);
                    // an `EXPECTATION_RESPONSE`, kept whatever the `logLevel` (`HttpActionHandler`)
                    state.log.record_with_message(request.clone(), serde_json::Value::Null, Some(expectation.id.clone()), message);
                    return Outcome::WebSocket { request: Box::new(Arc::unwrap_or_clone(request)), response: response.clone() };
                }
                Action::Sse(sse) => {
                    if let Err(cut) = action_dispatch_delay(state, sse.delay.as_ref().map(|d| d.resolve(state, &request))).await {
                        return cut.outcome(state, &request);
                    }
                    let action = expectation.canonical.get("httpSseResponse").cloned().unwrap_or_default();
                    let message = crate::recorded::LogEntry::new(crate::recorded::Kind::ExpectationResponse, "returning SSE response for request:{}for action:{}from expectation:{}")
                        .args([crate::recorded::Arg::from(crate::recorded::logged(&request)), (&action).into(), (&expectation.id).into()]);
                    // kept whatever the `logLevel` (`HttpActionHandler`'s SSE_RESPONSE asks none)
                    state.log.record_with_message(request.clone(), serde_json::Value::Null, Some(expectation.id.clone()), message);
                    return sse_stream(state, sse, &request).await;
                }
                Action::Llm(configured) => served!(llm_action(&m, configured, &mut log).await),
                Action::Unsupported(kind) => {
                    crate::log::warn(state, &format!("{kind} is not supported by mock-server yet; returning 404 for expectation {}", expectation.id));
                    (Reply::not_found(), Arc::new(not_found_json()))
                }
            }
        }
        // `attemptWebSocketPassthrough`: an unmatched upgrade in proxy mode is relayed to the port-forward remote,
        // else to its `Host`, over TLS when it arrived over TLS.
        None if !looped && crate::ws_relay::is_upgrade(&request) && websocket_target(state, &request).is_some() => {
            let (host, port) = websocket_target(state, &request).expect("websocket_target");
            let tls = request.secure;
            return Outcome::WebSocketRelay { request: Box::new(Arc::unwrap_or_clone(request)), host, port, tls, guarded: false };
        }
        // `handleProxyPass` throws on a target `URI.create` refuses: answered as a data-plane fault.
        None if !is_preflight(&request) && crate::forward::proxy_pass_refusal(state, &request).is_some() => {
            let (target, message) = crate::forward::proxy_pass_refusal(state, &request).expect("proxy_pass_refusal");
            let reply = crate::control::proxy_pass_refused(state, &request, &target, &message);
            return Outcome::respond(reply.finalize(&request, &state.config));
        }
        // `handleProxyPass`: a request under a proxy-pass prefix goes to its target.
        None if !is_preflight(&request) && crate::forward::proxy_pass_mapping(state, &request).is_some() => return proxy_pass(state, Arc::unwrap_or_clone(request)).await,
        // `returnNotFound` for a request that looped back through a proxy: the 404 carries the loop-prevention
        // header, so the MockServer that sent it logs it as no match.
        None if looped && !is_preflight(&request) && unmatched_target(state, &request).is_some() => {
            // upstream logs no `NO_MATCH_RESPONSE` for it (only a TRACE entry the event log holds no exchange of) but still
            // runs the closest-match diagnostics the hint header comes from
            let (mut reply, after) = no_match(state, &request, closest_scan.take()).await;
            for entry in after {
                crate::log::entry(state, &entry);
                state.log.message(entry);
            }
            reply.headers.push((FORWARDED_BY.into(), state.forwarded_by.clone()));
            return Outcome::respond(reply.finalize(&request, &state.config));
        }
        // `handleUnmatchedProxyForward`: in a tunnel or port-forwarding mode whatever no expectation matches goes to
        // the remote socket; otherwise a request for a non-local `Host` is proxied there (exploratory proxy).
        None if !looped && !is_preflight(&request) && unmatched_target(state, &request).is_some() => return unmatched_forward(state, Arc::unwrap_or_clone(request)).await,
        // OpenAI Responses API server-side state: a stored response answers `GET …/responses/{id}`.
        None if stored.is_some() => {
            let body = stored.clone().unwrap_or_default();
            let mut reply = Reply::status(200);
            reply.headers.push(("content-type".into(), "application/json".into()));
            reply.body = bytes::Bytes::from(body.clone());
            let logged = serde_json::json!({"statusCode": 200, "headers": {"content-type": ["application/json"]}, "body": body});
            // `HttpActionHandler`: an `EXPECTATION_RESPONSE` with the request and the stored response, whatever the
            // `logLevel`; it names no expectation.
            let entry = crate::recorded::LogEntry::new(crate::recorded::Kind::ExpectationResponse, "returning stored OpenAI Responses API response for request:{}");
            stored_entry = Some(entry.args([crate::recorded::logged(&request)]));
            (reply, Arc::new(logged))
        }
        None if state.static_files.is_some() && !is_preflight(&request) => match static_file(state, generation).await {
            StaticAnswer::Refused => {
                let reply = crate::overload::file_reads_refused(crate::overload::Reason::StaticFiles);
                return Outcome::respond(reply.finalize(&request, &state.config));
            }
            StaticAnswer::Served(reply, logged) => {
                static_served = true;
                let entry = crate::recorded::LogEntry::new(crate::recorded::Kind::ExpectationResponse, "returning static file response:{}for request:{}");
                stored_entry = Some(entry.args([crate::recorded::Arg::from(crate::recorded::logged_response(&logged)), crate::recorded::Arg::from(crate::recorded::logged(&request))]));
                (*reply, Arc::new(logged))
            }
            StaticAnswer::NotServed => {
                let (reply, after) = no_match(state, &request, closest_scan.take()).await;
                after_not_found = after;
                let logged = match reply.status {
                    404 => not_found_shared(),
                    status => Arc::new(serde_json::json!({"statusCode": status, "reasonPhrase": reason(status)})),
                };
                (reply, logged)
            }
        },
        None => {
            // `findClosestMatchHint` reads the matcher list after what this scan dropped lazily has left it (the
            // oracle's scheduler removes it while the request's own entries are logged), so the hint names a live one.
            let (reply, after) = no_match(state, &request, closest_scan.take()).await;
            after_not_found = after;
            let logged = match reply.status {
                // only its INFO entry and a response breakpoint read it
                404 if !state.info_enabled() && !response_holds => Arc::new(serde_json::Value::Null),
                404 => not_found_shared(),
                status => Arc::new(serde_json::json!({"statusCode": status, "reasonPhrase": reason(status)})),
            };
            (reply, logged)
        }
    };
    // `attemptResponseBreakpoint`: the response the client writes instead, if it changes it.
    if breakpoint_eligible && !static_served && response_holds {
        let paused = std::time::Instant::now();
        let continued = crate::breakpoint::Continued::default();
        let decision = crate::breakpoint::hold_response(state, &request, &logged_response, Some(continued.clone())).await;
        if let Some(crate::breakpoint::Decision::ModifyResponse(v)) = &decision {
            let respond = respond_logged(state, v);
            reply = materialise(state, &respond, &request).unwrap_or_else(|fallback| fallback.0);
            logged_response = Arc::new(crate::canonical::response(v));
        }
        if decision.is_some() {
            attach_breakpoint_timing(Arc::make_mut(&mut logged_response), paused.elapsed());
            // the mock path's continuation times the response the paused entry holds when it goes on unchanged
            // (`attachMockServedTiming(responseToWrite, …)`); the not-found path attaches no timing upstream
            if served_by.is_some() && matches!(decision, Some(crate::breakpoint::Decision::Continue)) {
                let _ = continued.set(serde_json::Value::clone(&logged_response));
            }
        }
    }
    // `ResponseWriter.writeResponse` adds the CORS and default response headers to the response object the
    // `returning response` entry and `REQUEST_RESPONSES` show (descending keys, as any headers); a not-found answer is
    // logged before it is written.
    if served_by.is_some() {
        let added = reply.add_writer_headers(&request, &state.config);
        if !added.is_empty() {
            with_logged_headers(Arc::make_mut(&mut logged_response), &added);
        }
    }
    let final_informational = is_final_informational(request.protocol, reply.status);
    if final_informational && request.protocol == "HTTP_2" {
        // `NettyResponseWriter.writeWhole`: over HTTP/2 a final 1xx is its head alone, written whole (`withoutChunking`)
        reply.chunk_size = None;
        reply.chunk_delay = None;
    }
    // the expectation a final 1xx over HTTP/2 or HTTP/3 is warned about once (`FinalInformationalResponseWarning`): the
    // matched one, which the post-processing guard holds
    let informational_warning = _post
        .expectation
        .as_ref()
        .filter(|_| final_informational && log.served_action.is_some())
        .filter(|e| first_final_informational(e))
        .map(|e| final_informational_warning(&request, &e.id, reply.status));
    let reply = reply.finalize(&request, &state.config);
    if let Some(id) = &served_by {
        let served = crate::telemetry::Served { method: &request.method, path: &request.path, status: Some(reply.status), expectation_id: Some(id), response_time_ms: 0, parented: true, server_address: None, server_port: None };
        crate::telemetry::request_span(state, served);
    }
    // the response as the event log holds it, for the validation WARN (`timing` included, as the response entry)
    let validated = mock_validation.map(|operation| (operation, serde_json::Value::clone(&logged_response), request.clone()));
    use crate::recorded::{Arg, Kind, LogEntry};
    let logged_request = logged_request.unwrap_or_else(|| crate::recorded::LoggedRequest::of(&request));
    // A mock response's `returning response` entry, built when the log is read: from the request the received entry
    // holds and the response the exchange holds (without a breakpoint's `timing`, which the entry shows and the exchange
    // does not).
    let served = match (&served_by, log.served_action.take()) {
        (Some(_), Some(action)) if logged_is_request && logged_response.get("timing").is_none() => {
            // the empty body boxed: the builder is kept with the exchange in the log, and an absent one took 88 bytes
            let (empty_body, action) = (log.empty_body.clone().map(Box::new), crate::recorded::interned_shared(action));
            // the console line is written from the entry's parts when they are the response and action as they are
            let line_action = empty_body.is_none().then(|| action.clone());
            Some((move |x: &crate::recorded::Exchange, logged: &crate::recorded::LoggedRequest| served_entry(x, logged, &action, empty_body.as_deref()), line_action))
        }
        (_, action) => {
            log.served_action = action;
            None
        }
    };
    // INFO switched on since the not-found answer was left unbuilt
    if served_by.is_none() && reply.status == 404 && logged_response.is_null() && state.info_enabled() {
        logged_response = not_found_shared();
    }
    let ordered = || logged_request.arg();
    // `LogEntry.setArguments`: an `HttpResponse` argument (the response, a response action) prints its body bare.
    let with_empty = |v: &serde_json::Value, is_action: bool| with_empty_body(v, log.empty_body.as_ref(), is_action);
    let response = || match log.empty_body {
        // its logged form built once while the thread holds the value (the not-found answer, a stored response)
        None => Arg::from(crate::recorded::logged_response_json(&logged_response)),
        Some(_) => Arg::from(crate::recorded::logged_response(&with_empty(&logged_response, false))),
    };
    let message = match (&served_by, &log.served_action) {
        (Some(id), Some(action)) => Some(
            LogEntry::new(Kind::ExpectationResponse, SERVED_FORMAT).args([response(), ordered(), crate::recorded::logged_response(&with_empty(action, true)).into(), id.into()]),
        ),
        (None, _) if stored_entry.is_some() => stored_entry.take(),
        // built only when kept (below INFO the filter that follows drops it)
        (None, _) if reply.status == 404 => state.info_enabled().then(|| LogEntry::new(Kind::NoMatchResponse, "no expectation for:{}returning response:{}").args([ordered(), response()]).other_argument(1)),
        _ => None,
    };
    // the completion's entry attaches the request (`push_exchange`) in the form already built
    // `MockServerLogger.logEvent` keeps an `EXPECTATION_RESPONSE` whatever the `logLevel`
    // Boxed (an entry is ~600 bytes): each step below moved it whole, an absent one too.
    let message = message.filter(|m| m.kind == Kind::ExpectationResponse || state.info_enabled()).map(|m| Box::new(m.request_logged(&request, &logged_request)));
    // `attachMockServedTiming`'s block is in the entry (its line and `httpResponse`), but `REQUEST_RESPONSES`
    // shows the response without it (oracle).
    let (message, logged_response) = match logged_response.get("timing") {
        Some(_) => {
            let message = message.map(|m| Box::new(m.response(crate::recorded::logged_response(&logged_response))));
            let mut untimed = logged_response;
            Arc::make_mut(&mut untimed).as_object_mut().map(|o| o.remove("timing"));
            (message, untimed)
        }
        None => (message, logged_response),
    };
    let after_warn = log.after_warn.take().map(|entry| (entry, request.clone()));
    if served_by.is_none() && reply.status == 404 {
        // an entry with the request set (`setHttpRequest`: a difference's TRACE entry, the closest match diff) is
        // about it, so a log clear that matches the request removes it
        let about = after_not_found.iter().any(|e| e.requests.is_some()).then(|| request.clone());
        state.log.record_no_match(request, logged_response, message.map(|m| *m));
        for entry in std::mem::take(&mut after_not_found) {
            crate::log::entry(state, &entry);
            match (&about, entry.requests.is_some()) {
                (Some(about), true) => state.log.message_about(entry, crate::recorded::Subject::Request(about.clone())),
                _ => state.log.message(entry),
            }
        }
    } else {
        // `processAction`: a preflight no expectation matched is answered with `OK`, then an INFO entry that names
        // no request, only its correlation id (so a log clear by request keeps it)
        let preflight = (served_by.is_none() && is_preflight(&request) && state.info_enabled())
            .then(|| LogEntry::new(Kind::Info, "returning CORS response for OPTIONS request").correlation(request.log_correlation_id.clone()));
        let warned_request = informational_warning.as_ref().map(|_| request.clone());
        match (served, message) {
            (Some((make, line_action)), _) => {
                let line = line_action.as_ref().map(|action| move |x: &crate::recorded::Exchange, logged: &crate::recorded::LoggedRequest, out: &mut String, scratch: &mut String| served_line(x, logged, action, out, scratch));
                let line = line.as_ref().map(|line| line as crate::recorded::ServedLine<'_>);
                state.log.record_served(&logged_request, logged_response, served_by, Kind::ExpectationResponse, make, line)
            }
            (None, Some(message)) => state.log.record_with_message(request, Arc::unwrap_or_clone(logged_response), served_by, *message),
            (None, None) => state.log.record(Arc::unwrap_or_clone(request), Arc::unwrap_or_clone(logged_response), served_by),
        }
        if let (Some(entry), Some(request)) = (informational_warning, warned_request) {
            crate::log::warn_event_about(state, entry, &request);
        }
        if let Some(entry) = preflight {
            state.log.message(entry);
        }
    }
    if let Some((entry, request)) = after_warn {
        // `writeResponseActionResponse` post-processes (an expectation the request used up is removed and
        // logged) before `handleAnyException` logs the exception (oracle).
        drop(_post);
        state.log.message_about(*entry, crate::recorded::Subject::Request(request));
    }
    let reply = match validated {
        Some(((spec, operation_id, id), logged, request)) => validate_mock_response(state, &request, (&spec, &operation_id, &id), reply, logged),
        None => reply,
    };
    dribbled(reply)
}

/// A mock response's `returning response` entry.
const SERVED_FORMAT: &str = "returning response:{}for request:{}for action:{}from expectation:{}";

/// `LogEntry.setArguments`: an `HttpResponse` argument (the response, a response action) prints its body bare, and an
/// empty one as the arm logged it (for the action only when it shows it too).
fn with_empty_body(v: &serde_json::Value, empty_body: Option<&(serde_json::Value, bool)>, is_action: bool) -> serde_json::Value {
    match empty_body {
        Some((body, in_action)) if !is_action || *in_action => crate::canonical::with_response_body(v, body),
        _ => v.clone(),
    }
}

/// The `returning response` entry of an exchange a mock response `action` of its expectation served, its request in
/// the logged form `logged`.
fn served_entry(x: &crate::recorded::Exchange, logged: &crate::recorded::LoggedRequest, action: &Arc<serde_json::Value>, empty_body: Option<&(serde_json::Value, bool)>) -> crate::recorded::LogEntry {
    use crate::recorded::{Arg, Kind, LogEntry, logged_response};
    let id = x.expectation_id.as_deref().unwrap_or_default();
    let (response, action) = match empty_body {
        // the response and the action, mostly one value, quoted as their logged form built once
        None => (crate::recorded::logged_response_json(&x.response), crate::recorded::logged_response_json(action)),
        Some(_) => (
            crate::log_entry::Json::new(logged_response(&with_empty_body(&x.response, empty_body, false))),
            crate::log_entry::Json::new(logged_response(&with_empty_body(action, empty_body, true))),
        ),
    };
    LogEntry::new(Kind::ExpectationResponse, SERVED_FORMAT)
        .args([Arg::from(response), logged.arg(), Arg::from(action), id.into()])
        .request_logged(&x.request, logged)
}

/// [`served_entry`]'s console message (the response and action as they are, no empty body logged in their place),
/// written from its parts.
fn served_line(x: &crate::recorded::Exchange, logged: &crate::recorded::LoggedRequest, action: &Arc<serde_json::Value>, out: &mut String, scratch: &mut String) {
    let id = x.expectation_id.as_deref().unwrap_or_default();
    let (response, action) = (crate::recorded::logged_response_json(&x.response), crate::recorded::logged_response_json(action));
    crate::matcher::format_log_message_blocks_into(out, 0, SERVED_FORMAT, 4, |i, out| match i {
        0 => response.write_block(out, scratch),
        1 => logged.json.write_block(out, scratch),
        2 => action.write_block(out, scratch),
        _ => crate::matcher::argument_block_into(out, 0, id),
    });
}

/// `Action::Respond`: a mock response, maybe a `recoverAfter` failure or a synthesized GraphQL body; a layer of the
/// request path ([`crate::boxed::layer`]).
fn respond_action<'a>(m: &'a Matched<'_>, respond: &'a action::Respond, log: &'a mut ArmLog) -> impl std::future::Future<Output = Arm> + Send + 'a {
    crate::boxed::layer(async move {
        let Matched { state, request, generation, expectation, injection, match_count, .. } = *m;
        let (reply, logged) = {
            // `selectRecoveryResponse`: a `recoverAfter` clause serves its failure response first.
            let recovery = expectation
                .has(crate::store::Rare::RecoverAfter)
                .then(|| expectation.canonical.get("httpResponse"))
                .flatten()
                .and_then(|configured| crate::chaos::http::recovery_response(state, configured, &expectation.id, request, match_count));
            let recovered = recovery.as_ref().map(action::respond);
            let respond = recovered.as_ref().unwrap_or(respond);
            let synthesized = graphql_synthesized(state, &expectation.canonical, respond, generation);
            let respond = synthesized.as_ref().map_or(respond, |(r, _)| r);
            // `handle` resolves the action's delay before the response is materialised (and logs a fallback),
            // then the write funnel resolves the materialised response's delay again, which is the one applied
            // (`writeResponseActionResponse`): a template that falls back logs twice.
            if let Some(delay) = &respond.delay {
                delay.resolve(state, generation);
            }
            let materialised = match materialise_file_body(state, respond, generation).await {
                Some(materialised) => materialised,
                None => return Arm::Done(Outcome::respond(crate::overload::file_reads_refused(crate::overload::Reason::FileBodies).finalize(request, &state.config))),
            };
            match materialised {
                Ok(mut reply) => {
                    // `WasmResponseShaper`: a WASM body matcher's module may rewrite the static response.
                    if let Some(module) = expectation.canonical.get("httpRequest").and_then(|r| r.get("body")).filter(|b| b.get("type").and_then(serde_json::Value::as_str) == Some("WASM")).and_then(|b| b.get("moduleName")).and_then(serde_json::Value::as_str) {
                        crate::wasm::shape(state, module, request, &mut reply);
                    }
                    let delay = || respond.delay.as_ref().map(|d| d.resolve(state, generation));
                    // the expectation's own response is logged as the action from the copy it keeps for that
                    let shared = recovery.is_none().then(|| expectation.served_response().cloned()).flatten();
                    let logged: Arc<serde_json::Value> = match &shared {
                        // the response as logged is the action itself, shared rather than copied for each request
                        Some(shared) if synthesized.is_none() && respond.generated.is_none() => {
                            log.served_action = Some(shared.clone());
                            shared.clone()
                        }
                        _ => {
                            let unserved = match (&recovery, &shared) {
                                (Some(failure), _) => crate::canonical::response(failure),
                                (None, Some(shared)) => serde_json::Value::clone(shared),
                                // a responder step's response when steps are configured
                                (None, None) => crate::side_actions::responder_value(&expectation.canonical, "httpResponse").cloned().unwrap_or_default(),
                            };
                            // `HttpResponseActionHandler` generates a `generateFromSchema` body into a clone: the
                            // logged action is the expectation's own, without it; the logged response has it.
                            log.served_action = Some(shared.unwrap_or_else(|| Arc::new(unserved.clone())));
                            let action = respond.served(unserved);
                            // a synthesized GraphQL body is logged with the response (a plain string), not the action
                            Arc::new(match (&synthesized, action) {
                                (Some((_, text)), serde_json::Value::Object(mut o)) => {
                                    o.insert("body".into(), serde_json::Value::String(text.clone()));
                                    serde_json::Value::Object(o)
                                }
                                (_, action) => action,
                            })
                        }
                    };
                    if recovery.is_none() && synthesized.is_none() && respond.generated.is_none() {
                        log.empty_body = expectation.empty_response_body().map(|b| (b.clone(), true));
                    }
                    match chaos_and_delay(state, injection, reply, logged, delay, || m.rate_limit()).await {
                        Ok(done) => done,
                        Err(cut) => return Arm::Done(cut.outcome(state, request)),
                    }
                }
                Err(fallback) => {
                    let (reply, logged, warn) = *fallback;
                    if reply.status == 500 || warn.is_some() {
                        log.served_action = Some(Arc::new(file_error_action(match &recovery {
                            Some(failure) => crate::canonical::response(failure),
                            None => expectation.canonical.get("httpResponse").cloned().unwrap_or_default(),
                        })));
                    }
                    log.after_warn = warn;
                    (reply, logged.into())
                }
            }
        };
        Arm::Served(reply, logged)
    })
}

/// `Action::Responses`: the response of a list (`httpResponses`) this match selects.
/// Boxed: its future is large ([`crate::boxed`]).
fn responses_action<'a>(m: &'a Matched<'_>, responses: &'a action::Responses, log: &'a mut ArmLog) -> crate::boxed::Boxed<'a, Arm> {
    Box::pin(async move {
        let Matched { state, request, generation, injection, rotation, .. } = *m;
        let (reply, logged) = {
            let forced = crate::action::forced_response_index(request).and_then(|f| usize::try_from(f).ok());
            let (respond, action) = &responses.responses[responses.select(rotation, forced)];
            // resolved twice, as for a single response
            if let Some(delay) = &respond.delay {
                delay.resolve(state, generation);
            }
            let materialised = match materialise_file_body(state, respond, generation).await {
                Some(materialised) => materialised,
                None => return Arm::Done(Outcome::respond(crate::overload::file_reads_refused(crate::overload::Reason::FileBodies).finalize(request, &state.config))),
            };
            match materialised {
                Ok(reply) => {
                    let delay = || respond.delay.as_ref().map(|d| d.resolve(state, generation));
                    // the logged action without a generated body, the response with it (as for a single response)
                    log.served_action = Some(Arc::new(action.clone()));
                    let action = respond.served(action.clone());
                    match chaos_and_delay(state, injection, reply, action, delay, || m.rate_limit()).await {
                        Ok(done) => done,
                        Err(cut) => return Arm::Done(cut.outcome(state, request)),
                    }
                }
                Err(fallback) => {
                    let (reply, logged, warn) = *fallback;
                    if reply.status == 500 || warn.is_some() {
                        log.served_action = Some(Arc::new(file_error_action(action.clone())));
                    }
                    log.after_warn = warn;
                    (reply, logged)
                }
            }
        };
        Arm::Served(reply, logged.into())
    })
}

/// `Action::Forward`: the forward, its chaos, drift, breakpoint and log entries, streamed or whole.
/// Boxed: its future is large ([`crate::boxed`]).
fn forward_action<'a>(m: &'a Matched<'_>, forward: &'a crate::forward::Forward, log: &'a mut ArmLog) -> crate::boxed::Boxed<'a, Arm> {
    Box::pin(async move {
        let Matched { state, request, generation, expectation, injection, breakpoint_eligible, .. } = *m;
        let (reply, logged) = {
            // `combineWithGlobalDelay(actionDelay)`: the forward waits its own delay plus `globalResponseDelayMillis`
            // before it is sent, refused with the 503 when `maxPendingDelayedResponses` is full
            if let Err(cut) = action_dispatch_delay(state, forward.delay().map(|d| d.resolve(state, request))).await {
                return Arm::Done(cut.outcome(state, request));
            }
            // `scheduleTemplateAction(rejectable(…))`: a forward template's render is admitted to the template
            // queue, or refused with the 503, once its delay is over
            let queued = match forward {
                crate::forward::Forward::Template { .. } => match state.overload.queue_render(state) {
                    Some(queued) => Some(queued),
                    None => return Arm::Done(Cut::Refused.outcome(state, request)),
                },
                _ => None,
            };
            // `blockIfLlmCostBudgetExceeded`: answered with the 429, nothing forwarded or logged.
            if let Some(reply) = crate::llm::budget::check_forward(state, forward, request) {
                return Arm::Done(Outcome::respond(reply.finalize(request, &state.config)));
            }
            let path = expectation.matcher.path_match(generation);
            let started = std::time::Instant::now();
            let mut result = forward.execute_queued(state, generation, &path, queued).await;
            // `writeForwardActionResponse` takes its chaos decisions and emits the request span on the head, before
            // choosing the streaming path: a dropped connection drops, an injected error replaces the stream (the
            // response is then written whole), a latency delays the head. GenAI waits for the stream's end.
            let mut stream_replaced = false;
            if let Some(forwarded) = result.as_mut().ok().filter(|f| f.streaming.is_some() && f.error.is_none()) {
                let target = forwarded.logged_request.first_header("host").map(str::to_string);
                forwarded_span(state, request, forwarded, target.as_deref(), Some(&expectation.id), started, true);
                if injection.is_some_and(|i| i.drops(state)) {
                    return Arm::Done(Outcome::DropConnection);
                }
                if let Some(limited) = m.rate_limit() {
                    crate::chaos::http::injected(state, "rateLimit");
                    forwarded.streaming = None;
                    let logged = rate_limit_logged(&limited);
                    replace_forwarded(forwarded, crate::chaos::http::Replacement { reply: limited, logged });
                    stream_replaced = true;
                }
                if let Some(injection) = injection {
                    if let Some(replacement) = (!stream_replaced).then(|| injection.replacement(state)).flatten() {
                        forwarded.streaming = None;
                        replace_forwarded(forwarded, replacement);
                        stream_replaced = true;
                    }
                    if let Some(latency) = injection.latency(state) {
                        optional_delay(state, latency).await;
                    }
                }
            }
            match result {
                Ok(mut forwarded) if forwarded.streaming.is_some() => {
                    let upstream = crate::drift::Observed::head(forwarded.reply.status, &forwarded.reply.headers);
                    let head = std::mem::take(&mut forwarded.reply).finalize(request, &state.config);
                    let close = head.close;
                    let (log_state, id, canonical, sent) = (state.clone(), expectation.id.clone(), expectation.canonical.clone(), forwarded.sent.clone());
                    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
                    let mut streaming = forwarded.streaming.take().expect("streaming");
                    let usage = observe_forwarded_llm_stream(state, &mut streaming, &forwarded, None);
                    let upstream_end = streaming.end.clone();
                    let stream_end = upstream_end.clone();
                    let chunks = streaming.relay(state, forwarded.logged_request.clone(), move |done| {
                        let _ = done_tx.send(done);
                    });
                    // `analyseDrift` runs on the response's head, before the body is relayed.
                    drift_pass(state, drift_request(forward, request, &forwarded.logged_request), &upstream).await;
                    // `writeStreamingForwardActionResponse`: logged once the stream has ended, with its GenAI span.
                    let on_end = async move {
                        if let Ok(mut done) = done_rx.await {
                            done.sent = sent;
                            let (llm, status) = (llm_sent(&done), done.reply.status);
                            let message = forwarded_message(&done, &canonical, &id, false);
                            log_state.log.record_forwarded(done.logged_request, done.logged_response, done.recorded, Some(id), message);
                            streamed_forward_gen_ai(&log_state, &llm, status, None, usage.as_ref(), stream_end.is_aborted());
                        }
                    };
                    return Arm::Done(relayed(state, request, head, chunks, close, upstream_end, on_end));
                }
                Ok(forwarded) if forwarded.threw.is_some() => {
                    // `handleAnyException`: the 404 is logged as the action's response, then the exception.
                    let reply = forwarded.reply.finalize(request, &state.config);
                    // `writeResponseActionResponse`'s `EXPECTATION_RESPONSE`, logged without asking a level
                    let action = expectation.canonical.as_object().and_then(|o| o.iter().find(|(k, _)| k.starts_with("http") && *k != "httpRequest")).map(|(_, v)| v.clone()).unwrap_or_default();
                    let message = crate::recorded::LogEntry::new(crate::recorded::Kind::ExpectationResponse, "returning response:{}for request:{}for action:{}from expectation:{}").args([
                        crate::recorded::Arg::from(&forwarded.logged_response),
                        crate::recorded::logged(&forwarded.logged_request).into(),
                        (&action).into(),
                        (&expectation.id).into(),
                    ]);
                    state.log.record_with_message(forwarded.logged_request.clone(), forwarded.logged_response, Some(expectation.id.clone()), message);
                    if state.info_enabled() {
                        // A WARN entry at INFO level, the exception's message its format.
                        let text = forwarded.threw.unwrap_or_default();
                        crate::log::info_as(state, crate::recorded::Kind::Warn, &text);
                        let entry = crate::recorded::LogEntry::new(crate::recorded::Kind::Warn, text).level(crate::recorded::Level::Info);
                        state.log.message_about(entry, crate::recorded::Subject::Request(Arc::new(forwarded.logged_request)));
                    }
                    return Arm::Done(Outcome::respond(reply));
                }
                Ok(mut forwarded) => {
                    // `materialiseFileBodyResponse` on the overridden response, before drift and chaos
                    if let Some(e) = forwarded.file_error.take() {
                        log_file_body_error(state, request, &e);
                    }
                    let mut replaced = false;
                    // `analyseDrift` compares the upstream's response, before any chaos or breakpoint replaces it.
                    let upstream = crate::drift::Observed::upstream(&forwarded.reply, &forwarded.logged_response);
                    if forwarded.error.is_none() {
                        if stream_replaced {
                            replaced = true;
                        } else {
                            let target = forwarded.logged_request.first_header("host").map(str::to_string);
                            // the GenAI span sniffs the request as sent (`clonedRequest`), not the logged one
                            forwarded_gen_ai(state, &forwarded, None);
                            forwarded_span(state, request, &forwarded, target.as_deref(), Some(&expectation.id), started, true);
                            match forward_chaos(state, injection, &mut forwarded, || m.rate_limit()).await {
                                Some(r) => replaced = r,
                                None => return Arm::Done(Outcome::DropConnection),
                            }
                        }
                        // `attemptResponseBreakpoint` on the upstream response.
                        if breakpoint_eligible && let Some(crate::breakpoint::Decision::ModifyResponse(v)) = crate::breakpoint::hold_response(state, request, &forwarded.logged_response, None).await {
                            let respond = respond_logged(state, &v);
                            forwarded.reply = materialise(state, &respond, request).unwrap_or_else(|fallback| fallback.0);
                            forwarded.logged_response = crate::canonical::response(&v);
                        }
                    }
                    // the loop hint (upstream 48b7e14d2, 9.1.0): appended to a named reason, else the 502's whole body
                    if let Some(hint) = forwarded.error.as_ref().and_then(|e| forward_loop_hint(&expectation.canonical, &forwarded.logged_request, e)) {
                        let body = match forwarded.error.as_ref().and_then(|e| e.connect_failure_reason(true)) {
                            Some(reason) => format!("{reason}; {hint}"),
                            None => hint.to_string(),
                        };
                        forwarded.reply.body = body.clone().into();
                        forwarded.logged_response = serde_json::json!({"statusCode": 502, "reasonPhrase": "Bad Gateway", "body": body});
                    }
                    let message = forwarded_message(&forwarded, &expectation.canonical, &expectation.id, replaced);
                    let reply = forwarded.reply.finalize(request, &state.config);
                    match &forwarded.error {
                        Some(error) => forward_failed(state, &forwarded.logged_request, error, &expectation.canonical, forward.reports_exception_class() || forwarded.retried, forwarded.logged_response),
                        None => {
                            let drifted = drift_request(forward, request, &forwarded.logged_request).clone();
                            // `analyseDrift` is a `scheduler.submit` racing this entry; a warm oracle logs it after
                            state.log.record_forwarded(forwarded.logged_request, forwarded.logged_response, forwarded.recorded, Some(expectation.id.clone()), message);
                            drift_pass(state, &drifted, &upstream).await;
                        }
                    }
                    return Arm::Done(Outcome::respond(reply));
                }
                // A forward's `responseTemplate` renders in the forward's future: its failure is the future's
                // (`handleExceptionDuringForwardingRequest`), not `handleAnyException`'s.
                Err(failed) if failed.role == templates::Role::ForwardResponse => {
                    return Arm::Done(Outcome::respond(forward_response_template_failed(state, request, &failed, &expectation.id).finalize(request, &state.config)));
                }
                Err(mut failed) => {
                    // The answer is logged as the forward template's response (`handleAnyException`), then the exception.
                    log.served_action = expectation.canonical.as_object().and_then(|o| o.iter().find(|(k, _)| k.starts_with("http") && *k != "httpRequest")).map(|(_, v)| Arc::new(v.clone()));
                    log.after_warn = failed.take_after(templates::failure_as_server_error(state));
                    template_failure_answer(state, &failed)
                }
            }
        };
        Arm::Served(reply, logged.into())
    })
}

/// `Action::ResponseTemplate`: the rendered response.
/// Boxed: its future is large ([`crate::boxed`]).
fn template_action<'a>(m: &'a Matched<'_>, template: &'a templates::Template, delay: Option<&'a action::Delay>, log: &'a mut ArmLog) -> crate::boxed::Boxed<'a, Arm> {
    Box::pin(async move {
        let Matched { state, request, generation, expectation, injection, .. } = *m;
        let (reply, logged) = {
            if let Some(delay) = delay && let Err(cut) = dispatch_delay(state, delay.resolve(state, request)).await {
                return Arm::Done(cut.outcome(state, request));
            }
            // `scheduleTemplateAction(rejectable(…))`: the render is admitted to the template queue, or refused with
            // the 503, once its delay is over, and runs when a template thread is free
            let Some(queued) = state.overload.queue_render(state) else { return Arm::Done(Cut::Refused.outcome(state, request)) };
            let thread = queued.start(&state.overload).await;
            let path = expectation.matcher.path_match(generation);
            // `returning response … for action`: the template, whether or not it produced a valid response
            log.served_action = Some(Arc::new(expectation.canonical.get("httpResponseTemplate").cloned().unwrap_or_default()));
            let rendered = crate::blocking::off_worker(|| templates::execute(state, &state.velocity_engines.response, template, generation, &path, None, templates::Role::Response));
            drop(thread);
            match rendered {
                Ok(generated) => {
                    let respond = respond_logged(state, &generated);
                    log.empty_body = crate::canonical::empty_response_body(&generated).map(|b| (b, false));
                    match materialise(state, &respond, generation) {
                        // the funnel resolves the materialised response's delay: none after a file-body 500
                        Ok(reply) => match chaos_and_delay(state, injection, reply, crate::canonical::response(&generated), || respond.delay.as_ref().map(|d| d.resolve(state, generation)), || m.rate_limit()).await {
                            Ok(done) => done,
                            Err(cut) => return Arm::Done(cut.outcome(state, request)),
                        },
                        Err(fallback) => {
                            let (reply, logged, warn) = *fallback;
                            log.after_warn = warn;
                            (reply, logged)
                        }
                    }
                }
                Err(mut failed) => {
                    log.after_warn = failed.take_after(templates::failure_as_server_error(state));
                    template_failure_answer(state, &failed)
                }
            }
        };
        Arm::Served(reply, logged.into())
    })
}

/// `Action::ResponseCallback`: the response a WebSocket callback client answers with.
/// Boxed: its future is large ([`crate::boxed`]).
fn callback_action<'a>(m: &'a Matched<'_>, client_id: &'a str, delay: Option<&'a action::Delay>, log: &'a mut ArmLog) -> crate::boxed::Boxed<'a, Arm> {
    Box::pin(async move {
        let Matched { state, request, expectation, injection, .. } = *m;
        let (reply, logged) = {
            // `rejectableIfDelayed`: refused before the callback is asked; the slot is held until the delay is over
            let delay = delay.as_ref().map(|d| d.resolve(state, request));
            let _waiting = match delay.filter(|d| d.as_millis() > 0) {
                Some(_) => match state.overload.admit(state, crate::overload::Reason::DelayedResponses, 1) {
                    Some(permit) => Some(permit),
                    None => return Arm::Done(Cut::Refused.outcome(state, request)),
                },
                None => None,
            };
            let parameters = expectation.matcher.path_match(request).parameters;
            let answer = state.callbacks.call(client_id, crate::recorded::ordered_with_path_parameters(request, &parameters)).await;
            if let Some(delay) = delay {
                tokio::time::sleep(delay).await;
            }
            drop(_waiting);
            match answer {
                Some(callback::Reply::Message(v) | callback::Reply::Request(v)) => {
                    let envelope_text = callback::received_text(&v);
                    let v = callback::strip_correlation(v);
                    let respond = respond_logged(state, &v);
                    match materialise_or_fail(state, &respond, request) {
                        // the funnel resolves the materialised response's delay: none after a file-body 500
                        Ok(reply) => match chaos_and_delay(state, injection, reply, crate::canonical::response(&v), || respond.delay.as_ref().map(|d| d.resolve(state, request)), || None).await {
                            Ok(done) => done,
                            Err(cut) => return Arm::Done(cut.outcome(state, request)),
                        },
                        // The client's message fails in the web socket handler when it is received (the `FILE` body
                        // is materialised then): an ERROR entry, and nothing answers the request, which hangs.
                        Err(Unmaterialised::Render(failure)) => {
                            log_received_message_failure(state, &envelope_text, failure);
                            return Arm::Done(Outcome::Hang);
                        }
                        Err(Unmaterialised::Fallback(fallback)) => {
                            let (reply, logged, _) = *fallback;
                            // `handleAnyException`'s `writeResponseActionResponse` logs the 500 against the callback action
                            log.served_action = Some(Arc::new(expectation.canonical.get("httpResponseObjectCallback").cloned().unwrap_or_default()));
                            (reply, logged)
                        }
                    }
                }
                Some(callback::Reply::Error(message)) => {
                    let mut reply = Reply::status(404);
                    reply.body = message.clone().into();
                    (reply, serde_json::json!({"statusCode": 404, "body": message}))
                }
                None => (Reply::not_found(), not_found_json()),
            }
        };
        Arm::Served(reply, logged.into())
    })
}

/// `Action::ResponseClassCallback`: the response a callback class answers with.
/// Boxed: its future is large ([`crate::boxed`]).
fn class_callback_action<'a>(m: &'a Matched<'_>, class: &'a str, delay: Option<&'a action::Delay>, log: &'a mut ArmLog) -> crate::boxed::Boxed<'a, Arm> {
    Box::pin(async move {
        let Matched { state, request, generation, expectation, injection, .. } = *m;
        let (reply, logged) = {
            if let Some(delay) = delay && let Err(cut) = dispatch_delay(state, delay.resolve(state, request)).await {
                return Arm::Done(cut.outcome(state, request));
            }
            log.served_action = Some(Arc::new(expectation.canonical.get("httpResponseClassCallback").cloned().unwrap_or_default()));
            let parameters = expectation.matcher.path_match(generation).parameters;
            let model = crate::recorded::ordered_with_path_parameters(generation, &parameters);
            match crate::class_callback::respond(state, class, generation, model).await {
                Some(v) => {
                    let respond = respond_logged(state, &v);
                    match materialise(state, &respond, request) {
                        // the funnel resolves the materialised response's delay: none after a file-body 500
                        Ok(reply) => match chaos_and_delay(state, injection, reply, crate::canonical::response(&v), || respond.delay.as_ref().map(|d| d.resolve(state, request)), || m.rate_limit()).await {
                            Ok(done) => done,
                            Err(cut) => return Arm::Done(cut.outcome(state, request)),
                        },
                        Err(fallback) => {
                            let (reply, logged, warn) = *fallback;
                            log.after_warn = warn;
                            (reply, logged)
                        }
                    }
                }
                // `notFoundResponse()` goes through the write funnel like any callback's response: it takes the
                // rate limit (oracle) and the chaos
                None => match chaos_and_delay(state, injection, Reply::not_found(), not_found_json(), || None, || m.rate_limit()).await {
                    Ok(done) => done,
                    Err(cut) => return Arm::Done(cut.outcome(state, request)),
                },
            }
        };
        Arm::Served(reply, logged.into())
    })
}

/// `Action::Llm`: the LLM response, streamed or whole, its chaos and stored-response records.
/// Boxed: its future is large ([`crate::boxed`]).
fn llm_action<'a>(m: &'a Matched<'_>, configured: &'a crate::llm::Llm, log: &'a mut ArmLog) -> crate::boxed::Boxed<'a, Arm> {
    Box::pin(async move {
        let Matched { state, request, expectation, .. } = *m;
        let (reply, logged) = {
            let inferred = configured.with_inferred_usage(state.config.bool_property("llmInferUsageEnabled", false), request);
            let llm = inferred.as_ref().unwrap_or(configured);
            // Chaos (and strict structured-output enforcement) answer with a plain error, even for a stream, but a
            // content-filter block answered with HTTP 200 streams (`ChaosOutcome.getStreamedBlock`).
            let preemptive = configured.preemptive(&state.llm_quotas, request);
            let streamed_block = preemptive.as_ref().and_then(|(error, _)| configured.streamed_block(error, request));
            let streaming = streamed_block.is_some() || (preemptive.is_none() && llm.has_completion && llm.completion.streaming);
            // The action as its log lines print it (`HttpLlmResponse.toString`): properties alphabetical.
            let action = crate::canonical::sorted(&expectation.input.get("httpLlmResponse").cloned().unwrap_or_default());
            // the chaos outcome is taken before the action is scheduled; the log entry and the answer after it
            let delay = action.get("delay").filter(|d| !d.is_null()).and_then(action::delay);
            if let Err(cut) = action_dispatch_delay(state, delay.map(|d| d.resolve(state, request))).await {
                return Arm::Done(cut.outcome(state, request));
            }
            let format = if streaming {
                "returning streaming LLM response for request:{}for action:{}from expectation:{}"
            } else {
                "returning LLM response for request:{}for action:{}from expectation:{}"
            };
            let message = crate::recorded::LogEntry::new(crate::recorded::Kind::ExpectationResponse, format)
                .args([crate::recorded::Arg::from(crate::recorded::logged(request)), (&action).into(), (&expectation.id).into()]);
            // kept whatever the `logLevel` (`HttpActionHandler`'s LLM_RESPONSE asks none)
            state.log.record_with_message(request.clone(), serde_json::Value::Null, Some(expectation.id.clone()), message);
            if let Some((error, chaos)) = preemptive {
                if chaos {
                    state.config.metrics.increment(crate::metrics::Count::LlmChaosInjected);
                }
                if let Some((events, format)) = streamed_block {
                    let headers = vec![("content-type".into(), format.content_type().into()), ("cache-control".into(), "no-cache".into())];
                    let sse = action::Sse { status: 200, headers, events, delay: None, template: None, close_connection: None, format };
                    return Arm::Done(sse_stream(state, &sse, request).await);
                }
                log.served_action = Some(Arc::new(action));
                match llm_written(state, llm_reply(error.status, error.headers.clone(), error.body.clone()), llm_logged(error.status, &error.headers, error.body)).await {
                    Ok(done) => done,
                    Err(cut) => return Arm::Done(cut.outcome(state, request)),
                }
            } else {
                // a model load or unload generates nothing: no span, no usage
                if !llm.model_management(request) {
                    crate::telemetry::served_completion(state, llm);
                    crate::llm::budget::served(state, llm);
                }
                let encoded = if streaming { llm.encode_streaming(request).map(Some) } else { Ok(None) };
                match encoded {
                    Ok(Some((events, format))) => {
                        // `recordStreamedIfStored`: recorded from the full stream, before chaos truncation, as
                        // the real server keeps the response it generated whether or not the client read it all.
                        if llm.provider.as_deref() == Some("OPENAI_RESPONSES") {
                            let chained = crate::llm::conversation::decode("OPENAI_RESPONSES", request);
                            crate::llm::responses::record_streamed_if_stored(&state.config, &request.body_str(), chained, &llm.completion, &events);
                        }
                        let events = match &llm.chaos {
                            Some(chaos) => {
                                if !events.is_empty() && crate::llm::chaos::alters_stream(chaos) {
                                    state.config.metrics.increment(crate::metrics::Count::LlmChaosInjected);
                                }
                                crate::llm::chaos::apply_streaming(events, chaos)
                            }
                            None => events,
                        };
                        let sse = action::Sse {
                            status: 200,
                            headers: vec![("content-type".into(), format.content_type().into()), ("cache-control".into(), "no-cache".into())],
                            events,
                            delay: None,
                            template: None,
                            close_connection: None,
                            format,
                        };
                        return Arm::Done(sse_stream(state, &sse, request).await);
                    }
                    // The codec throws inside the scheduled stream: the connection is closed unanswered.
                    Err(_) => return Arm::Done(Outcome::DropConnection),
                    Ok(None) => {
                        let (status, headers, body) = llm.respond(request, crate::llm::vectors::Limits::from_config(&state.config));
                        if status == 200 {
                            log.served_action = Some(Arc::new(action));
                            if llm.provider.as_deref() == Some("OPENAI_RESPONSES") {
                                let chained = crate::llm::conversation::decode("OPENAI_RESPONSES", request);
                                crate::llm::responses::record_if_stored(&state.config, &request.body_str(), chained, &llm.completion, &body);
                            }
                        }
                        match llm_written(state, llm_reply(status, headers.clone(), body.clone()), llm_logged(status, &headers, body)).await {
                            Ok(done) => done,
                            Err(cut) => return Arm::Done(cut.outcome(state, request)),
                        }
                    }
                }
            }
        };
        Arm::Served(reply, logged.into())
    })
}

/// `handleProxyPass`: a request under a proxy-pass prefix goes to its target.
/// Boxed: its future is large ([`crate::boxed`]).
fn proxy_pass(state: &Arc<State>, request: HttpRequest) -> crate::boxed::Boxed<'_, Outcome> {
    Box::pin(async move {
        let mapping = crate::forward::proxy_pass_mapping(state, &request).expect("proxy_pass_mapping");
        if let Some(reply) = crate::llm::budget::check_proxy_pass(state, &mapping, &request) {
            return Outcome::respond(reply.finalize(&request, &state.config));
        }
        // a mapping whose target leads back here matches again on every hop, as a forward does: the 508 is written
        // as it is, with no forwarded-request entry
        if let Some(body) = crate::forward_loop::refuse(state, &request, crate::forward_loop::Route::ProxyPass) {
            let reply = Reply { status: crate::forward_loop::LOOP_DETECTED, reason: Some("Loop Detected".into()), body: body.into(), ..Reply::default() };
            return Outcome::respond(reply.finalize(&request, &state.config));
        }
        if let Some(reply) = proxy_refused(state, &request, mapping.host()).await {
            return Outcome::respond(reply);
        }
        let started = std::time::Instant::now();
        let mut forwarded = mapping.forward(state, &request).await;
        if forwarded.error.is_none() && forwarded.streaming.is_none() {
            forwarded_telemetry(state, &request, &forwarded, Some(&mapping.address()), None, started, false);
        }
        let logged = request.clone();
        let target = mapping.address();
        // a `FORWARDED_REQUEST` `handleProxyPass` logs without asking a level
        let record = move |state: &State, done: crate::forward::Forwarded| {
            let curl = crate::curl::to_curl(&logged, Some(&target));
            // the response with the client's `timing`, as a forward's entry shows it
            let mut response = done.logged_response.clone();
            if let (Some(timing), Some(o)) = (done.timing, response.as_object_mut()) {
                o.insert("timing".into(), timing.json());
            }
            let message = crate::recorded::LogEntry::new(crate::recorded::Kind::ForwardedRequest, "returning response:{}for proxy pass forwarded request\n\n in json:{}\n\n in curl:{}")
                .args([crate::recorded::Arg::from(&response), crate::recorded::logged(&logged).into(), curl.into()]);
            state.log.record_forwarded(logged.clone(), done.logged_response, done.recorded, None, Some(message));
        };
        if let Some(mut streaming) = forwarded.streaming.take() {
            let head = std::mem::take(&mut forwarded.reply).finalize(&request, &state.config);
            let close = head.close;
            let log_state = state.clone();
            let (done_tx, done_rx) = tokio::sync::oneshot::channel();
            let address = mapping.address();
            let usage = observe_forwarded_llm_stream(state, &mut streaming, &forwarded, Some(&address));
            let upstream_end = streaming.end.clone();
            let stream_end = upstream_end.clone();
            let chunks = streaming.relay(state, forwarded.logged_request.clone(), move |done| {
                let _ = done_tx.send(done);
            });
            let on_end = async move {
                if let Ok(done) = done_rx.await {
                    let (llm, status) = (llm_sent(&done), done.reply.status);
                    record(&log_state, done);
                    streamed_forward_gen_ai(&log_state, &llm, status, Some(&address), usage.as_ref(), stream_end.is_aborted());
                }
            };
            return relayed(state, &request, head, chunks, close, upstream_end, on_end);
        }
        if let Some(error) = &forwarded.error {
            let error = match error {
                // `returnedHeaderLimitFailure` (upstream a78886b4d, after 8.0.0): the client's refusal, logged
                // about the mapping's target, then the reason as the error and the 502's body.
                crate::client::Error::HeaderLimit(reason, _) => {
                    let (host, port) = (mapping.host(), mapping.port());
                    log_header_limit_refusal(state, format!("{host}/<unresolved>:{port}"), format!("{host}:{port}"), reason);
                    reason.clone()
                }
                crate::client::Error::TooLarge(message) => format!("proxy pass forwarding failed for {}: {message}", mapping.target_uri),
                // `returnedUpstreamFailureReason` (master): one ERROR about the request naming the
                // mapping's target and the reason, which is also the 502's body.
                error if error.is_named_failure() => {
                    let reason = error.exception_message().unwrap_or_default();
                    let entry = crate::recorded::LogEntry::at(crate::recorded::Level::Error, "failed to proxy pass request{}to{}because:{}")
                        .request(&request)
                        .args([crate::recorded::Arg::from(crate::recorded::logged(&request)), mapping.target_uri.as_str().into(), reason.as_str().into()]);
                    crate::log::error_event(state, entry);
                    reason
                }
                // `UpstreamConnectFailure.reason` (upstream 48b7e14d2, 9.1.0): the cause, also the 502's body
                error if error.connect_failure_reason(true).is_some() => {
                    format!("proxy pass forwarding failed for {}: {}", mapping.target_uri, error.connect_failure_reason(true).unwrap_or_default())
                }
                error => format!("proxy pass forwarding failed for {}: {}", mapping.target_uri, error.proxy_pass_cause(mapping.host(), mapping.port())),
            };
            let message = crate::recorded::LogEntry::new(crate::recorded::Kind::NoMatchResponse, "failed to forward request:{}error:{}returning response:{}")
                .args([crate::recorded::Arg::from(crate::recorded::logged(&request)), error.into(), (&forwarded.logged_response).into()]);
            let reply = forwarded.reply.finalize(&request, &state.config);
            match state.info_enabled() {
                true => state.log.record_with_message(request, forwarded.logged_response, None, message),
                false => state.log.record(request, forwarded.logged_response, None),
            }
            return Outcome::respond(reply);
        }
        let reply = std::mem::take(&mut forwarded.reply).finalize(&request, &state.config);
        record(state, forwarded);
        Outcome::respond(reply)
    })
}

/// `refusedByPrivateNetworkBlock`: a request no expectation matched, refused by `InetAddressValidator` for its
/// destination `host`, is logged (WARN `proxied request blocked by SSRF policy:…`) and answered 502 by
/// `returnBadGateway` with the refusal as the error.
async fn proxy_refused(state: &State, request: &HttpRequest, host: &str) -> Option<Reply> {
    use crate::recorded::{Arg, Kind, Level, LogEntry};
    let reason = crate::ws_relay::blocked(state, host).await?;
    if !matches!(state.log_level.as_str(), "OFF" | "ERROR") {
        let entry = LogEntry::new(Kind::Warn, "proxied request blocked by SSRF policy:{}").level(Level::Warn).request(request).args([reason.clone()]);
        crate::log::entry_as(state, Level::Warn, &entry);
        state.log.message_about(entry, crate::recorded::Subject::Request(Arc::new(request.clone())));
    }
    let logged = serde_json::json!({"statusCode": 502, "reasonPhrase": "Bad Gateway"});
    let message = LogEntry::new(Kind::NoMatchResponse, "failed to forward request:{}error:{}returning response:{}")
        .args([Arg::from(crate::recorded::logged(request)), reason.into(), Arg::from(&logged)]);
    let reply = Reply::status(502).finalize(request, &state.config);
    match state.info_enabled() {
        true => state.log.record_with_message(request.clone(), logged, None, message),
        false => state.log.record(request.clone(), logged, None),
    }
    Some(reply)
}

/// `handleUnmatchedProxyForward`: the remote socket of a tunnel or port-forwarding mode, or a non-local `Host`.
/// Boxed: its future is large ([`crate::boxed`]).
fn unmatched_forward(state: &Arc<State>, request: HttpRequest) -> crate::boxed::Boxed<'_, Outcome> {
    Box::pin(async move {
        let (target, exploratory) = unmatched_target(state, &request).expect("unmatched_target");
        let invalid_target = target.clone().err();
        let (host, port) = target.unwrap_or_default();
        // `potentiallyHttpProxy`: the exploratory proxy, or (outside a tunnel) a configured `proxyRemoteHost` and
        // `proxyRemotePort` (`hasConfiguredRemoteProxy`, live; scenario `proxy_remote_host_runtime`)
        if (exploratory || (request.remote_target.is_none() && state.config.proxy_remote().is_some())) && let Some(reply) = crate::auth::proxy_rejection(&state.config, &request) {
            let reply = reply.finalize(&request, &state.config);
            if state.info_enabled() {
                let logged = serde_json::json!({"statusCode": 407, "headers": {"proxy-authenticate": [reply.header("proxy-authenticate").unwrap_or_default()]}});
                let entry = crate::recorded::LogEntry::new(crate::recorded::Kind::AuthenticationFailed, "proxy authentication failed so returning response:{}for forwarded request:{}")
                    .request(&request)
                    .response(logged.clone())
                    .synthetic_expectation(serde_json::json!({"httpRequest": crate::recorded::logged(&request), "httpResponse": logged.clone()}))
                    .args([crate::recorded::Arg::from(&logged), crate::recorded::logged(&request).into()]);
                state.log.message_about(entry, crate::recorded::Subject::Request(Arc::new(request.clone())));
            }
            return Outcome::respond(reply);
        }
        // Validation proxy (`validateProxyOpenAPISpec`): the request is checked against the spec first.
        let validation_spec = state.config.property("validateProxyOpenAPISpec").filter(|s| !s.is_empty());
        let enforce = state.config.bool_property("validateProxyEnforce", false);
        if let Some(spec) = &validation_spec {
            let errors = crate::openapi::checking_spec_fetches(&state.config, || crate::openapi_validation::validate_request(spec, &request, None));
            if !errors.is_empty() {
                let entry = crate::recorded::LogEntry::new(crate::recorded::Kind::OpenapiRequestValidationFailed, "validation proxy: request does not conform to OpenAPI spec{}errors:{}")
                    .level(crate::recorded::Level::Warn)
                    .args([crate::recorded::Arg::from(crate::recorded::logged(&request)), errors.join("; ").into()]);
                crate::log::entry_as(state, crate::recorded::Level::Warn, &entry);
                state.log.message_about(entry, crate::recorded::Subject::Request(Arc::new(request.clone())));
                if enforce {
                    let mut reply = Reply::status(400);
                    reply.body = bytes::Bytes::from(format!("OpenAPI request validation failed: {}", errors.join("; ")));
                    return Outcome::respond(reply.finalize(&request, &state.config));
                }
            }
        }
        if let Some(reply) = crate::llm::budget::check(state, None, &request) {
            return Outcome::respond(reply.finalize(&request, &state.config));
        }
        if invalid_target.is_none() && let Some(reply) = proxy_refused(state, &request, &host).await {
            return Outcome::respond(reply);
        }
        let started = std::time::Instant::now();
        let (mut forwarded, echoed) = match &invalid_target {
            // The address cannot be built, so nothing is sent: the exception surfaces as a bad gateway.
            Some(_) => (
                crate::forward::Forwarded {
                    reply: Reply::status(502),
                    logged_request: request.clone(),
                    logged_response: serde_json::json!({"statusCode": 502, "reasonPhrase": "Bad Gateway"}),
                    ..Default::default()
                },
                false,
            ),
            None => crate::forward::unmatched(state, &request, &host, port, exploratory).await,
        };
        if forwarded.recorded.is_some() && forwarded.streaming.is_none() && !echoed {
            forwarded_telemetry(state, &request, &forwarded, Some(&format!("{host}:{port}")), None, started, true);
        }
        if let Some(spec) = validation_spec.as_deref().filter(|_| forwarded.recorded.is_some()) && let Some(rejected) = validate_proxy_response(state, spec, &request, &forwarded.reply, enforce) {
            forwarded.logged_response = serde_json::json!({"statusCode": 502, "reasonPhrase": "Bad Gateway", "body": String::from_utf8_lossy(&rejected.body)});
            forwarded.reply = rejected;
        }
        if let Some(mut streaming) = forwarded.streaming.take() {
            let head = std::mem::take(&mut forwarded.reply).finalize(&request, &state.config);
            let close = head.close;
            let (log_state, logged) = (state.clone(), request.clone());
            let target = format!("{host}:{port}");
            let usage = (!echoed).then(|| observe_forwarded_llm_stream(state, &mut streaming, &forwarded, Some(&target))).flatten();
            let (done_tx, done_rx) = tokio::sync::oneshot::channel::<crate::forward::Forwarded>();
            let upstream_end = streaming.end.clone();
            let stream_end = upstream_end.clone();
            let chunks = streaming.relay(state, forwarded.logged_request.clone(), move |done| {
                let _ = done_tx.send(done);
            });
            let on_end = async move {
                let Ok(done) = done_rx.await else { return };
                let (llm, status) = (llm_sent(&done), done.reply.status);
                // a `FORWARDED_REQUEST`, kept whatever the `logLevel` (`handleUnmatchedProxyForward`)
                let curl = crate::curl::to_curl(&logged, Some(&target));
                let timed = with_timing(&done.logged_response, done.timing);
                let message = crate::recorded::LogEntry::new(crate::recorded::Kind::ForwardedRequest, "returning response:{}for forwarded request\n\n in json:{}\n\n in curl:{}")
                    .response(timed.clone())
                    .args([crate::recorded::Arg::from(&timed), crate::recorded::logged(&logged).into(), curl.into()]);
                log_state.log.record_forwarded(done.logged_request, done.logged_response, done.recorded, None, Some(message));
                streamed_forward_gen_ai(&log_state, &llm, status, Some(&target), usage.as_ref(), stream_end.is_aborted());
            };
            return relayed(state, &request, head, chunks, close, upstream_end, on_end);
        }
        // the 502's body names a connection that could not be made (upstream 48b7e14d2, 9.1.0), with the fix for a
        // timeout naming socketConnectionTimeoutInMillis only where it applies (not `potentiallyHttpProxy`)
        let potentially_http_proxy = exploratory || (request.remote_target.is_none() && state.config.proxy_remote().is_some());
        if forwarded.recorded.is_none() && !echoed && invalid_target.is_none() && let Some(reason) = forwarded.error.as_ref().filter(|e| !e.is_named_failure()).and_then(|e| e.connect_failure_reason(!potentially_http_proxy)) {
            forwarded.reply.body = reason.clone().into();
            forwarded.logged_response = serde_json::json!({"statusCode": 502, "reasonPhrase": "Bad Gateway", "body": reason});
        }
        let reply = forwarded.reply.finalize(&request, &state.config);
        let ordered = || crate::recorded::Arg::from(crate::recorded::logged(&request));
        let response = || crate::recorded::Arg::from(&forwarded.logged_response);
        if echoed {
            // `NO_MATCH_RESPONSE`: logged with a 404 whatever the echo answered.
            // The argument is the upstream's own response (`setArguments(originalRequest, response)`): the loop header
            // removed, no response-time header, the client's `timing` (the 404's own entry shows none of them).
            let mut upstream = with_timing(&forwarded.logged_response, forwarded.timing);
            if let Some(headers) = upstream.get_mut("headers").and_then(serde_json::Value::as_object_mut) {
                headers.retain(|name, _| !name.eq_ignore_ascii_case(FORWARDED_BY) && !name.eq_ignore_ascii_case("x-mockserver-response-time-ms"));
                if headers.is_empty() {
                    upstream.as_object_mut().map(|o| o.remove("headers"));
                }
            }
            let message = crate::recorded::LogEntry::new(crate::recorded::Kind::NoMatchResponse, "no expectation for:{}returning response:{}")
                .args([ordered(), crate::recorded::Arg::from(&upstream)])
                .other_argument(1);
            state.log.record_no_match(request, not_found_json(), state.info_enabled().then_some(message));
        } else if forwarded.recorded.is_none() {
            // `returnBadGateway`: the connection failed.
            let error = match &forwarded.error {
                _ if invalid_target.is_some() => invalid_target.clone().unwrap_or_default(),
                // not a connection failure, so `returnBadGateway` carries the `ExecutionException` message
                // `returnedHeaderLimitFailure` and `upstreamFailureReason` come first (upstream a78886b4d and 7a8b8c424,
                // after 8.0.0): the client's WARN for a refusal, an ERROR about the request for a named TLS failure.
                Some(crate::client::Error::HeaderLimit(reason, _)) => {
                    log_header_limit_refusal(state, java_socket_address(&host, port), format!("{host}:{port}"), reason);
                    reason.clone()
                }
                Some(error) if error.is_named_failure() => {
                    let reason = error.exception_message().unwrap_or_default();
                    // `getRemoteAddressWithFallback`: the channel's remote socket, else the unresolved proxyRemoteHost
                    let remote = match (request.remote_target.as_deref(), state.config.port_forward.clone().or_else(|| state.config.proxy_remote())) {
                        (Some((host, port)), _) => java_socket_address(host, *port),
                        (None, Some((host, port))) => format!("{host}/<unresolved>:{port}"),
                        (None, None) => String::new(),
                    };
                    let entry = crate::recorded::LogEntry::at(crate::recorded::Level::Error, "failed to proxy request{}to remote address{}because:{}")
                        .request(&request)
                        .args([ordered(), remote.into(), reason.as_str().into()]);
                    crate::log::error_event(state, entry);
                    reason
                }
                // `UpstreamConnectFailure.reason(failure, !potentiallyHttpProxy)` (upstream 48b7e14d2, 9.1.0): a request
                // proxied only because its Host is not MockServer's connects with a fixed timeout
                Some(error) if error.connect_failure_reason(true).is_some() => error.connect_failure_reason(!potentially_http_proxy).unwrap_or_default(),
                Some(crate::client::Error::Resolve { host, .. }) if exploratory => format!("java.net.UnknownHostException: {host}"),
                _ if exploratory => "failed to connect to proxied socket due to exploratory HTTP proxy".to_string(),
                Some(crate::client::Error::TooLarge(message)) => {
                    log_scheduler_warning(state, message);
                    message.clone()
                }
                Some(crate::client::Error::Tls) => format!("TLS handshake exception while proxying request to remote address{host}/{host}:{port}"),
                // transparent proxying by Host header (no remote socket): the client's exception as it is
                Some(e) if remote_socket(state, &request).is_none() => e.exception_string(),
                _ => format!("Connection refused: {host}:{port}"),
            };
            let message = crate::recorded::LogEntry::new(crate::recorded::Kind::NoMatchResponse, "failed to forward request:{}error:{}returning response:{}").args([ordered(), error.into(), response()]);
            match state.info_enabled() {
                true => state.log.record_with_message(request, forwarded.logged_response, None, message),
                false => state.log.record(request, forwarded.logged_response, None),
            }
        } else {
            // a `FORWARDED_REQUEST`, kept whatever the `logLevel` (`handleUnmatchedProxyForward`)
            let curl = crate::curl::to_curl(&request, Some(&format!("{host}:{port}")));
            // the entry's response carries the client's `timing` (`logResponse = response.clone()`)
            let timed = with_timing(&forwarded.logged_response, forwarded.timing);
            let message = crate::recorded::LogEntry::new(crate::recorded::Kind::ForwardedRequest, "returning response:{}for forwarded request\n\n in json:{}\n\n in curl:{}")
                .response(timed.clone())
                .args([crate::recorded::Arg::from(&timed), ordered(), curl.into()]);
            state.log.record_forwarded(forwarded.logged_request, forwarded.logged_response, forwarded.recorded, None, Some(message));
        }
        Outcome::respond(reply)
    })
}

/// The spec and `operationId` of an OpenAPI expectation whose mock responses `openAPIResponseValidation` checks,
/// with the expectation's id.
fn mock_response_operation(state: &State, expectation: &crate::store::Expectation) -> Option<(String, String, String)> {
    if !state.config.hot_bool(crate::config::Hot::OpenApiResponseValidation, false) {
        return None;
    }
    let text = |pointer: &str| expectation.canonical.pointer(pointer).and_then(serde_json::Value::as_str).filter(|t| !t.trim().is_empty()).map(str::to_string);
    Some((text("/httpRequest/specUrlOrPayload")?, text("/httpRequest/operationId")?, expectation.id.clone()))
}

/// `validateOpenAPIResponse`: a mock response that violates its operation is logged (WARN, after the response
/// entry) and, under `enforceResponseValidationForMocks`, replaced by a 502 naming the violations; the event log
/// keeps the response as it was.
fn validate_mock_response(state: &State, request: &HttpRequest, (spec, operation_id, id): (&str, &str, &str), reply: Reply, logged: serde_json::Value) -> Reply {
    let headers: crate::request::MultiMap = reply.headers.iter().map(|(k, v)| (k.clone(), vec![v.clone()])).collect();
    let body = String::from_utf8_lossy(&reply.body).into_owned();
    let response = crate::openapi_validation::Response { status: reply.status, headers: &headers, body: &body };
    let errors = crate::openapi::checking_spec_fetches(&state.config, || crate::openapi_validation::validate_response(spec, operation_id, &response));
    if errors.is_empty() {
        return reply;
    }
    let entry = crate::recorded::LogEntry::new(
        crate::recorded::Kind::OpenapiResponseValidationFailed,
        format!("OpenAPI response validation failed for operation {operation_id}:{{}}for request:{{}}for response:{{}}"),
    )
    .level(crate::recorded::Level::Warn)
    .request(request)
    .response(crate::recorded::logged_response(&logged))
    .expectation_id(id)
    .args([errors.join("\n").into(), crate::recorded::Arg::from(crate::recorded::logged(request)), crate::recorded::Arg::from(crate::recorded::logged_response(&logged))]);
    crate::log::entry_as(state, crate::recorded::Level::Warn, &entry);
    state.log.message_about(entry, crate::recorded::Subject::Request(Arc::new(request.clone())));
    if !state.config.bool_property("enforceResponseValidationForMocks", false) {
        return reply;
    }
    let mut rejected = Reply::status(502);
    rejected.body = bytes::Bytes::from(format!("OpenAPI response validation failed: {}", errors.join("; ")));
    rejected.finalize(request, &state.config)
}

/// `emitForwardGenAiSpan` and `emitRequestSpan` for an answered forward to `target` (`host:port`).
fn forwarded_telemetry(state: &State, request: &HttpRequest, forwarded: &crate::forward::Forwarded, target: Option<&str>, expectation_id: Option<&str>, started: std::time::Instant, parented: bool) {
    forwarded_gen_ai(state, forwarded, target);
    forwarded_span(state, request, forwarded, target, expectation_id, started, parented);
}

/// The request a forward sent, as the LLM accounting reads it (`emitForwardGenAiSpan`'s `forwardedRequest`): the
/// overridden or templated request when it is not the logged one.
struct LlmSent {
    method: String,
    path: String,
    /// `LlmProviderSniffer.extractHost`: its socket address first (the most reliable source on the forward path), else
    /// its `Host` header.
    host: Option<String>,
    body: Vec<u8>,
}

fn llm_sent(forwarded: &crate::forward::Forwarded) -> LlmSent {
    let logged = &forwarded.logged_request;
    let logged_host = match logged.socket_address.as_deref() {
        Some((host, _, _)) if !host.is_empty() => Some(host.clone()),
        _ => logged.first_header("host").map(str::to_string),
    };
    let Some((json, _)) = &forwarded.sent else {
        return LlmSent { method: logged.method.clone(), path: logged.path.clone(), host: logged_host, body: logged.body.to_vec() };
    };
    let text = |v: &serde_json::Value| v.as_str().map(str::to_string);
    let header_host = match json.get("headers") {
        Some(serde_json::Value::Object(map)) => map.iter().find(|(k, _)| k.eq_ignore_ascii_case("host")).and_then(|(_, v)| v.get(0).and_then(text).or_else(|| text(v))),
        Some(serde_json::Value::Array(list)) => list
            .iter()
            .find(|h| h.get("name").and_then(serde_json::Value::as_str).is_some_and(|n| n.eq_ignore_ascii_case("host")))
            .and_then(|h| h.get("values").and_then(|v| v.get(0)).and_then(text)),
        _ => None,
    };
    let host = json.pointer("/socketAddress/host").and_then(text).filter(|h| !h.is_empty()).or(header_host);
    let body = match json.get("body") {
        Some(serde_json::Value::String(b)) => b.clone().into_bytes(),
        Some(serde_json::Value::Object(b)) => match b.get("json").or_else(|| b.get("string")) {
            Some(serde_json::Value::String(t)) => t.clone().into_bytes(),
            Some(other) => other.to_string().into_bytes(),
            None => logged.body.to_vec(),
        },
        Some(other) if !other.is_null() => other.to_string().into_bytes(),
        _ => Vec::new(),
    };
    LlmSent {
        method: json.get("method").and_then(text).unwrap_or_else(|| logged.method.clone()),
        path: json.get("path").and_then(text).unwrap_or_else(|| logged.path.clone()),
        host: host.or(logged_host),
        body,
    }
}

/// `isForwardLlmAccountingEnabled`: GenAI spans, LLM metrics or a cost budget.
fn forward_llm_accounting_enabled(state: &State) -> bool {
    state.telemetry.enabled() || crate::llm::budget::enabled(state) || crate::metrics::llm_metrics_enabled(&state.config)
}

/// The usage read from a forwarded LLM response as it is relayed as a stream (`LlmStreamUsageScanner`).
type StreamUsage = Arc<std::sync::Mutex<crate::llm::stream_usage::Scanner>>;

/// `observeForwardedLlmStream`: start reading the usage out of a forwarded LLM response relayed as a stream (the
/// captured body keeps only the start of a stream, and usage is at its end). `None` when this is not a completion sent
/// to an LLM provider or nothing would use the result.
fn observe_forwarded_llm_stream(state: &State, streaming: &mut crate::forward::Streaming, forwarded: &crate::forward::Forwarded, target: Option<&str>) -> Option<StreamUsage> {
    if !forward_llm_accounting_enabled(state) {
        return None;
    }
    let sent = llm_sent(forwarded);
    let provider = crate::telemetry::sniff(state, target.or(sent.host.as_deref()), &sent.path)?;
    if !crate::telemetry::accountable_operation(&provider, &sent.method, &sent.path).is_some_and(crate::telemetry::Operation::is_completion) {
        return None;
    }
    let scanner: StreamUsage = Arc::new(std::sync::Mutex::new(crate::llm::stream_usage::Scanner::new()));
    let observed = scanner.clone();
    streaming.observe_chunks(move |chunk| observed.lock().unwrap_or_else(std::sync::PoisonError::into_inner).accept(chunk));
    Some(scanner)
}

/// `emitStreamedForwardGenAiSpan`: once every chunk of a relayed stream has passed, its GenAI span and usage, with
/// whether the stream ended in an error.
/// Called after the stream's forwarded-request entry is logged, as upstream's completion listener does.
fn streamed_forward_gen_ai(state: &State, sent: &LlmSent, status: u32, target: Option<&str>, usage: Option<&StreamUsage>, cut_off: bool) {
    let Some(usage) = usage else { return };
    let scanner = usage.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let head = Reply { status, ..Reply::default() };
    forwarded_gen_ai_from(state, sent, &head, target, Some(&scanner), cut_off);
}

/// `emitForwardGenAiSpan` for a forwarded response whose whole (decompressed) body is in hand.
fn forwarded_gen_ai(state: &State, forwarded: &crate::forward::Forwarded, target: Option<&str>) {
    forwarded_gen_ai_from(state, &llm_sent(forwarded), &forwarded.reply, target, None, false);
}

/// `emitForwardGenAiSpan`: a forward to an LLM provider (known by host, or by the configured `llmBaseUrl` /
/// `llmProvider`) reports the upstream's completion in a GenAI span, the LLM token and cost metrics and the cost
/// budget. A response relayed as a stream is read from `streamed`; a whole body that is an event stream aggregated
/// rather than relayed (no usage parsed from it as one JSON document) is scanned as one. Anything unparseable reports
/// nothing.
fn forwarded_gen_ai_from(state: &State, sent: &LlmSent, reply: &Reply, target: Option<&str>, streamed: Option<&crate::llm::stream_usage::Scanner>, cut_off: bool) {
    use crate::llm::stream_usage::Scanner;
    if !forward_llm_accounting_enabled(state) {
        return;
    }
    let target = target.or(sent.host.as_deref());
    let Some(provider) = crate::telemetry::sniff(state, target, &sent.path) else { return };
    // an endpoint that calls no model (`GET /v1/models`, a token count, a batch) is not accounted
    let Some(operation) = crate::telemetry::accountable_operation(&provider, &sent.method, &sent.path) else { return };
    let completion_path = operation.is_completion();
    if streamed.is_some() && !completion_path {
        return;
    }
    let budget = &state.config.metrics.cost_budget;
    // a background completion is polled until it finishes and may be fetched again after, so each is counted once;
    // the claim is released when the usage then cannot be counted
    let claimed_poll = if crate::telemetry::is_polled_completion(&provider, &sent.method, &sent.path) {
        let id = (streamed.is_none() && reply.status == 200).then(|| crate::telemetry::polled_completion_id(&provider, &decompressed(reply))).flatten();
        let Some(key) = id.and_then(|id| budget.claim_polled(&provider, &id)) else { return };
        Some(ClaimedPoll { budget, key: Some(key) })
    } else {
        None
    };
    let aggregated;
    let (completion, scanned): (crate::telemetry::Completion, Option<&Scanner>) = match streamed {
        Some(scanner) => (streamed_completion(&provider, scanner), Some(scanner)),
        None => {
            let body = decompressed(reply);
            let parsed = crate::telemetry::parse_completion_response(&provider, &body, &|name| reply.header(name).map(str::to_string));
            if parsed.as_ref().is_some_and(|c| c.has_usage) {
                (parsed.expect("parsed"), None)
            } else {
                // an event stream that was aggregated rather than relayed as a stream
                let mut scanner = Scanner::new();
                scanner.accept(&body);
                if body.is_empty() || !(scanner.usage().is_some() || scanner.streamed()) {
                    match parsed {
                        Some(c) => (c, None),
                        None => return,
                    }
                } else if scanner.streamed() && !completion_path {
                    return;
                } else {
                    aggregated = scanner;
                    (streamed_completion(&provider, &aggregated), Some(&aggregated))
                }
            }
        }
    };
    if claimed_poll.is_some() && !completion.usage().has_token_counts() {
        return;
    }
    let model = crate::telemetry::forwarded_model(&provider, operation, &completion, &sent.path, &sent.body);
    if let Some(scanned) = scanned {
        log_streamed_usage_unavailable(state, &provider, model.as_deref(), &sent.path, reply.status, &completion, scanned, cut_off);
    }
    if state.telemetry.enabled() {
        crate::telemetry::operation_span(state, operation.gen_ai_name(), &provider, model.as_deref(), &completion);
    }
    let vertex_ai = crate::telemetry::is_vertex_ai_host(target);
    crate::llm::budget::record_at(state, &provider, model.as_deref(), completion.input_tokens.unwrap_or(0), completion.output_tokens.unwrap_or(0), vertex_ai);
    if let Some(mut claimed) = claimed_poll {
        claimed.key = None;
    }
    // a background response counted from its stream must not be counted again when it is fetched
    if let Some(scanned) = scanned.filter(|s| provider == "OPENAI_RESPONSES" && s.final_usage_seen() && completion.usage().has_token_counts()) && let Some(id) = scanned.response_id() {
        budget.mark_polled_counted(&provider, id);
    }
}

/// A polled completion's claim on its id (`claimPolledCompletion`), released when dropped still holding it.
struct ClaimedPoll<'a> {
    budget: &'a crate::llm::budget::CostBudget,
    key: Option<String>,
}

impl Drop for ClaimedPoll<'_> {
    fn drop(&mut self) {
        if let Some(key) = self.key.take() {
            self.budget.release_polled(&key);
        }
    }
}

/// A forwarded response's body as upstream reads it, decompressed.
fn decompressed(reply: &Reply) -> Bytes {
    crate::request::decompress(reply.header("content-encoding"), &reply.body).unwrap_or_else(|| reply.body.clone())
}

/// `streamedCompletion`: the model, stop reason and usage a scanned stream reported.
fn streamed_completion(provider: &str, scanned: &crate::llm::stream_usage::Scanner) -> crate::telemetry::Completion {
    let mut completion = crate::telemetry::Completion { model: scanned.model().map(str::to_string), stop_reason: scanned.stop_reason().map(str::to_string), ..Default::default() };
    if let Some(usage) = scanned.usage().and_then(|u| crate::telemetry::parse_usage(provider, Some(&u))) {
        completion.set_usage(Some(usage));
    }
    completion
}

const STREAMED_USAGE_MISSING: &str = "no token usage in the streamed {} response for model {}, so the call is not counted in LLM token and cost metrics or towards llmCostBudgetUsd";
const STREAMED_USAGE_INCOMPLETE: &str = "the streamed {} response for model {} ended before its final usage event, so only the tokens reported before it ended are counted in LLM token and cost metrics and towards llmCostBudgetUsd";

/// `logStreamedUsageUnavailable`: nothing is estimated in place of missing usage, so the operator is told the call was
/// not (wholly) counted: a WARN once a budget is set, else INFO, at most once a minute per provider and model.
#[allow(clippy::too_many_arguments)]
fn log_streamed_usage_unavailable(
    state: &State,
    provider: &str,
    model: Option<&str>,
    path: &str,
    status: u32,
    completion: &crate::telemetry::Completion,
    scanned: &crate::llm::stream_usage::Scanner,
    cut_off: bool,
) {
    use crate::recorded::{Arg, Level, LogEntry};
    if !(200..=299).contains(&status) {
        return;
    }
    let counted = completion.usage().has_token_counts();
    // a stream that repeats its counts on every chunk is whole unless it was cut off
    let whole = scanned.final_usage_seen() || (scanned.usage_on_every_chunk() && !cut_off);
    if (counted && whole) || !state.config.metrics.cost_budget.usage_log_due(provider, model, counted, state.config.nano_time()) {
        return;
    }
    let lower = path.to_lowercase();
    // Azure serves the Responses API too, where usage is not opt-in; Bedrock serves OpenAI Chat Completions
    let usage_is_opt_in = provider == "OPENAI" || (provider == "AZURE_OPENAI" && !lower.contains("/responses")) || (provider == "BEDROCK" && lower.ends_with("/chat/completions"));
    let format = if counted {
        STREAMED_USAGE_INCOMPLETE.to_string()
    } else if usage_is_opt_in {
        format!("{STREAMED_USAGE_MISSING} - set stream_options.include_usage to true in the client's request for it to be counted")
    } else {
        STREAMED_USAGE_MISSING.to_string()
    };
    let model = model.map_or(Arg::from(serde_json::Value::Null), Arg::from);
    let level = if crate::llm::budget::enabled(state) { Level::Warn } else { Level::Info };
    let entry = LogEntry::at(level, format).args([Arg::from(provider), model]);
    match level {
        Level::Warn => crate::log::warn_event(state, entry),
        _ => crate::log::info_event(state, entry),
    }
}

/// `emitRequestSpan` for a forwarded request.
fn forwarded_span(state: &State, request: &HttpRequest, forwarded: &crate::forward::Forwarded, target: Option<&str>, expectation_id: Option<&str>, started: std::time::Instant, parented: bool) {
    if !state.telemetry.enabled() {
        return;
    }
    let reply = &forwarded.reply;
    let (address, port) = match target.and_then(|t| t.rsplit_once(':')) {
        Some((host, port)) => (Some(host.trim_start_matches('[').trim_end_matches(']')), port.parse().ok()),
        None => (target, None),
    };
    let served = crate::telemetry::Served {
        method: &request.method,
        path: &request.path,
        status: Some(reply.status),
        expectation_id,
        response_time_ms: started.elapsed().as_millis() as i64,
        parented,
        server_address: address,
        server_port: port,
    };
    crate::telemetry::request_span(state, served);
}

/// A streaming-proxy body (`NettyResponseWriter.writeStreamingResponse`), each chunk held by a RESPONSE_STREAM
/// breakpoint matching the request, if any. Upstream's HTTP/3 writer holds nothing.
fn relayed(
    state: &Arc<State>,
    request: &HttpRequest,
    head: Reply,
    chunks: tokio::sync::mpsc::Receiver<Bytes>,
    close: bool,
    upstream_end: Arc<crate::client::StreamEnd>,
    on_end: impl std::future::Future<Output = ()> + Send + 'static,
) -> Outcome {
    let held = match request.protocol {
        "HTTP_3" => None,
        _ => {
            let id = format!("{}-stream", crate::breakpoint::correlation(request));
            crate::breakpoint::stream(state, request, crate::breakpoint::StreamPhase::Response, id, &request.method, &request.path)
        }
    };
    let (chunks, cut) = match held {
        Some(held) => {
            let (chunks, cut) = crate::breakpoint::hold_chunks(held, chunks);
            (chunks, Some(cut))
        }
        None => (chunks, None),
    };
    // The streaming body's completion listeners fire after its last chunk went through the writer (and any frame
    // hold): `on_end` runs once every chunk has passed, before the stream is closed.
    let (tx, out) = tokio::sync::mpsc::channel(16);
    let mut chunks = chunks;
    tokio::spawn(async move {
        // a client that has gone is noticed at once, not at the next chunk, which a quiet upstream may never send
        while let Some(chunk) = tokio::select! { chunk = chunks.recv() => chunk, _ = tx.closed() => None } {
            if tx.send(chunk).await.is_err() {
                // the client has gone: dropping the chunks stops the producer, a forward's upstream with it
                break;
            }
        }
        drop(chunks);
        on_end.await;
        drop(tx);
    });
    Outcome::Stream { head: Box::new(head), chunks: out, close, trailers: None, cut, chunk_count: None, upstream_end: Some(upstream_end) }
}

/// `writeChunkedResponseWithDelay`: with `chunkSize` and `chunkDelay`, the head goes out first, then each chunk after
/// its own sampled delay (an empty body is one empty chunk); the trailers ride the last one. A status that is always
/// empty on HTTP/1.1 has no chunks left to write ([`Reply::omit_body`]).
/// `FinalInformationalResponseWarning.isResetAfterItIsSent`: a `1xx` over HTTP/2 (but `101`) or HTTP/3 can only be an
/// interim response, so its stream is reset after it.
pub(crate) fn is_final_informational(protocol: &str, status: u32) -> bool {
    (100..200).contains(&status) && (protocol == "HTTP_3" || (protocol == "HTTP_2" && status != 101))
}

/// `FinalInformationalResponseWarning.warned`: the expectations warned about, by identity and weakly, so one removed
/// or replaced is warned about afresh. Process-wide: an expectation's identity is its own whichever server holds it.
static FINAL_INFORMATIONAL_WARNED: std::sync::Mutex<Vec<std::sync::Weak<crate::store::Expectation>>> = std::sync::Mutex::new(Vec::new());

fn first_final_informational(expectation: &Arc<crate::store::Expectation>) -> bool {
    let mut warned = FINAL_INFORMATIONAL_WARNED.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    warned.retain(|w| w.strong_count() > 0);
    if warned.iter().any(|w| std::ptr::eq(w.as_ptr(), Arc::as_ptr(expectation))) {
        return false;
    }
    warned.push(Arc::downgrade(expectation));
    true
}

/// `FinalInformationalResponseWarning.warnOnce`'s WARN, about the request.
fn final_informational_warning(request: &HttpRequest, id: &str, status: u32) -> crate::recorded::LogEntry {
    use crate::recorded::{Arg, Level, LogEntry};
    let (protocol, reset) = if request.protocol == "HTTP_3" { ("HTTP/3", "H3_NO_ERROR") } else { ("HTTP/2", "NO_ERROR") };
    let format = format!(
        "expectation:{{}}answered a request over {protocol} with the status:{{}}which {protocol} allows only as an interim response, so MockServer sent it and then reset the stream with {reset} and most clients report the request as failed rather than answered; to answer {protocol} clients give the expectation a status of 200 or above, or to keep the 1xx for HTTP/1.1 clients only add a protocol of HTTP_1_1 to its request matcher (logged once for each expectation)"
    );
    LogEntry::at(Level::Warn, format).args([Arg::from(id), Arg::from(serde_json::json!(status))]).correlation(request.log_correlation_id.clone())
}

fn dribbled(mut reply: Reply) -> Outcome {
    let (Some(size), Some(delay), false) = (reply.chunk_size, reply.chunk_delay.clone(), reply.omit_body) else { return Outcome::respond(reply) };
    let body = std::mem::take(&mut reply.body);
    let close = reply.close;
    let mut pieces: Vec<Bytes> = body.chunks(size.max(1)).map(Bytes::copy_from_slice).collect();
    if pieces.is_empty() {
        pieces.push(Bytes::new());
    }
    let chunk_count = pieces.len();
    let (trailers_tx, trailers) = tokio::sync::oneshot::channel();
    let _ = trailers_tx.send(std::mem::take(&mut reply.trailers));
    let (tx, chunks) = tokio::sync::mpsc::channel(4);
    tokio::spawn(async move {
        for piece in pieces {
            // Stop as soon as the writer is gone (the client reset the stream or closed the connection).
            tokio::select! {
                _ = tokio::time::sleep(delay.sample()) => {}
                _ = tx.closed() => return,
            }
            if tx.send(piece).await.is_err() {
                return;
            }
        }
    });
    Outcome::Stream { head: Box::new(reply), chunks, close, trailers: Some(trailers), cut: None, chunk_count: Some(chunk_count), upstream_end: None }
}

/// `attachMockServedTiming` after a RESPONSE-phase hold (any decision, a timeout too): the logged response's `timing`
/// gains `breakpointHeldMillis`, and its `totalTimeInMillis` the time held (oracle). Jackson writes the
/// block's fields in alphabetical order.
fn attach_breakpoint_timing(logged: &mut serde_json::Value, held: std::time::Duration) {
    let Some(o) = logged.as_object_mut() else { return };
    let held = held.as_millis() as u64;
    let mut timing = o.get("timing").and_then(serde_json::Value::as_object).cloned().unwrap_or_default();
    let total = timing.get("totalTimeInMillis").and_then(serde_json::Value::as_u64).unwrap_or(0) + held;
    timing.insert("breakpointHeldMillis".into(), held.into());
    timing.insert("totalTimeInMillis".into(), total.into());
    timing.sort_keys();
    o.insert("timing".into(), serde_json::Value::Object(timing));
}

/// The logged response with headers `ResponseWriter` added: its `headers` written again as a `keyToMultiValue`
/// (descending keys), placed where `HttpResponseDTO` writes them (after `statusCode`/`reasonPhrase`) when it had none.
fn with_logged_headers(logged: &mut serde_json::Value, added: &[(String, String)]) {
    use serde_json::Value;
    let Some(o) = logged.as_object_mut() else { return };
    let headers = match o.get("headers") {
        Some(Value::Array(list)) => {
            let mut list = list.clone();
            list.extend(added.iter().map(|(name, value)| serde_json::json!({"name": name, "values": [value]})));
            Value::Array(list)
        }
        Some(Value::Object(map)) => {
            let mut map = map.clone();
            map.extend(added.iter().map(|(name, value)| (name.clone(), serde_json::json!([value]))));
            Value::Object(map)
        }
        _ => Value::Object(added.iter().map(|(name, value)| (name.clone(), serde_json::json!([value]))).collect()),
    };
    let headers = crate::canonical::multi_map(&headers);
    let mut out = serde_json::Map::new();
    let mut placed = false;
    for (k, v) in std::mem::take(o) {
        if !placed && !matches!(k.as_str(), "statusCode" | "statusCodeRange" | "reasonPhrase") {
            out.insert("headers".into(), headers.clone());
            placed = true;
        }
        if k != "headers" {
            out.insert(k, v);
        }
    }
    if !placed {
        out.insert("headers".into(), headers);
    }
    *o = out;
}

/// `writeResponseActionResponse`'s chaos and delays for a mock response: a dropped connection (`None`); else the
/// response replaced by a quota or error response (then its own delay is not applied), or reshaped; then the
/// response's delay, `globalResponseDelayMillis` and the chaos latency. With any of those, the logged response
/// carries a `timing` block (`attachMockServedTiming`).
async fn chaos_and_delay<L: LoggedResponse>(
    state: &State,
    injection: Option<&crate::chaos::http::Injection>,
    mut reply: Reply,
    mut logged: L,
    delay: impl FnOnce() -> Option<std::time::Duration>,
    rate_limit: impl FnOnce() -> Option<Reply>,
) -> Result<(Reply, L), Cut> {
    let mut latency = None;
    // `writeResponseActionResponse` resolves the delay of the response it writes: a replacement's (none), so a
    // configured delay template is not rendered (nor its fallback logged) when chaos drops or replaces the response
    let mut replaced = false;
    if injection.is_some_and(|i| i.drops(state)) {
        return Err(Cut::Drop);
    }
    // the rate limit, taken once the connection is not dropped, comes before the chaos quota and error
    let limited = rate_limit();
    if let Some(limited) = limited {
        crate::chaos::http::injected(state, "rateLimit");
        logged = L::from(rate_limit_logged(&limited));
        reply = limited;
        replaced = true;
    }
    if let Some(injection) = injection {
        match (!replaced).then(|| injection.replacement(state)).flatten() {
            Some(replacement) => {
                reply = replacement.reply;
                logged = L::from(replacement.logged);
                replaced = true;
            }
            None if replaced => {}
            None if injection.reshapes() => injection.reshape(state, &mut reply, logged.value_mut()),
            None => {}
        }
        latency = injection.latency(state);
    }
    let delay = if replaced { None } else { delay() };
    let started = std::time::Instant::now();
    let global = global_delay(state);
    let injected_delay = delay.unwrap_or_default() + global.unwrap_or_default();
    let total = injected_delay + latency.unwrap_or_default();
    if !total.is_zero() {
        // `rejectable(write, overloadResponse)`: a delayed write holds a slot of `maxPendingDelayedResponses` while it
        // waits, and is answered with the 503 when none is free
        dispatch_delay(state, total).await?;
    }
    // whole milliseconds: a delay of 1 microsecond (a template's `MICROSECONDS` delay) records no timing
    if latency.is_some() || injected_delay.as_millis() > 0 {
        let mut timing = serde_json::Map::new();
        if let Some(latency) = latency {
            timing.insert("injectedChaosLatencyMillis".into(), (latency.as_millis() as u64).into());
        }
        if injected_delay.as_millis() > 0 {
            timing.insert("injectedDelayMillis".into(), (injected_delay.as_millis() as u64).into());
        }
        timing.insert("totalTimeInMillis".into(), (started.elapsed().as_millis() as u64).into());
        if let Some(o) = logged.value_mut().as_object_mut() {
            o.insert("timing".into(), serde_json::Value::Object(timing));
        }
    }
    Ok((reply, logged))
}

/// A response as logged, owned or shared: a shared one is copied only when chaos or a delay changes it.
trait LoggedResponse: From<serde_json::Value> {
    fn value_mut(&mut self) -> &mut serde_json::Value;
}

impl LoggedResponse for serde_json::Value {
    fn value_mut(&mut self) -> &mut serde_json::Value {
        self
    }
}

impl LoggedResponse for Arc<serde_json::Value> {
    fn value_mut(&mut self) -> &mut serde_json::Value {
        Arc::make_mut(self)
    }
}

/// Why the write funnel answers without the mock's response.
enum Cut {
    /// Chaos dropped the connection.
    Drop,
    /// The delayed task was refused for overload (`HttpActionHandler.overloadResponse`).
    Refused,
}

impl Cut {
    fn outcome(self, state: &State, request: &HttpRequest) -> Outcome {
        match self {
            Cut::Drop => Outcome::DropConnection,
            Cut::Refused => Outcome::respond(crate::overload::refused().finalize(request, &state.config)),
        }
    }
}

/// `Scheduler.delayOptional`: a chaos latency on an already-forwarded response waits while holding a slot of the
/// `maxPendingDelayedResponses` budget, or is skipped (the response sent at once) when none is free: refusing would
/// discard an upstream response whose request has already been sent.
async fn optional_delay(state: &State, latency: std::time::Duration) {
    let _permit = match latency.as_millis() {
        0 => None,
        _ => match state.overload.admit(state, crate::overload::Reason::DelaySkipped, 1) {
            Some(permit) => Some(permit),
            None => return,
        },
    };
    tokio::time::sleep(latency).await;
}

/// `scheduler.schedule(rejectableIfDelayed(…), combineWithGlobalDelay(actionDelay))`, how upstream dispatches a
/// forward, an error and the streaming actions (SSE, WebSocket, gRPC stream, LLM): the action's own delay plus
/// `globalResponseDelayMillis`, waited out holding a slot of `maxPendingDelayedResponses`, or refused with the 503
///.
async fn action_dispatch_delay(state: &State, action_delay: Option<std::time::Duration>) -> Result<(), Cut> {
    let delay = action_delay.unwrap_or_default() + global_delay(state).unwrap_or_default();
    match delay.is_zero() {
        true => Ok(()),
        false => dispatch_delay(state, delay).await,
    }
}

/// `Scheduler.scheduleAfterDelay` for a dispatch upstream wraps as `rejectable`: waits `delay` out while holding a slot
/// of the `maxPendingDelayedResponses` budget, or refuses it when none is free. A delay under a millisecond
/// (`sampleValueMillis` 0) runs as undelayed, never refused.
async fn dispatch_delay(state: &State, delay: std::time::Duration) -> Result<(), Cut> {
    let _permit = match delay.as_millis() {
        0 => None,
        _ => Some(state.overload.admit(state, crate::overload::Reason::DelayedResponses, 1).ok_or(Cut::Refused)?),
    };
    tokio::time::sleep(delay).await;
    Ok(())
}

/// `writeForwardActionResponse`'s rate limit and chaos for a forwarded response: `None` when the connection is
/// dropped, else whether the over-limit, a quota or an error response replaced the upstream's. The logged response
/// keeps the forward's timing header first; a replacement logs without the upstream's timing, and a chaos latency is
/// noted in it otherwise.
async fn forward_chaos(
    state: &State,
    injection: Option<&crate::chaos::http::Injection>,
    forwarded: &mut crate::forward::Forwarded,
    rate_limit: impl FnOnce() -> Option<Reply>,
) -> Option<bool> {
    if injection.is_some_and(|i| i.drops(state)) {
        return None;
    }
    // the rate limit, taken once the connection is not dropped, replaces the upstream's response before chaos would
    if let Some(limited) = rate_limit() {
        crate::chaos::http::injected(state, "rateLimit");
        let logged = rate_limit_logged(&limited);
        replace_forwarded(forwarded, crate::chaos::http::Replacement { reply: limited, logged });
        if let Some(latency) = injection.and_then(|i| i.latency(state)) {
            optional_delay(state, latency).await;
        }
        return Some(true);
    }
    let Some(injection) = injection else { return Some(false) };
    let replaced = match injection.replacement(state) {
        Some(replacement) => {
            replace_forwarded(forwarded, replacement);
            true
        }
        None => {
            injection.reshape(state, &mut forwarded.reply, &mut forwarded.logged_response);
            if let Some((recorded, _)) = forwarded.recorded.as_mut() {
                recorded["httpResponse"] = forwarded.logged_response.clone();
            }
            false
        }
    };
    if let Some(latency) = injection.latency(state) {
        if let Some(timing) = forwarded.timing.as_mut() {
            timing.injected_chaos_latency = Some(latency.as_millis() as i64);
        }
        optional_delay(state, latency).await;
    }
    Some(replaced)
}

/// A quota or error response replacing the upstream's: logged with the forward's timing header first, without the
/// upstream's timing.
fn replace_forwarded(forwarded: &mut crate::forward::Forwarded, replacement: crate::chaos::http::Replacement) {
    let timing_header = forwarded.logged_response.pointer("/headers/x-mockserver-response-time-ms").cloned();
    forwarded.reply = replacement.reply;
    let mut logged = replacement.logged;
    if let (Some(timing), Some(o)) = (timing_header, logged.as_object_mut()) {
        let mut headers = serde_json::Map::new();
        headers.insert("x-mockserver-response-time-ms".into(), timing);
        if let Some(serde_json::Value::Object(h)) = o.get("headers") {
            headers.extend(h.clone());
        }
        o.insert("headers".into(), serde_json::Value::Object(headers));
    }
    forwarded.logged_response = logged;
    forwarded.timing = None;
    if let Some((recorded, _)) = forwarded.recorded.as_mut() {
        recorded["httpResponse"] = forwarded.logged_response.clone();
    }
}

/// The request `analyseDrift` sees: `HttpForwardActionHandler` replaces the received request's `Host` in place, so after
/// a plain `httpForward` it is the forwarded request; the other forward actions send a copy and leave it as received.
fn drift_request<'a>(forward: &crate::forward::Forward, received: &'a HttpRequest, forwarded: &'a HttpRequest) -> &'a HttpRequest {
    match forward {
        crate::forward::Forward::To { .. } => forwarded,
        _ => received,
    }
}

/// `analyseDrift` after a forward (`driftDetectionEnabled`, sampled at `driftSampleRate`): every live expectation
/// is matched against the request again, each evaluation is logged, and the response stubs among the matches are
/// compared with the upstream's response (`DriftAnalyzer`). The forward's continuation first waits for an action
/// scheduler thread (`Scheduler.submit(future, …)`), which semantic drift analyses can all be holding.
async fn drift_pass(state: &Arc<State>, request: &HttpRequest, upstream: &crate::drift::Observed) {
    let _thread = state.drift.scheduler_thread(&state.config).await;
    if !state.config.bool_property("driftDetectionEnabled", true) {
        return;
    }
    let rate = state.config.property("driftSampleRate").and_then(|r| r.trim().parse::<f64>().ok()).unwrap_or(1.0);
    if !crate::chaos::http::should_inject(Some(rate), None) {
        return;
    }
    let (evaluating, request) = (state.clone(), request.clone());
    let matching = move || {
        // `retrieveExpectationsMatchingRequest`: every expectation, whatever its namespace.
        let evaluated = evaluating.store.evaluate_all(&request);
        if evaluating.info_enabled() {
            log_evaluations(&evaluating, &request, &evaluated, None, false);
        }
        evaluated.into_iter().filter(|e| e.matched).map(|e| e.expectation).collect()
    };
    // `writeForwardActionResponse` times the wait for a response that has already arrived (the task runs once the
    // forward completes), so the response time it records is 0 ms.
    crate::drift::analyse_forward(state, matching, upstream, 0);
}

/// `globalResponseDelayMillis`, when positive.
fn global_delay(state: &State) -> Option<std::time::Duration> {
    let millis = state.config.hot_int(crate::config::Hot::GlobalResponseDelayMillis, 0);
    (millis > 0).then(|| std::time::Duration::from_millis(millis as u64))
}

/// A CRUD response as its `EXPECTATION_RESPONSE` log entry records it: `CrudActionHandler` sets its media type on the
/// body (`withBody(json, MediaType.JSON_UTF_8)`), not as a header, so the body is a typed `STRING` carrying it and
/// only the `X-` pagination headers are headers (oracle, scenario `log_level_warn_event_log`).
fn crud_response_json(reply: &Reply) -> serde_json::Value {
    use base64::Engine as _;
    let mut o = serde_json::Map::new();
    o.insert("statusCode".into(), reply.status.into());
    let headers: Vec<(String, String)> = reply.headers.iter().filter(|(k, _)| k.to_ascii_lowercase().starts_with("x-")).cloned().collect();
    if !headers.is_empty() {
        let mut h = serde_json::Map::new();
        for (k, v) in headers {
            h.insert(k, serde_json::json!([v]));
        }
        o.insert("headers".into(), serde_json::Value::Object(h));
    }
    if !reply.body.is_empty() {
        let text = String::from_utf8_lossy(&reply.body).into_owned();
        let body = match reply.header("content-type") {
            Some(ct) => serde_json::json!({
                "type": "STRING",
                "string": text,
                "rawBytes": base64::engine::general_purpose::STANDARD.encode(&reply.body),
                "contentType": ct,
            }),
            None => text.into(),
        };
        o.insert("body".into(), body);
    }
    serde_json::Value::Object(o)
}

/// `dispatchPrimaryActionInternal`: where a WebSocket upgrade matched by a plain `httpForward` is relayed (host, port,
/// TLS): the forward's host and port, or without a host where an unmatched upgrade would go. `None` for any other
/// request or action.
fn forward_relay_target(state: &State, action: &Action, request: &HttpRequest) -> Option<(String, u16, bool)> {
    let Action::Forward(forward) = action else { return None };
    let crate::forward::Forward::To { target, .. } = forward.as_ref() else { return None };
    if !crate::ws_relay::is_upgrade(request) {
        return None;
    }
    match target.host.as_deref().filter(|h| !h.trim().is_empty()) {
        Some(host) => u16::try_from(target.port).ok().map(|port| (host.to_string(), port, target.secure)),
        None => remote_socket(state, request)
            .or_else(|| {
                let host = request.first_header("host").filter(|h| !h.is_empty())?;
                socket_address_from_host_header(host, request.secure).ok()
            })
            .map(|(host, port)| (host, port, request.secure)),
    }
}

/// `RequestMatchers.postProcess`, when dropped: ends the response in progress, and removes (and logs) an
/// expectation the request used up. The removal is logged under a correlation id of its own
/// (`removeHttpRequestMatcher(httpRequestMatcher, UUIDService.getUUID())`), not the request's, so the dashboard does
/// not group it with the request's entries.
/// The server is held (`Arc`) by a guard that outlives the request's handling, else borrowed: a clone per request
/// wrote the server's reference count, which every request worker shares.
pub(crate) struct PostProcess<S: std::ops::Deref<Target = State> = Arc<State>> {
    pub(crate) state: S,
    pub(crate) expectation: Option<Arc<crate::store::Expectation>>,
}

impl<S: std::ops::Deref<Target = State>> Drop for PostProcess<S> {
    fn drop(&mut self) {
        if let Some(e) = self.expectation.take()
            && self.state.store.post_process(&e)
        {
            crate::control::log_removals(&self.state, &[e], &uuid::Uuid::new_v4().to_string());
        }
    }
}

/// The DEBUG diagnostic for a namespaced request that matched nothing while other tenants' expectations were
/// skipped (`RequestMatchers.firstMatchingExpectation`).
fn log_namespace_silence(state: &State, request: &HttpRequest, namespace: Option<&str>) {
    let Some(namespace) = namespace else { return };
    if !crate::log::debug_enabled(state) {
        return;
    }
    // Counted over every stored matcher, before its liveness is checked (`namespaceSkipped++` precedes it).
    let skipped = state.store.all().iter().filter(|e| !crate::namespace::admits(e.namespace.as_deref(), Some(namespace))).count();
    if skipped == 0 {
        return;
    }
    let format = format!("request in namespace:{{}}did not match any expectation; {skipped} expectation(s) skipped due to namespace mismatch");
    let entry = crate::recorded::LogEntry::new(crate::recorded::Kind::ExpectationNotMatched, format).level(crate::recorded::Level::Debug).args([namespace]);
    state.log.message_about(entry, crate::recorded::Subject::Request(Arc::new(request.clone())));
}

/// `EXPECTATION_MATCHED` / `EXPECTATION_NOT_MATCHED` for each expectation matching tried, then, when none
/// matched, the closest one among those the request's `namespace` admits (`RequestMatchers.firstMatchingExpectation`).
pub(crate) fn log_evaluated(state: &State, request: &HttpRequest, evaluated: &[crate::store::Evaluated], namespace: Option<Option<&str>>) {
    log_evaluations(state, request, evaluated, namespace, true);
}

/// `detailed`: the mismatch reasons carry their differences (a `MatchDifference` context was given). `unmatched`:
/// nothing matched, so the closest expectation is logged, chosen among those its namespace admits.
pub(crate) fn log_evaluations(state: &State, request: &HttpRequest, evaluated: &[crate::store::Evaluated], unmatched: Option<Option<&str>>, detailed: bool) {
    crate::blocking::off_worker_when_large(request.body.len(), || {
        let shown = crate::recorded::LoggedRequest::of(request);
        log_evaluations_logged(state, request, &shown, Some(&shown.request), None, evaluated, unmatched, detailed)
    });
}

/// [`log_evaluations`] with the request's logged form (`shown`) already built.
/// The WARN the commit of a matched expectation raised (`consumeSharedTimesCounter`), after its matched entry.
fn log_commit_warning(state: &State, e: &crate::store::Evaluated) {
    if let Some(text) = &e.warning {
        crate::log::warn_event(state, crate::recorded::LogEntry::at(crate::recorded::Level::Warn, text.clone()));
    }
}

/// An evaluated expectation as its matching entries print it (`logged_expectation_ending` of its snapshot), shared
/// between the requests that evaluate it while its `times` stay the same: building, comparing
/// (`share_expectation`) and dropping a fresh copy per request was most of the INFO cost of a match. The printed form
/// depends only on the expectation (its canonical form and end date never change) and the snapshot's `times`.
/// Remembered per thread, keyed by the expectation's address; each entry holds a weak reference to it, which keeps
/// that address from being reused by a new expectation while the entry exists.
fn logged_expectation(e: &crate::store::Evaluated) -> std::rc::Rc<LoggedExpectation> {
    use std::cell::RefCell;
    use std::collections::HashMap;
    // the snapshot's `times` follow from its remaining count alone, which keys the printed form
    type Cached = (std::sync::Weak<crate::store::Expectation>, i64, std::rc::Rc<LoggedExpectation>);
    thread_local! {
        static LOGGED: RefCell<HashMap<usize, Cached>> = RefCell::new(HashMap::new());
    }
    const REMEMBERED: usize = 256;
    let key = Arc::as_ptr(&e.expectation) as usize;
    // A walk entry took no snapshot: its `times` are the expectation's own now.
    let remaining = e.snapshot_remaining();
    LOGGED.with(|logged| {
        let mut logged = logged.borrow_mut();
        // the weak reference keeps the address taken while it is remembered, so an entry is always this expectation's
        if let Some((.., shown)) = logged.get(&key).filter(|(_, cached, _)| *cached == remaining) {
            return shown.clone();
        }
        let snapshot = e.expectation.current_at(remaining);
        let json = crate::log_entry::Json::new(crate::canonical::logged_matched_expectation(&snapshot, e.expectation.end_date_millis()));
        let shown = std::rc::Rc::new(LoggedExpectation { json, block: Default::default(), weight: Default::default() });
        if logged.len() >= REMEMBERED {
            logged.clear();
        }
        logged.insert(key, (Arc::downgrade(&e.expectation), remaining, shown.clone()));
        shown
    })
}

/// [`logged_expectation`]: the printed form, with its block in a message and its weight worked out the first time they
/// are needed.
struct LoggedExpectation {
    json: crate::log_entry::Json,
    block: std::cell::OnceCell<String>,
    weight: std::cell::OnceCell<u64>,
}

impl LoggedExpectation {
    /// Its text (`log_value`) as an argument of a log message shows it ([`crate::matcher::argument_block_into`]).
    fn block(&self) -> &str {
        self.block.get_or_init(|| argument_block(|text| crate::recorded::log_value_into(text, &self.json)))
    }

    /// Its weight against the event log's byte budget.
    fn weight(&self) -> u64 {
        *self.weight.get_or_init(|| crate::recorded::expectation_weight(&self.json))
    }
}

/// The entries of [`log_evaluations`], the request's logged form (`shown`) built already; `subject`, when given, is a
/// request held already that equals `request`, which the entries are about instead of a copy.
#[allow(clippy::too_many_arguments)]
fn log_evaluations_logged(
    state: &State,
    request: &HttpRequest,
    shown: &crate::recorded::LoggedRequest,
    subject: Option<&Arc<HttpRequest>>,
    before: Option<&HttpRequest>,
    evaluated: &[crate::store::Evaluated],
    unmatched: Option<Option<&str>>,
    detailed: bool,
) -> Option<ClosestScan> {
    use crate::recorded::{Arg, Kind, LogEntry, Subject};
    // `detailedMatchFailures=false`: the context the scan passes records no differences, but hints are still written;
    // so does a match without a context (`failFast` generates them whenever it builds the because, e.g. the HTTP/3 bidi
    // peek recorded from the oracle).
    let reasons = match (detailed, state.config.hot_bool(crate::config::Hot::DetailedMatchFailures, true)) {
        (false, _) => crate::matcher::Reasons::Hints,
        (true, true) => crate::matcher::Reasons::Full,
        (true, false) => crate::matcher::Reasons::Hints,
    };
    let millis = regex_timeout_millis(state);
    // Without a context (`detailed` false) nothing records a difference, so none logs at TRACE.
    let trace = detailed && trace_enabled(state);
    // the request the entries are about: `subject`, a request held already that equals it, or a copy
    let logged = subject.cloned().unwrap_or_else(|| Arc::new(request.clone()));
    // the entry's expectation and its argument are one value
    let matched = |expectation: crate::log_entry::Json| {
        LogEntry::new(Kind::ExpectationMatched, "request:{}matched expectation:{}").request_logged(request, shown).args([shown.arg(), Arg::from(expectation.clone())]).expectation_shared(expectation)
    };
    let matched_shown = shown;
    // The scan ran before the match set path parameters on the request; its entries show the request as it is now.
    let request = before.unwrap_or(request);
    let not_matched = |label: String, expectation: crate::log_entry::Json, because: String| {
        let entry = LogEntry::new(Kind::ExpectationNotMatched, label.clone()).request_logged(request, shown).expectation_shared(expectation.clone());
        match because.is_empty() {
            true => entry.args([shown.arg(), Arg::from(expectation)]),
            false => {
                let entry = entry.with_format(format!("{label}:{{}}because:{{}}"));
                entry.because(because.clone()).args([shown.arg(), expectation.into(), because.into()])
            }
        }
    };
    let mut budget = NotMatchedLogBudget::of(state);
    // The request's weight against the event log's byte budget, which each of its deferred entries adds.
    let request_weight = std::cell::OnceCell::new();
    // `fullScanClosestMatchAndLazyRemoval`: when the candidate index narrowed the scan and nothing matched, the
    // expectations outside it are evaluated (and logged) after it, in match order, at most
    // `CLOSEST_MATCH_MAX_EVALUATIONS` of them; the rest are counted as not checked.
    let mut walk = ClosestWalk::default();
    // The expectations the walk goes through, which its entries name by place.
    let mut walked = None;
    if let Some(namespace) = unmatched {
        let scanned: std::collections::HashSet<*const crate::store::Expectation> = evaluated.iter().map(|e| Arc::as_ptr(&e.expectation)).collect();
        let admissible = walked.insert(state.store.admissible(namespace));
        walk.extra.reserve(admissible.len().saturating_sub(scanned.len()).min(CLOSEST_MATCH_MAX_EVALUATIONS));
        for (at, (e, path_misses)) in admissible.iter_with_path_misses(&request.path).enumerate() {
            if !scanned.is_empty() && scanned.contains(&Arc::as_ptr(e)) {
                walk.checked += 1;
                continue;
            }
            if walk.extra.len() == CLOSEST_MATCH_MAX_EVALUATIONS {
                walk.not_checked += 1;
                continue;
            }
            walk.checked += 1;
            // One its literal path fails is not evaluated: it cannot match and meets no regex timeout.
            if path_misses {
                walk.extra.push(Walked { at: at as u32, matched: false, plain: true, timeouts: NO_TIMEOUTS });
                continue;
            }
            // Its regex timeouts are met again, from the cache, by the logging below; past the budget they are kept
            // for it instead.
            let (matched, timeouts) = crate::matcher::regex_timeouts(millis, || e.matcher.matches(request, crate::matcher::Mode::DataPlane));
            let kept = if timeouts.is_empty() {
                NO_TIMEOUTS
            } else {
                walk.timeouts.push(timeouts);
                (walk.timeouts.len() - 1) as u32
            };
            walk.extra.push(Walked { at: at as u32, matched, plain: false, timeouts: kept });
        }
    }
    let debug = crate::log::debug_enabled(state);
    for i in 0..evaluated.len() + walk.extra.len() {
        // A walk entry takes no snapshot: the few entries the budget admits read the expectation when they are logged.
        let made;
        let e = match i.checked_sub(evaluated.len()) {
            None => &evaluated[i],
            Some(j) => {
                let w = &walk.extra[j];
                let expectation = walked.as_ref().map(|a| a.get(w.at as usize)).expect("walked");
                // A walk entry past the budget: withheld, and the regex timeouts its walk match met are logged,
                // which is all the general path below does for it (the re-evaluation meets the same ones), without the
                // second match of each of up to 1,000 expectations.
                let logs_as_expectation = || w.plain || (!skipped_unsupported(expectation) && expectation.matcher.logs_as_expectation());
                if !debug && !w.matched && budget.exhausted() && logs_as_expectation() {
                    budget.admit();
                    if w.timeouts != NO_TIMEOUTS {
                        log_regex_timeouts(state, std::mem::take(&mut walk.timeouts[w.timeouts as usize]));
                    }
                    continue;
                }
                made = crate::store::Evaluated { expectation: expectation.clone(), remaining: None, matched: w.matched, active: true, warning: None };
                &made
            }
        };
        if skipped_unsupported(&e.expectation) {
            continue;
        }
        // A conditional or OpenAPI expectation logs from the matchers it is made of.
        let (logs, timeouts) = crate::matcher::regex_timeouts(millis, || e.expectation.matcher.match_logs(request, reasons, crate::log::debug_enabled(state), trace));
        if let Some(logs) = logs {
            // Their matchers reject a used-up or expired expectation without logging anything.
            if !e.active {
                continue;
            }
            log_regex_timeouts(state, timeouts);
            for mut entry in logs {
                if let crate::matcher::Logged::Branch { notes, .. } = &mut entry {
                    log_match_notes(state, std::mem::take(notes), request);
                }
                // Each branch's or operation's did-not-match entry draws on the request's budget.
                let not_matched_entry = matches!(entry, crate::matcher::Logged::Branch { matched: false, .. } | crate::matcher::Logged::Operation { matched: false, .. });
                if not_matched_entry && !budget.admit() {
                    continue;
                }
                let entry = match entry {
                    crate::matcher::Logged::Branch { matched: true, expectation, .. } => matched(crate::log_entry::Json::new(expectation)),
                    crate::matcher::Logged::Branch { matched: false, id, expectation, because, .. } => {
                        not_matched(format!("request:{{}}didn't match expectation \"{id}\""), crate::log_entry::Json::new(expectation), because)
                    }
                    crate::matcher::Logged::Operation { matched: true, request: operation, .. } => {
                        LogEntry::new(Kind::ExpectationMatched, "request:{}matched request:{}").request_logged(request, matched_shown).args([matched_shown.arg(), Arg::from(&operation)])
                    }
                    crate::matcher::Logged::Operation { matched: false, description, request: operation, because } => {
                        LogEntry::new(Kind::ExpectationNotMatched, format!("request:{{}}didn't match{description} request matcher:{{}}because:{{}}"))
                            .request_logged(request, shown)
                            .because(because.clone())
                            .args([shown.arg(), (&operation).into(), because.into()])
                    }
                };
                state.log.message_about(entry, Subject::Request(logged.clone()));
            }
            log_commit_warning(state, e);
            continue;
        }
        // The scan's fail-fast match wrote its `would match` DEBUG entries and its differences' TRACE entries before
        // the result, and its regex timeouts (`runRegexWithTimeout`) before all: the re-evaluation meets them again,
        // from the cache, at no cost.
        // `maxLoggedMatchFailures`: past the budget the did-not-match entry, and its because text, are left out.
        let logs_entry = e.matched || budget.admit();
        let because = || e.expectation.matcher.because_with(request, reasons);
        let ((notes, because), timeouts) = crate::matcher::regex_timeouts(millis, || {
            let notes = if e.active && crate::log::debug_enabled(state) { e.expectation.matcher.match_notes(request, true, trace) } else { Vec::new() };
            // Past the budget no because text is built, but the fail-fast match the scan ran still met its timeouts.
            if e.active && !e.matched && !logs_entry {
                e.expectation.matcher.matches(request, crate::matcher::Mode::DataPlane);
            }
            (notes, (e.active && !e.matched && logs_entry).then(because))
        });
        log_regex_timeouts(state, timeouts);
        log_match_notes(state, notes, request);
        if !logs_entry {
            if !e.active {
                crate::control::log_lazy_removals(state, Some(&e.expectation.id));
            }
            continue;
        }
        let logged_form = logged_expectation(e);
        let expectation = logged_form.json.clone();
        // An entry about a request the log holds already: built when the log is read, its console line written from
        // its parts.
        if let Some(subject) = subject {
            let weight_of_request = || *request_weight.get_or_init(|| crate::recorded::request_weight(subject));
            let live = e.expectation.clone();
            if e.matched {
                const FORMAT: &str = "request:{}matched expectation:{}";
                let weight = || crate::recorded::message_weight(weight_of_request(), logged_form.weight(), "");
                let text = |out: &mut String, scratch: &mut String| {
                    crate::matcher::format_log_message_blocks_into(out, 0, FORMAT, 2, |i, out| match i {
                        0 => shown.json.write_block(out, scratch),
                        _ => out.push_str(logged_form.block()),
                    })
                };
                let shown = shown.clone();
                state.log.message_about_deferred_with(crate::recorded::Level::Info, Kind::ExpectationMatched, subject.clone(), Some(&weight), Some(&text), move || {
                    let live = live.clone();
                    LogEntry::new(Kind::ExpectationMatched, FORMAT)
                        .request_logged(&shown.request, &shown)
                        .args([shown.arg(), Arg::from(expectation.clone())])
                        .expectation_shared(expectation.clone())
                        .live_expectation(move || crate::canonical::logged_matched_expectation(&live.current(), live.end_date_millis()), None)
                });
            } else {
                // A used-up or expired one has an empty because, which the format drops and the arguments keep.
                let because = if e.active { because.unwrap_or_default() } else { String::new() };
                let format = not_matched_format(&e.expectation.id, &because);
                let weight = || crate::recorded::message_weight(weight_of_request(), logged_form.weight(), &because);
                let arguments = if e.active && because.is_empty() { 2 } else { 3 };
                let text = |out: &mut String, scratch: &mut String| {
                    crate::matcher::format_log_message_blocks_into(out, 0, &format, arguments, |i, out| match i {
                        0 => shown.json.write_block(out, scratch),
                        1 => out.push_str(logged_form.block()),
                        _ => crate::matcher::argument_block_into(out, 0, &because),
                    })
                };
                let (shown, active, because) = (shown.clone(), e.active, because.clone());
                state.log.message_about_deferred_with(crate::recorded::Level::Info, Kind::ExpectationNotMatched, subject.clone(), Some(&weight), Some(&text), move || {
                    let entry = LogEntry::new(Kind::ExpectationNotMatched, not_matched_format(&live.id, "")).request_logged(&shown.request, &shown).expectation_shared(expectation.clone());
                    let entry = match (active, because.is_empty()) {
                        (false, _) => entry.because("").args([shown.arg(), expectation.clone().into(), String::new().into()]),
                        (true, true) => entry.args([shown.arg(), Arg::from(expectation.clone())]),
                        (true, false) => entry.with_format(not_matched_format(&live.id, &because)).because(because.clone()).args([shown.arg(), expectation.clone().into(), because.clone().into()]),
                    };
                    let live = live.clone();
                    entry.live_expectation(move || crate::canonical::logged_matched_expectation(&live.current(), live.end_date_millis()), None)
                });
            }
            log_commit_warning(state, e);
            if !e.active {
                crate::control::log_lazy_removals(state, Some(&e.expectation.id));
            }
            continue;
        }
        let entry = if e.matched {
            matched(expectation)
        } else if !e.active {
            // `HttpRequestPropertiesMatcher.matches` with an empty because: the format drops it, the arguments do not.
            LogEntry::new(Kind::ExpectationNotMatched, format!("request:{{}}didn't match expectation \"{}\"", e.expectation.id))
                .request_logged(request, shown)
                .expectation_shared(expectation.clone())
                .because("")
                .args([shown.arg(), expectation.into(), String::new().into()])
        } else {
            not_matched(format!("request:{{}}didn't match expectation \"{}\"", e.expectation.id), expectation, because.unwrap_or_default())
        };
        // The entry holds the expectation itself, as it is when the log is read (its argument is a copy).
        let live = e.expectation.clone();
        let entry = entry.live_expectation(move || crate::canonical::logged_matched_expectation(&live.current(), live.end_date_millis()), None);
        state.log.message_about(entry, Subject::Request(logged.clone()));
        log_commit_warning(state, e);
        // `scheduleLazyRemoval` follows the not-matched entry of a used-up or expired expectation.
        if !e.active {
            crate::control::log_lazy_removals(state, Some(&e.expectation.id));
        }
    }
    let namespace = unmatched?;
    // The namespace gate runs before matching, so another tenant's expectation is never the closest.
    // A used-up or expired expectation the scan met is never offered (upstream 65a116781): it fails with no
    // recorded difference, and would otherwise rank closest for every unmatched request.
    let records = state.config.hot_bool(crate::config::Hot::DetailedMatchFailures, true);
    let candidates = state.store.admissible(namespace);
    // Past the evaluation cap only the expectations checked compete.
    let checked: Option<std::collections::HashSet<*const crate::store::Expectation>> = (walk.not_checked > 0).then(|| {
        let walked = walked.as_ref().map(|a| walk.extra.iter().map(|w| Arc::as_ptr(a.get(w.at as usize)))).into_iter().flatten();
        evaluated.iter().map(|e| Arc::as_ptr(&e.expectation)).chain(walked).collect()
    });
    let (live_closest, timeouts) = crate::matcher::regex_timeouts(millis, || {
        closest_match(candidates.iter_with_path_misses(&request.path).filter(|(e, _)| checked.as_ref().is_none_or(|c| c.contains(&Arc::as_ptr(e)))), request, |_| records)
    });
    // Under `detailedMatchFailures=false` the hint's scan records what an OpenAPI matcher's own contexts record, so it
    // differs from this one; otherwise the two are the same evaluation (unless this one stopped at the cap).
    let scan = (records && checked.is_none()).then(|| ClosestScan { candidates, closest: live_closest.clone(), timeouts });
    let closest = live_closest.map(|(closest, _)| {
        // `countMatchedApplicableFields` re-evaluates it without fail-fast, meeting its regex timeouts again.
        let ((notes, count), timeouts) = crate::matcher::regex_timeouts(millis, || {
            let notes = if crate::log::debug_enabled(state) { closest.matcher.match_notes(request, false, trace_enabled(state)) } else { Vec::new() };
            (notes, closest.matcher.matched_field_count(request))
        });
        log_regex_timeouts(state, timeouts);
        log_match_notes(state, notes, request);
        (closest, count)
    });
    match (closest, subject) {
        (Some((closest, count)), Some(subject)) => {
            // the expectation as it is now, as a walk entry shows it
            let logged_form = logged_expectation(&crate::store::Evaluated { expectation: closest.clone(), remaining: None, matched: false, active: true, warning: None });
            let format = format!("closest expectation:{{}}matched {count}/10 fields for request:{{}}{}", walk.note(&budget));
            let weight = || crate::recorded::message_weight(*request_weight.get_or_init(|| crate::recorded::request_weight(subject)), logged_form.weight(), "");
            let text = |out: &mut String, scratch: &mut String| {
                crate::matcher::format_log_message_blocks_into(out, 0, &format, 2, |i, out| match i {
                    0 => out.push_str(logged_form.block()),
                    _ => shown.json.write_block(out, scratch),
                })
            };
            let (shown, expectation, live, format) = (shown.clone(), logged_form.json.clone(), closest.clone(), format.clone());
            state.log.message_about_deferred_with(crate::recorded::Level::Info, Kind::ExpectationNotMatched, subject.clone(), Some(&weight), Some(&text), move || {
                let live = live.clone();
                LogEntry::new(Kind::ExpectationNotMatched, format.clone())
                    .request_logged(&shown.request, &shown)
                    .expectation(serde_json::Value::clone(&expectation))
                    .args([Arg::from(expectation.clone()), shown.arg()])
                    .live_expectation(move || crate::canonical::logged_matched_expectation(&live.current(), live.end_date_millis()), None)
            });
        }
        (Some((closest, count)), None) => {
            let expectation = crate::canonical::logged_matched_expectation(&closest.current(), closest.end_date_millis());
            let live = closest.clone();
            let entry = LogEntry::new(Kind::ExpectationNotMatched, format!("closest expectation:{{}}matched {count}/10 fields for request:{{}}{}", walk.note(&budget)))
                .request_logged(request, shown)
                .expectation(expectation.clone())
                .args([Arg::from(&expectation), shown.arg()])
                .live_expectation(move || crate::canonical::logged_matched_expectation(&live.current(), live.end_date_millis()), None);
            state.log.message_about(entry, Subject::Request(logged));
        }
        (None, _) => {}
    }
    scan
}

/// A did-not-match entry's format: with its because, when it has one.
fn not_matched_format(id: &str, because: &str) -> String {
    let mut format = String::with_capacity(id.len() + 64);
    format.push_str("request:{}didn't match expectation \"");
    format.push_str(id);
    format.push('"');
    if !because.is_empty() {
        format.push_str(":{}because:{}");
    }
    format
}

/// The text `write` writes, as an argument of a log message shows it ([`crate::matcher::argument_block_into`]); the
/// text is written into a buffer the thread keeps, so only the block is allocated.
fn argument_block(write: impl FnOnce(&mut String)) -> String {
    thread_local! {
        static TEXT: std::cell::RefCell<String> = const { std::cell::RefCell::new(String::new()) };
    }
    let block_of = |text: &str| {
        // each line takes an indent
        let mut block = String::with_capacity(text.len() + 2 * text.bytes().filter(|&b| b == b'\n').count() + 8);
        crate::matcher::argument_block_into(&mut block, 0, text);
        block
    };
    TEXT.with(|kept| {
        let mut text = kept.take();
        text.clear();
        write(&mut text);
        let block = block_of(&text);
        *kept.borrow_mut() = text;
        block
    })
}

/// `RequestMatchers.DEFAULT_CLOSEST_MATCH_MAX_EVALUATIONS`: the most expectations an unmatched request's INFO
/// closest-match walk evaluates beyond the candidate index's, and the most the 404 hint scan checks.
const CLOSEST_MATCH_MAX_EVALUATIONS: usize = 1000;

/// The INFO closest-match walk beyond the candidate index (`ClosestMatchAccumulator`): the expectations it evaluated,
/// and how many were checked in all and how many were left unchecked past the cap.
#[derive(Default)]
struct ClosestWalk {
    extra: Vec<Walked>,
    /// The regex timeouts the walk met: those of each of `extra` that met any.
    timeouts: Vec<Vec<crate::matcher::RegexTimeout>>,
    checked: usize,
    not_checked: usize,
}

/// One expectation the closest-match walk evaluated, held by its place among the admissible ones rather than by a
/// reference count: up to 1,000 of them per request, shared by every request worker.
struct Walked {
    at: u32,
    matched: bool,
    /// Its literal path failed the request ([`crate::store::Candidates::iter_with_path_misses`]): a plain matcher, which
    /// logs as the expectation.
    plain: bool,
    /// Its regex timeouts' place in [`ClosestWalk::timeouts`]; [`NO_TIMEOUTS`] when it met none.
    timeouts: u32,
}

const NO_TIMEOUTS: u32 = u32::MAX;

/// `DnsRequestPropertiesMatcher.matches` and `BinaryRequestPropertiesMatcher.matches` reject an HTTP request without
/// logging anything. Only an unsupported matcher is either.
fn skipped_unsupported(e: &crate::store::Expectation) -> bool {
    e.matcher.is_unsupported() && (e.dns.is_some() || crate::canonical::is_binary_request(&e.canonical["httpRequest"]))
}

impl ClosestWalk {
    /// The closest-match line's suffixes: the entries the budget left out, then the expectations the cap left out.
    fn note(&self, budget: &NotMatchedLogBudget) -> String {
        let mut note = budget.note();
        if self.not_checked > 0 {
            if !note.is_empty() {
                note.push_str("; ");
            }
            note.push_str(&format!(
                "only {} of {} expectations were checked, so a closer one may exist",
                self.checked,
                self.checked + self.not_checked
            ));
        }
        note
    }
}

/// `NotMatchedLogBudget`: how many `EXPECTATION_NOT_MATCHED` entries one request may still write
/// (`maxLoggedMatchFailures`, default 50; negative: no limit, 0: none), and how many it withheld.
pub(crate) struct NotMatchedLogBudget {
    left: Option<i64>,
    withheld: u64,
}

impl NotMatchedLogBudget {
    pub(crate) fn of(state: &State) -> Self {
        let limit = state.config.int_property("maxLoggedMatchFailures", 50);
        NotMatchedLogBudget { left: (limit >= 0).then_some(limit), withheld: 0 }
    }

    /// Whether one more entry may be written; counts it as written, or as withheld when the budget is used up.
    pub(crate) fn admit(&mut self) -> bool {
        match &mut self.left {
            None => true,
            Some(left) if *left > 0 => {
                *left -= 1;
                true
            }
            Some(_) => {
                self.withheld += 1;
                false
            }
        }
    }

    /// Whether no more entries may be written ([`NotMatchedLogBudget::admit`] would withhold the next one).
    pub(crate) fn exhausted(&self) -> bool {
        self.left == Some(0)
    }

    /// The closest-match line's note on the entries left out (empty when none were).
    pub(crate) fn note(&self) -> String {
        match self.withheld {
            0 => String::new(),
            n => format!("{n} further did-not-match entries were not logged (maxLoggedMatchFailures)"),
        }
    }
}

/// The expectation closest to an unmatched request, with the fields that did not match it.
type Closest = (Arc<crate::store::Expectation>, Vec<(&'static str, crate::matcher::Difference)>);

/// One closest-match scan of an unmatched request (with records in every context): the candidates it went through,
/// in order, its result and the regex timeouts it met.
pub(crate) struct ClosestScan {
    candidates: crate::store::Candidates,
    closest: Option<Closest>,
    timeouts: Vec<crate::matcher::RegexTimeout>,
}

impl ClosestScan {
    /// This scan's result and timeouts, when a scan of `candidates` would be the same evaluation: the same
    /// expectations in the same order (an expectation's matcher never changes; a regex timeout, once met, is met
    /// again from the cache).
    fn reused_for(
        self,
        candidates: &crate::store::Candidates,
    ) -> Option<(Option<Closest>, Vec<crate::matcher::RegexTimeout>)> {
        self.candidates.same(candidates).then_some((self.closest, self.timeouts))
    }
}

/// `RegexStringMatcher`'s DEBUG `matcher{}would match{}if matcher was used for control plane`: the
/// request's value is a `SensitiveLogValue` (upstream c76143e4a), masked under `redactSecretsInLog`; and
/// the TRACE entry of each difference the match recorded.
fn log_match_notes(state: &State, notes: Vec<crate::matcher::MatchNote>, request: &HttpRequest) {
    if !crate::log::debug_enabled(state) {
        return;
    }
    let mut about = None;
    for note in notes {
        let difference = matches!(note, crate::matcher::MatchNote::Difference(_));
        let entry = match_note_entry(note, request);
        crate::log::entry(state, &entry);
        match difference {
            // about the request (`setHttpRequest`): a log clear that matches it removes the entry
            true => state.log.message_about(entry, crate::recorded::Subject::Request(about.get_or_insert_with(|| Arc::new(request.clone())).clone())),
            false => state.log.message(entry),
        }
    }
}

/// Whether TRACE events are logged: the matchers then log each difference they record.
pub(crate) fn trace_enabled(state: &State) -> bool {
    state.log_level == "TRACE"
}

/// `MatchDifference.addDifference(mockServerLogger, …)`'s TRACE entry (`message` already formatted), about `request`.
pub(crate) fn difference_entry(message: String, request: &HttpRequest) -> crate::recorded::LogEntry {
    crate::recorded::LogEntry::at(crate::recorded::Level::Trace, message).request(request)
}

/// `regexMatchingTimeoutMillis` as the server started (8.0.0's matchers read `ConfigurationProperties`, so a value
/// set over `PUT /mockserver/configuration` changes nothing).
fn regex_timeout_millis(state: &State) -> i64 {
    state.config.int_startup_property("regexMatchingTimeoutMillis", 5000)
}

/// `RegexStringMatcher.runRegexWithTimeout`'s WARN for each regex evaluation that outlived its budget; a
/// pattern that is the request's value is a `SensitiveLogValue` (upstream c76143e4a).
fn log_regex_timeouts(state: &State, timeouts: Vec<crate::matcher::RegexTimeout>) {
    for t in timeouts {
        if t.thrown {
            crate::log::error_event(state, regex_timeout_entry(t));
        } else {
            crate::log::warn_event(state, regex_timeout_entry(t));
        }
    }
}

/// Runs a control-plane operation (retrieve, verify, clear) under the startup `regexMatchingTimeoutMillis`, logging
/// each filter evaluation that times out. The operation calls [`flush_regex_timeouts`] before each of
/// its own entries, as upstream logs the WARN while it evaluates; the rest is logged at the end.
/// At TRACE it also logs the differences its matches of received requests record, likewise.
pub(crate) fn control_plane_regex_scope<R>(state: &State, f: impl FnOnce() -> R) -> R {
    let ((result, differences), rest) =
        crate::matcher::regex_timeouts_each(regex_timeout_millis(state), || crate::matcher::tracing_received(trace_enabled(state), f));
    log_regex_timeouts(state, rest);
    log_differences(state, differences);
    result
}

/// Logs the timeouts and differences the current [`control_plane_regex_scope`] has met so far.
pub(crate) fn flush_regex_timeouts(state: &State) {
    log_regex_timeouts(state, crate::matcher::take_regex_timeouts());
    log_differences(state, crate::matcher::take_received_trace());
}

fn log_differences(state: &State, differences: Vec<(String, crate::matcher::Traced)>) {
    for (message, about) in differences {
        match about {
            crate::matcher::Traced::Request(request) => {
                let entry = difference_entry(message, &request);
                crate::log::entry(state, &entry);
                state.log.message_about(entry, crate::recorded::Subject::Request(Arc::new(*request)));
            }
            crate::matcher::Traced::Definition(definition) => {
                let entry = crate::recorded::LogEntry::at(crate::recorded::Level::Trace, message).request_json(definition.clone());
                crate::log::entry(state, &entry);
                state.log.message_about(entry, crate::recorded::Subject::Definition(definition));
            }
        }
    }
}

fn regex_timeout_entry(t: crate::matcher::RegexTimeout) -> crate::recorded::LogEntry {
    if t.thrown {
        return crate::recorded::LogEntry::at(crate::recorded::Level::Error, "exception validating JSON");
    }
    const FORMAT: &str = "regex evaluation timed out after {}ms for pattern:{}— treating as non-match (raise mockserver.regexMatchingTimeoutMillis or simplify the pattern to suppress this)";
    // `MatchingTimeoutExecutor.matchesWithRegexTimeout` prefixes its site's description.
    let format = t.description.map_or_else(|| FORMAT.to_string(), |d| format!("{d} {FORMAT}"));
    crate::recorded::LogEntry::at(crate::recorded::Level::Warn, format)
    .args([crate::recorded::Arg::from(serde_json::json!(t.millis)), if t.sensitive { crate::recorded::Arg::sensitive(t.pattern) } else { t.pattern.into() }])
}

fn match_note_entry(note: crate::matcher::MatchNote, request: &HttpRequest) -> crate::recorded::LogEntry {
    match note {
        crate::matcher::MatchNote::WouldMatch(w) => would_match_entry(w),
        crate::matcher::MatchNote::Difference(message) => difference_entry(message, request),
    }
}

fn would_match_entry(w: crate::matcher::WouldMatch) -> crate::recorded::LogEntry {
    crate::recorded::LogEntry::at(crate::recorded::Level::Debug, "matcher{}would match{}if matcher was used for control plane")
        .args([crate::recorded::Arg::from(w.matcher.as_str()), crate::recorded::Arg::sensitive(w.matched)])
}

/// `HttpResponseActionHandler.synthesizeGraphQLResponse`: a response without a body, matched by a `GRAPHQL` body that
/// carries a schema, answers the request's query with a body synthesized from that schema (`graphql_schema`); a
/// failure is logged and leaves the body unset.
fn graphql_synthesized(state: &State, canonical: &serde_json::Value, respond: &action::Respond, request: &HttpRequest) -> Option<(action::Respond, String)> {
    if respond.file.is_some() || respond.generated.is_some() {
        return None;
    }
    let response = canonical.get("httpResponse")?;
    if response.get("body").is_some_and(|b| !b.is_null()) || response.get("generateFromSchema").is_some_and(|g| !g.is_null()) {
        return None;
    }
    let body = canonical.get("httpRequest").and_then(|r| r.get("body")).filter(|b| b.get("type").and_then(serde_json::Value::as_str) == Some("GRAPHQL"))?;
    let schema = body.get("schema").and_then(serde_json::Value::as_str).filter(|s| !s.trim().is_empty())?;
    let query = request.body_str();
    if query.trim().is_empty() {
        return None;
    }
    match crate::graphql_schema::Schema::build(schema).and_then(|s| s.synthesize(&query)) {
        Ok(text) => {
            let mut synthesized = respond.clone();
            synthesized.reply.body = bytes::Bytes::from(text.clone());
            synthesized.reply.default_content_type = Some("application/json".into());
            Some((synthesized, text))
        }
        Err(message) => {
            let format = "unable to synthesize GraphQL response from registered schema, leaving response body unset because:{}";
            crate::log::warn_event(state, crate::recorded::LogEntry::new(crate::recorded::Kind::Warn, format).request(request).args([message.as_str()]));
            None
        }
    }
}

/// The over-limit response as the write funnel logs it: map-form headers in descending key order.
fn rate_limit_logged(reply: &Reply) -> serde_json::Value {
    let headers: serde_json::Map<String, serde_json::Value> = reply.headers.iter().map(|(k, v)| (k.clone(), serde_json::json!([v]))).collect();
    crate::canonical::response(&serde_json::json!({"statusCode": reply.status, "headers": headers, "body": String::from_utf8_lossy(&reply.body)}))
}

/// The action a file-body 500 is logged as served by (`handleAnyException`'s `writeResponseActionResponse`): the
/// response with its `FILE` body printed as an empty string (8.0.0).
fn file_error_action(mut action: serde_json::Value) -> serde_json::Value {
    if let Some(body) = action.get_mut("body") {
        *body = serde_json::Value::String(String::new());
    }
    action
}

/// The response with its `FILE` body read (and rendered); `Err` is the reply to send instead: a 500 when the file
/// cannot be read (`fileBodyErrorResponse`), a 404 when its template fails.
/// What a response that could not be materialised is answered with: the reply, its logged form and the WARN
/// `handleAnyException` logs after it (a `FILE` body's template that failed to render). Boxed: a reply is large and
/// this is the failure path.
type Fallback = Box<(Reply, serde_json::Value, Option<Box<crate::recorded::LogEntry>>)>;

fn materialise(state: &State, respond: &action::Respond, request: &HttpRequest) -> Result<Reply, Fallback> {
    materialise_or_fail(state, respond, request).map_err(|failed| match failed {
        Unmaterialised::Render(failure) => render_failure_fallback(state, failure),
        Unmaterialised::Fallback(fallback) => fallback,
    })
}

/// Why a response could not be materialised: its `FILE` body's template failed to render, or the answer to send
/// instead is already built (the file-body 500).
enum Unmaterialised {
    Render(action::RenderFailure),
    Fallback(Fallback),
}

/// `handleAnyException`: the 404, then a WARN entry at INFO level whose format is the exception's message.
fn render_failure_fallback(state: &State, failure: action::RenderFailure) -> Fallback {
    let after = state.info_enabled().then(|| {
        crate::log::info_as(state, crate::recorded::Kind::Warn, &failure.message);
        let entry = crate::recorded::LogEntry::new(crate::recorded::Kind::Warn, failure.message.clone()).level(crate::recorded::Level::Info);
        let entry = entry.throwable(format!("java.lang.RuntimeException: {}", failure.message));
        Box::new(match failure.bean {
            Some(bean) => entry.throwable_bean(bean),
            None => entry,
        })
    });
    Box::new((Reply::not_found(), not_found_json(), after))
}

fn materialise_or_fail(state: &State, respond: &action::Respond, request: &HttpRequest) -> Result<Reply, Unmaterialised> {
    if let Some(cause) = &respond.generate_failure {
        let format = "unable to generate a schema-valid response from the inline JSON schema, leaving response body unset because:{}";
        crate::log::warn_event(state, crate::recorded::LogEntry::new(crate::recorded::Kind::Warn, format).args([cause.as_str()]));
    }
    let Some(file) = &respond.file else { return Ok(respond.reply.clone()) };
    let mut reply = respond.reply.clone();
    match file.materialise(Some(state), request) {
        Ok(Ok((body, content_type))) => {
            reply.body = body;
            reply.default_content_type = content_type;
            Ok(reply)
        }
        Ok(Err(failure)) => Err(Unmaterialised::Render(failure)),
        Err(e) => {
            log_file_body_error(state, request, &e);
            let mut reply = Reply::status(500);
            reply.reason = Some("Internal Server Error".into());
            reply.body = Bytes::from_static(b"Error reading file for response body");
            Err(Unmaterialised::Fallback(Box::new((reply, serde_json::json!({"statusCode": 500, "reasonPhrase": "Internal Server Error", "body": "Error reading file for response body"}), None))))
        }
    }
}

/// `CallbackWebSocketServerHandler`'s ERROR for a message whose materialising threw: `web socket server caught
/// exception`, the throwable `Exception while receiving web socket message<message>` caused by the template's.
fn log_received_message_failure(state: &State, message: &str, failure: action::RenderFailure) {
    if !crate::log::error_enabled(state) {
        return;
    }
    let text = format!("Exception while receiving web socket message{message}");
    let cause = failure.bean.unwrap_or_else(|| serde_json::json!({"localizedMessage": failure.message, "message": failure.message, "stackTrace": []}));
    let bean = serde_json::json!({"cause": cause, "localizedMessage": text, "message": text, "stackTrace": []});
    let trace = crate::log::throwable_text(&["java.lang.RuntimeException", "java.lang.RuntimeException"], &bean);
    let entry = crate::recorded::LogEntry::at(crate::recorded::Level::Error, "web socket server caught exception").throwable(&trace).throwable_bean(bean);
    crate::log::error_event(state, entry);
}

/// `submitFileBodyResponse`: a matched response with a `FILE` body is materialised on the file read pool, off the
/// network tasks; `None` when the file read queue is full (the caller answers the 503). Other responses are
/// materialised in place.
async fn materialise_file_body(state: &Arc<State>, respond: &action::Respond, request: &HttpRequest) -> Option<Result<Reply, Fallback>> {
    if respond.file.is_none() {
        return Some(materialise(state, respond, request));
    }
    let (on_pool, respond, request) = (state.clone(), respond.clone(), request.clone());
    state.overload.file_read(state, crate::overload::Reason::FileBodies, move || materialise(&on_pool, &respond, &request)).await
}

/// What `serveStaticFileOrReturnNotFound` answers an unmatched, unproxied request with.
enum StaticAnswer {
    /// The file the request names, and the response as logged.
    Served(Box<Reply>, serde_json::Value),
    /// The file read queue is full: the 503.
    Refused,
    /// No file may be served: the usual 404.
    NotServed,
}

/// `serveStaticFileOrReturnNotFound`: a `GET` or `HEAD` outside the control plane is answered from
/// `staticFilesDirectory`, read on the file read pool; a file that cannot be read is logged at WARN and not served.
async fn static_file(state: &Arc<State>, request: &HttpRequest) -> StaticAnswer {
    let Some(directory) = state.static_files.clone() else { return StaticAnswer::NotServed };
    if !crate::static_files::StaticFileDirectory::is_servable_method(&request.method) || crate::cors_origin::is_control_plane_request(request, &state.config) {
        return StaticAnswer::NotServed;
    }
    let (method, path) = (request.method.clone(), request.path.clone());
    let Some(read) = state.overload.file_read(state, crate::overload::Reason::StaticFiles, move || directory.respond(&method, &path)).await else {
        return StaticAnswer::Refused;
    };
    let file = match read {
        Ok(Some(file)) => file,
        Ok(None) => return StaticAnswer::NotServed,
        Err(e) => {
            let format = "returning 404 as the static file for request:{}could not be served";
            let entry = crate::recorded::LogEntry::new(crate::recorded::Kind::Warn, format).args([crate::recorded::logged(request)]);
            crate::log::warn_event_about(state, entry.throwable(format!("java.io.IOException: {e}")), request);
            return StaticAnswer::NotServed;
        }
    };
    let mut reply = Reply::status(200);
    reply.headers.push(("content-type".into(), file.content_type.into()));
    let mut logged = serde_json::json!({"statusCode": 200, "headers": {"content-type": [file.content_type]}});
    match file.body {
        Some(body) => {
            use base64::Engine as _;
            logged["body"] = serde_json::json!({"type": "BINARY", "base64Bytes": base64::engine::general_purpose::STANDARD.encode(&body), "contentType": file.content_type});
            reply.body = body;
        }
        None => {
            reply.headers.push(("content-length".into(), file.size.to_string()));
            logged["headers"]["content-length"] = serde_json::json!([file.size.to_string()]);
        }
    }
    StaticAnswer::Served(Box::new(reply), logged)
}

/// `logFileBodyError`: an event-log entry about the request with the `FileBodyException`.
fn log_file_body_error(state: &State, request: &HttpRequest, e: &action::FileBodyError) {
    if crate::log::error_enabled(state) {
        let format = "unable to read file \"{}\" for response body, returning 500 because:{}";
        let bean = e.bean();
        let trace = crate::log::throwable_text(&e.classes(), &bean);
        let entry = crate::recorded::LogEntry::at(crate::recorded::Level::Error, format).request(request).args([e.path.as_str(), e.message.as_str()]).throwable(&trace).throwable_bean(bean);
        crate::log::error_with_throwable(state, &entry, Some(request), &trace);
        state.log.message_about(entry, crate::recorded::Subject::Request(Arc::new(request.clone())));
    }
}

/// An SSE event's delay: one unbounded delayed task (`scheduler.schedule(writeEvent, false, delay)` with no rejectable
/// wrapper), counted while it waits; a delay under a millisecond runs inline, uncounted.
async fn sse_event_delay(state: &State, delay: std::time::Duration) {
    let _pending = (delay.as_millis() > 0).then(|| state.overload.unbounded_delayed());
    tokio::time::sleep(delay).await;
}

/// `HttpSseResponseActionHandler`: the head (`text/event-stream`, `no-cache`, the connection decision, chunked,
/// then the action's headers), then each event after its delay, rendered when the action names a template type.
async fn sse_stream(state: &Arc<State>, sse: &action::Sse, request: &HttpRequest) -> Outcome {
    let close = sse.close_connection.unwrap_or(!request.keep_alive) || state.config.bool_property("alwaysCloseSocketConnections", false);
    let mut head = Reply::status(sse.status);
    let mut set = |name: &str, value: String| {
        head.headers.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
        head.headers.push((name.to_string(), value));
    };
    set("content-type", "text/event-stream".into());
    set("cache-control", "no-cache".into());
    set("connection", if close { "close" } else { "keep-alive" }.into());
    set("transfer-encoding", "chunked".into());
    for (name, value) in &sse.headers {
        set(name, value.clone());
    }
    // `Http3ResponseWriter.respondingDirectly` (upstream 18b3a36e7): over HTTP/3 the HTTP/1.1 objects are turned into
    // frames by `Http3HttpObjectEncoder` (`src/http3.rs`); the events are the same code on every protocol.
    head.written_as_http1_objects = request.transport() == crate::request::Protocol::Http3;
    let (tx, rx) = tokio::sync::mpsc::channel(16);
    let format = sse.format;
    let events = sse.events.clone();
    let template = sse.template;
    // `streamBreakpoint`: a RESPONSE_STREAM breakpoint holds each event before it is written.
    let id = format!("{}-stream", crate::breakpoint::correlation(request));
    // `request.getReceivedTimestamp()`, set as `HttpState.handle` takes the request: the time it is dispatched here
    let received = chrono::Utc::now().timestamp_millis();
    let held = crate::breakpoint::stream(state, request, crate::breakpoint::StreamPhase::Response, id, &request.method, &request.path).map(|held| held.on_event_loop().received_at(received));
    // the head goes out once the first event's dispatch has (`HeldStream::dispatched`)
    let first_dispatched = held.as_ref().map(crate::breakpoint::HeldStream::dispatched);
    let (state, request) = (Arc::clone(state), request.clone());
    // `JSON_ARRAY`: `[` before the first element, `,\r\n` between elements and `]` once the stream ran to completion.
    let json_array = format == crate::llm::codec::Format::JsonArray;
    tokio::spawn(async move {
        if json_array && tx.send(bytes::Bytes::from_static(b"[")).await.is_err() {
            return;
        }
        let mut written = false;
        for event in events {
            if let Some(delay) = &event.delay {
                let delay = delay.resolve(&state, &request);
                // `scheduler.schedule(writeEvent, false, delay)`: the head does not wait for a delayed event
                if let Some(held) = held.as_ref().filter(|_| !delay.is_zero()) {
                    held.open_gate();
                }
                sse_event_delay(&state, delay).await;
            }
            if tx.is_closed() {
                return;
            }
            let mut event = event;
            if let (Some(engine), Some(data)) = (template, event.data.as_ref()) && let Ok(rendered) = crate::templates::render_text(&state, &state.velocity_engines.sse, engine, data, &request) {
                event.data = Some(rendered);
            }
            // CLOSE ends the stream there, without a JSON array's closing bracket (`finishStream`).
            let Some(frames) = crate::breakpoint::pass(held.as_ref(), event.framed(format), Vec::clone, |_, bytes| bytes).await else { return };
            for mut framed in frames {
                if json_array && std::mem::replace(&mut written, true) {
                    framed.splice(0..0, *b",\r\n");
                }
                if tx.send(bytes::Bytes::from(framed)).await.is_err() {
                    return;
                }
            }
        }
        if json_array {
            let _ = tx.send(bytes::Bytes::from_static(b"]")).await;
        }
    });
    if let Some(dispatched) = first_dispatched {
        let _ = dispatched.await;
    }
    Outcome::Stream { head: Box::new(head), chunks: rx, close, trailers: None, cut: None, chunk_count: None, upstream_end: None }
}

/// `validateProxyResponse`: the upstream response checked against the operation the request selects; under
/// `validateProxyEnforce` a violating one is replaced by a 502 naming the violations.
fn validate_proxy_response(state: &State, spec: &str, request: &HttpRequest, reply: &Reply, enforce: bool) -> Option<Reply> {
    let operation_id = crate::openapi_validation::operation_id(spec, request)?;
    let body = String::from_utf8_lossy(&reply.body);
    let headers: crate::request::MultiMap = reply.headers.iter().map(|(k, v)| (k.clone(), vec![v.clone()])).collect();
    let response = crate::openapi_validation::Response { status: reply.status, headers: &headers, body: &body };
    let errors = crate::openapi::checking_spec_fetches(&state.config, || crate::openapi_validation::validate_response(spec, &operation_id, &response));
    if errors.is_empty() {
        return None;
    }
    let entry = crate::recorded::LogEntry::new(crate::recorded::Kind::OpenapiResponseValidationFailed, "validation proxy: upstream response does not conform to OpenAPI spec{}errors:{}")
        .level(crate::recorded::Level::Warn)
        .args([crate::recorded::Arg::from(crate::recorded::logged(request)), errors.join("; ").into()]);
    crate::log::entry_as(state, crate::recorded::Level::Warn, &entry);
    state.log.message_about(entry, crate::recorded::Subject::Request(Arc::new(request.clone())));
    enforce.then(|| {
        let mut rejected = Reply::status(502);
        rejected.body = bytes::Bytes::from(format!("OpenAPI response validation failed: {}", errors.join("; ")));
        rejected
    })
}

/// The frames `Throwable.printStackTrace` shows under a refused connect, in the oracle image (verified against 8.0.0).
const CONNECT_FRAMES: &str = "\n\tat java.base/sun.nio.ch.Net.pollConnect(Native Method)
\tat java.base/sun.nio.ch.Net.pollConnectNow(Unknown Source)
\tat java.base/sun.nio.ch.SocketChannelImpl.finishConnect(Unknown Source)
\tat shaded_package.io.netty.channel.socket.nio.NioSocketChannel.doFinishConnect(NioSocketChannel.java:330)
\tat shaded_package.io.netty.channel.nio.AbstractNioChannel$AbstractNioUnsafe.finishConnect(AbstractNioChannel.java:384)
\tat shaded_package.io.netty.channel.nio.AbstractNioChannel$AbstractNioUnsafe.handle(AbstractNioChannel.java:432)
\tat shaded_package.io.netty.channel.nio.NioIoHandler$DefaultNioRegistration.handle(NioIoHandler.java:388)
\tat shaded_package.io.netty.channel.nio.NioIoHandler.processSelectedKey(NioIoHandler.java:596)
\tat shaded_package.io.netty.channel.nio.NioIoHandler.processSelectedKeysPlain(NioIoHandler.java:541)
\tat shaded_package.io.netty.channel.nio.NioIoHandler.processSelectedKeys(NioIoHandler.java:514)
\tat shaded_package.io.netty.channel.nio.NioIoHandler.run(NioIoHandler.java:484)
\tat shaded_package.io.netty.channel.SingleThreadIoEventLoop.runIo(SingleThreadIoEventLoop.java:225)
\tat shaded_package.io.netty.channel.SingleThreadIoEventLoop.run(SingleThreadIoEventLoop.java:196)
\tat shaded_package.io.netty.util.concurrent.SingleThreadEventExecutor$5.run(SingleThreadEventExecutor.java:1204)
\tat shaded_package.io.netty.util.internal.ThreadExecutorMap$2.run(ThreadExecutorMap.java:74)
\tat java.base/java.lang.Thread.run(Unknown Source)";

/// `Scheduler`'s completion callback for a failed client future: a WARN entry at INFO level, about no request.
fn log_scheduler_warning(state: &State, message: &str) {
    log_scheduler_warning_with(state, message, None);
}

/// [`log_scheduler_warning`] with the entry's throwable: the first lines of its stack trace, which the dashboard shows.
fn log_scheduler_warning_with(state: &State, message: &str, throwable: Option<&str>) {
    // The entry is a WARN-typed one at INFO level, which the oracle prints as INFO, the throwable after the message;
    // `MockServerLogger.logEvent` drops it below `logLevel` INFO.
    if !state.info_enabled() {
        return;
    }
    match throwable {
        Some(trace) => crate::log::info_with_throwable(state, crate::recorded::Kind::Warn, message, &format!("{trace}{CONNECT_FRAMES}")),
        None => crate::log::info_as(state, crate::recorded::Kind::Warn, message),
    }
    let mut entry = crate::recorded::LogEntry::new(crate::recorded::Kind::Warn, message).level(crate::recorded::Level::Info);
    if let Some(trace) = throwable {
        entry = entry.throwable(trace);
    }
    state.log.message(entry);
}

/// An `EXCEPTION` entry at ERROR level, about `request` when given; also written to the console.
fn log_exception(state: &State, message: &str, request: Option<&HttpRequest>) {
    crate::log::error(state, message);
    let subject = request.map_or(crate::recorded::Subject::None, |r| crate::recorded::Subject::Request(Arc::new(r.clone())));
    state.log.message_about(crate::recorded::LogEntry::new(crate::recorded::Kind::Exception, message), subject);
}

/// `ForwardHeaderLimit.refuse`'s entry (upstream a78886b4d, after 8.0.0): a WARN about no request naming the upstream
/// connection's remote socket, `address` as `InetSocketAddress.toString` prints it and `dashboard` as Jackson does.
fn log_header_limit_refusal(state: &State, address: String, dashboard: String, reason: &str) {
    let entry = crate::recorded::LogEntry::at(crate::recorded::Level::Warn, "failing forward to:{}because:{}")
        .args([crate::recorded::Arg::socket_address_as(address, dashboard), reason.into()]);
    crate::log::warn_event(state, entry);
}

/// `ForwardHeaderLimit.refuse`'s entry for a forward whose remote socket is the forwarded request's `Host`,
/// unresolved (`InetSocketAddress.createUnresolved`).
pub(crate) fn log_forward_header_limit(state: &State, forwarded: &HttpRequest, reason: &str) {
    let target = forwarded.first_header("host").and_then(|host| socket_address_from_host_header(host, forwarded.secure).ok());
    if let Some((host, port)) = target {
        log_header_limit_refusal(state, format!("{host}/<unresolved>:{port}"), format!("{host}:{port}"), reason);
    }
}

/// `InetSocketAddress.toString` of `new InetSocketAddress(host, port)`: `/ip:port` for a literal address, else
/// `host/ip:port` resolved (IPv4 first) or `host/<unresolved>:port`.
fn java_socket_address(host: &str, port: u16) -> String {
    match host.parse::<std::net::IpAddr>() {
        Ok(ip) => format!("/{}:{port}", crate::server::java_host_address(ip)),
        Err(_) => match crate::inet_address::lookup_blocking(host, port).ok().and_then(|a| a.into_iter().min_by_key(std::net::SocketAddr::is_ipv6)) {
            Some(address) => format!("{host}/{}:{port}", crate::server::java_host_address(address.ip())),
            None => format!("{host}/<unresolved>:{port}"),
        },
    }
}

/// `handleExceptionDuringForwardingRequest`'s loop hint (upstream 48b7e14d2, 9.1.0): an `httpForward` whose target is
/// the address the request was received on, which failed for running out of local ports or for a reason nothing names
/// (not a header limit or a failure `upstreamFailureReason` names, which answer first).
pub(crate) fn forward_loop_hint(expectation: &serde_json::Value, request: &HttpRequest, error: &crate::client::Error) -> Option<&'static str> {
    use crate::client::Error;
    if matches!(error.underlying(), Error::HeaderLimit(..)) || error.is_named_failure() {
        return None;
    }
    let reason = error.connect_failure_reason(true);
    if reason.as_deref().is_some_and(|r| r != crate::client::OUT_OF_LOCAL_REASON) {
        return None;
    }
    let forward = expectation.get("httpForward")?;
    let host = forward.get("host").and_then(serde_json::Value::as_str)?;
    let port = forward.get("port").and_then(serde_json::Value::as_u64).and_then(|p| u16::try_from(p).ok())?;
    crate::client::targets_receiving_address(host, port, &request.local_address).then_some(crate::client::FORWARD_LOOP_HINT)
}

/// `handleExceptionDuringForwardingRequest` then `returnBadGateway`: why an expectation's forward got no response,
/// logged with the 502 it answers (a `NO_MATCH_RESPONSE`, served by no expectation). `exception_class`: the
/// forward's future carries Netty's connect exception itself, which prints with its class.
fn forward_failed(state: &State, request: &HttpRequest, error: &crate::client::Error, expectation: &serde_json::Value, exception_class: bool, response: serde_json::Value) {
    use crate::client::Error;
    let shown = crate::recorded::log_value(&crate::recorded::logged(request));
    let loop_hint = forward_loop_hint(expectation, request, error);
    let error = match error {
        // `UpstreamConnectFailure.reason` (upstream 48b7e14d2, 9.1.0): the cause and its fix, with the loop hint for a
        // forward back to the receiving address that ran out of local ports; the failure itself is logged at TRACE
        // only, and the scheduler logs nothing for the failed future.
        _ if error.connect_failure_reason(true).is_some() => {
            error.connect_failure_reason(true).unwrap_or_default()
        }
        // a connection that failed for a reason nothing names (a refused one is named above)
        _ if error.is_connection_failure() => "failed to connect to remote socket while forwarding request".to_string(),
        Error::Tls => {
            let mut action = expectation.as_object().cloned().unwrap_or_default();
            action.retain(|k, _| k.starts_with("http"));
            action.remove("httpRequest");
            let action = action.values().next().map(crate::json::pretty).unwrap_or_default();
            let text = crate::matcher::format_log_message(0, "TLS handshake exception while forwarding request{}for action{}", &[&shown, &action]);
            log_exception(state, &text, Some(request));
            "TLS handshake exception while forwarding request".to_string()
        }
        Error::TooLarge(message) => {
            // The client's own handler logs it first (about no request), then the action handler.
            log_scheduler_warning(state, message);
            log_exception(state, message, Some(request));
            message.clone()
        }
        // `ForwardHeaderLimit.refuse` logs the refusal as the client raises it (upstream a78886b4d, after 8.0.0); the
        // scheduler then logs the failed future, and `returnedHeaderLimitFailure` answers with the reason, logging
        // nothing more.
        Error::HeaderLimit(reason, connect_failure) => {
            // The connection's remote socket: `createUnresolved(host, port)` from `httpForward`,
            // `httpForwardWithFallback` and `httpForwardValidate` with a host; any other action passes none, so the
            // client resolves the request's `Host` (`socketAddressFromHostHeader`), as the oracle prints it.
            let unresolved = ["httpForward", "httpForwardWithFallback"].iter().any(|k| expectation.get(*k).is_some())
                || expectation.pointer("/httpForwardValidate/host").is_some_and(|h| !h.is_null());
            let target = request.first_header("host").and_then(|host| socket_address_from_host_header(host, request.secure).ok());
            match target {
                Some((host, port)) if !unresolved => log_header_limit_refusal(state, java_socket_address(&host, port), format!("{host}:{port}"), reason),
                _ => log_forward_header_limit(state, request, reason),
            }
            // An upstream proxy's CONNECT reply fails the connection: the future carries `ProxyConnectException`.
            // A future that carries the exception itself (override and validate handlers, a retried forward) prints
            // with its class, as for a refused connection.
            let failure = match connect_failure {
                Some(connect_failure) => connect_failure.clone(),
                None if exception_class => format!("{}: {reason}", error.exception_class()),
                None => reason.clone(),
            };
            log_scheduler_warning(state, &failure);
            reason.clone()
        }
        // `upstreamFailureReason` (upstream 7a8b8c424, after 8.0.0): one ERROR about the request, and the scheduler's
        // entry for the failed future is skipped.
        _ if error.is_named_failure() => {
            let reason = error.exception_message().unwrap_or_default();
            let action = expectation.as_object().and_then(|o| o.iter().find(|(k, _)| k.starts_with("http") && *k != "httpRequest")).map(|(_, v)| v.clone()).unwrap_or_default();
            let entry = crate::recorded::LogEntry::at(crate::recorded::Level::Error, "failed to forward request{}for action{}because:{}")
                .request(request)
                .args([crate::recorded::Arg::from(crate::recorded::logged(request)), action.into(), reason.as_str().into()]);
            crate::log::error_event(state, entry);
            reason
        }
        Error::Protocol => "unknown error".to_string(),
        // Netty's direct-memory limit: everything was logged where the client failed.
        Error::DirectMemory { .. } => error.exception_string(),
        // Any other exception: the client logs it, then the handler logs the wrapped exception (its `toString`) and
        // answers with that.
        // `exception_class`: the future the scheduler waits on is a dependent stage, so it is told of a
        // `CompletionException`, whose message is the cause's `toString`.
        other => {
            log_scheduler_warning(state, &if exception_class { other.exception_string() } else { other.logged_message() });
            let wrapped = other.exception_string();
            log_exception(state, &wrapped, Some(request));
            wrapped
        }
    };
    // the loop hint appended to the error (`returnLoopHintOrBadGateway`, and a reason that ran out of local ports)
    let error = match loop_hint {
        Some(hint) if error.is_empty() => hint.to_string(),
        Some(hint) => format!("{error}; {hint}"),
        None => error,
    };
    let mut message = crate::recorded::LogEntry::new(crate::recorded::Kind::NoMatchResponse, "failed to forward request:{}error:{}returning response:{}")
        .args([crate::recorded::Arg::from(crate::recorded::logged(request)), error.into(), (&response).into()]);
    // `returnBadGateway(…, expectationId)` (upstream f143fa299, 9.1.0): the entry names the expectation whose forward
    // failed; the exchange itself stays unserved, so verification by expectation id does not count it
    if let Some(id) = expectation.get("id").and_then(serde_json::Value::as_str) {
        message = message.expectation_id(id);
    }
    let _ = shown;
    match state.info_enabled() {
        true => state.log.record_with_message(request.clone(), response, None, message),
        false => state.log.record(request.clone(), response, None),
    }
}

/// `writeForwardActionResponse`'s log line, for a forward whose sent request differs from the logged one: the
/// response with the client's `timing`, the request as sent and as curl, the action and its expectation.
/// `replaced`: a chaos error or quota response replaced the upstream's. A `FORWARDED_REQUEST`, kept whatever the
/// `logLevel` (`writeForwardActionResponse` asks none).
/// The logged response with the forwarding client's `timing` (`HttpResponse.withTiming`), when it measured one.
fn with_timing(logged_response: &serde_json::Value, timing: Option<crate::client::Timing>) -> serde_json::Value {
    let mut response = crate::recorded::logged_response(logged_response);
    if let (Some(timing), Some(o)) = (timing, response.as_object_mut()) {
        o.insert("timing".into(), timing.json());
    }
    response
}

fn forwarded_message(forwarded: &crate::forward::Forwarded, expectation: &serde_json::Value, id: &str, replaced: bool) -> Option<crate::recorded::LogEntry> {
    let (sent, curl) = forwarded.sent.as_ref().filter(|_| forwarded.recorded.is_some())?;
    let mut response = crate::recorded::logged_response(&forwarded.logged_response);
    if let (Some(timing), Some(o)) = (forwarded.timing, response.as_object_mut()) {
        o.insert("timing".into(), timing.json());
    }
    let action = expectation.as_object()?.iter().find(|(k, _)| k.starts_with("http") && *k != "httpRequest").map(|(_, v)| v.clone()).unwrap_or_default();
    let format = if replaced {
        "returning chaos-injected error response:{}replacing forwarded response\n\n in json:{}\n\n in curl:{}for action:{}from expectation:{}"
    } else {
        "returning response:{}for forwarded request\n\n in json:{}\n\n in curl:{}for action:{}from expectation:{}"
    };
    let mut entry = crate::recorded::LogEntry::new(crate::recorded::Kind::ForwardedRequest, format)
        .response(response.clone())
        .expectation_id(id)
        .args([crate::recorded::Arg::from(&response), sent.into(), curl.into(), (&action).into(), id.into()]);
    // The recorded expectation as the model serialises it: bodies bare, its response the logged one with the timing;
    // `setHttpRequest(request)` is the request it records.
    entry.expectation = forwarded.recorded.as_ref().map(|(canonical, _)| {
        let mut recorded = canonical.clone();
        if let Some(o) = recorded.as_object_mut() {
            if let Some(r) = o.get("httpRequest").cloned().map(crate::recorded::model_json) {
                o.insert("httpRequest".into(), r);
            }
            if let Some(recorded_response) = o.get("httpResponse") {
                // its body as the model serialises it: a JSON body with a non-default content type stays typed
                // (oracle)
                let body = recorded_response.get("body").map(|b| crate::recorded::model_json(serde_json::json!({"body": b}))["body"].clone());
                let mut response = response.clone();
                if let (Some(body), Some(r)) = (body, response.as_object_mut().filter(|r| r.contains_key("body"))) {
                    r.insert("body".into(), body);
                }
                o.insert("httpResponse".into(), response);
            }
        }
        crate::log_entry::Json::new(recorded)
    });
    // `setExpectation(request, response)`
    entry.synthetic_expectation = entry.expectation.is_some();
    if let Some(r) = forwarded.recorded.as_ref().and_then(|(canonical, _)| canonical.get("httpRequest")) {
        entry = entry.request_json(crate::recorded::with_bare_body(r));
    }
    Some(entry)
}

/// A forward's `responseTemplate` failed (not merely rendered output that is not valid, which keeps the upstream's
/// response without `templateFailureAsServerError`). The scheduler logs the failed future (a `CompletionException`
/// about no request), then `returnedTemplateFailure` logs the engine's failure and answers `500` without a response
/// entry; without `templateFailureAsServerError` it is any failed forward: logged, and answered 502.
fn forward_response_template_failed(state: &State, request: &HttpRequest, failed: &templates::Failed, expectation_id: &str) -> Reply {
    use crate::recorded::{Kind, Level, LogEntry};
    let server_error = templates::failure_as_server_error(state);
    let failure = if server_error { failed.template_failure() } else { (*failed.logged).clone() };
    let future = failure.java_string();
    if state.info_enabled() {
        crate::log::info_as(state, Kind::Warn, &future);
        // logged on the scheduler thread that completes the future, which carries no port of its own
        state.log.message(LogEntry::new(Kind::Warn, future.clone()).level(Level::Info).without_port().throwable(future.clone()).throwable_bean(failure.wrapped_bean()));
    }
    if server_error {
        let logged = &failed.logged;
        crate::log::error(state, &logged.message);
        let entry = LogEntry::new(Kind::Exception, logged.message.clone()).level(Level::Error).throwable(logged.java_string()).throwable_bean(logged.bean.clone());
        state.log.message_about(entry, crate::recorded::Subject::Request(Arc::new(request.clone())));
        return templates::failure_reply(failed).0;
    }
    // `handleExceptionDuringForwardingRequest`: the exception is the future's cause, logged with its `toString`
    crate::log::error(state, &future);
    let entry = LogEntry::new(Kind::Exception, future.clone()).level(Level::Error).throwable(future.clone()).throwable_bean(failure.wrapped_bean());
    state.log.message_about(entry, crate::recorded::Subject::Request(Arc::new(request.clone())));
    let response = serde_json::json!({"statusCode": 502, "reasonPhrase": "Bad Gateway"});
    let message = LogEntry::new(Kind::NoMatchResponse, "failed to forward request:{}error:{}returning response:{}")
        .expectation_id(expectation_id)
        .args([crate::recorded::Arg::from(crate::recorded::logged(request)), future.into(), (&response).into()]);
    match state.info_enabled() {
        true => state.log.record_with_message(request.clone(), response, None, message),
        false => state.log.record(request.clone(), response, None),
    }
    Reply::status(502)
}

/// `handleAnyException` for a failed template: the `500` of `templateFailureAsServerError`, else the 404.
fn template_failure_answer(state: &State, failed: &templates::Failed) -> (Reply, serde_json::Value) {
    if templates::failure_as_server_error(state) {
        templates::failure_reply(failed)
    } else {
        (Reply::not_found(), not_found_json())
    }
}

fn not_found_json() -> serde_json::Value {
    serde_json::json!({"statusCode": 404, "reasonPhrase": "Not Found"})
}

/// [`not_found_json`] as every unmatched request on this thread logs it: one value, interned
/// ([`crate::recorded::interned_shared`]), so its logged form and weight are worked out once, not per request.
fn not_found_shared() -> Arc<serde_json::Value> {
    thread_local! {
        static NOT_FOUND: Arc<serde_json::Value> = Arc::new(not_found_json());
    }
    crate::recorded::interned_shared(NOT_FOUND.with(Arc::clone))
}

fn reason(status: u32) -> String {
    crate::status::reason_phrase(status)
}

/// `ResponseWriter.writeDataPlanePreflightResponse`: a preflight for a request the control plane would not serve, under
/// the `corsAllowOrigin` policy; on a path the control plane serves with other methods (a bare alias such as `/graphql`)
/// only the requested method is allowed.
fn data_plane_preflight(state: &State, request: &HttpRequest) -> Reply {
    let mut reply = Reply::status(200);
    reply.headers.push(("version".into(), crate::control::VERSION.into()));
    let requested = request.first_header("access-control-request-method").filter(|m| !m.is_empty());
    if let Some(method) = requested.filter(|_| crate::cors_origin::is_control_plane_path_candidate(&request.path)) {
        reply.headers.push(("access-control-allow-methods".into(), method.to_string()));
    }
    reply.add_cors_headers(request, &state.config);
    reply
}

fn is_preflight(request: &HttpRequest) -> bool {
    request.method == "OPTIONS"
        && request.first_header("origin").is_some()
        && request.first_header("access-control-request-method").is_some()
}

/// `getRemoteAddressWithFallback`: the connection's tunnel target, else the port-forward remote, else the live
/// `proxyRemoteHost`/`proxyRemotePort` ([`crate::config::Config::proxy_remote`]).
fn remote_socket(state: &State, request: &HttpRequest) -> Option<(String, u16)> {
    request.remote_target.as_deref().cloned().or_else(|| state.config.port_forward.clone()).or_else(|| state.config.proxy_remote())
}

/// `retrievalResponseOrNull`: the stored OpenAI Responses API answer an unmatched request names, when no relay,
/// proxy pass or unmatched forward takes it first (`HttpActionHandler`'s last branch, before `attemptRequestBreakpoint`).
fn stored_retrieval(state: &State, request: &HttpRequest, looped: bool) -> Option<String> {
    let taken = is_preflight(request)
        || (!looped && crate::ws_relay::is_upgrade(request) && websocket_target(state, request).is_some())
        || crate::forward::proxy_pass_refusal(state, request).is_some()
        || crate::forward::proxy_pass_mapping(state, request).is_some()
        || unmatched_target(state, request).is_some();
    (!taken).then(|| crate::llm::responses::retrieve(&request.method, &request.path)).flatten()
}

/// A forward target: host and port.
type HostPort = (String, u16);

/// Where an unmatched request is proxied: the remote socket, else a non-local `Host` (exploratory, flagged).
///
/// A `Host` header that `HttpRequest.socketAddressFromHostHeader` cannot turn into an address is still attempted (the
/// exploratory proxy only checks that the header is non-empty and not local): the `Err` is the exception's message,
/// which the forward then fails with (502).
fn unmatched_target(state: &State, request: &HttpRequest) -> Option<(Result<HostPort, String>, bool)> {
    if let Some(target) = remote_socket(state, request) {
        return Some((Ok(target), false));
    }
    // `transparentProxyEnabled` marks every connection `PROXYING` (`TransparentProxyHandler`): its Host-header forward
    // is a proxied request, not the exploratory proxy.
    let exploratory = !state.config.hot_bool(crate::config::Hot::TransparentProxyEnabled, false);
    host_target(state, request).map(|target| (target, exploratory))
}

/// A non-local `Host` as host and port (defaulting by scheme); `None` when local, absent or malformed.
fn host_target(state: &State, request: &HttpRequest) -> Option<Result<(String, u16), String>> {
    // `attemptToProxyIfNoMatchingExpectation`, which `PUT /mockserver/mode` sets too: one configuration, as upstream
    // 0e8566814 has it. The 8.0.0 oracle process kept forwarding in SIMULATE (scenario
    // `operating_mode_data_plane`, its `diverge` steps; docs/divergences.md).
    let proxy = state.config.hot_bool(crate::config::Hot::AttemptToProxyIfNoMatchingExpectation, true);
    if !proxy {
        return None;
    }
    let host = request.first_header("host").filter(|h| !h.is_empty())?;
    if state.is_local_host(host) || crate::client::on_no_proxy_list(&state.config, host) {
        return None;
    }
    Some(socket_address_from_host_header(host, request.secure))
}

/// `HttpRequest.socketAddressFromHostHeader`: `splitHostPort` (a bracketed IPv6 form, else `String.split(":")`, which
/// drops trailing empty strings), `Integer.parseInt` of the second part and `new InetSocketAddress`, with the
/// messages of the exceptions those throw. An empty host name is the loopback address, as `InetAddress.getByName("")`.
fn socket_address_from_host_header(host: &str, secure: bool) -> Result<(String, u16), String> {
    let bracketed = host.starts_with('[').then(|| host.find(']')).flatten().filter(|end| *end > 0);
    let parts: Vec<&str> = match bracketed {
        Some(end) => match host[end..].find(':') {
            Some(colon) => vec![&host[1..end], &host[end + colon + 1..]],
            None => vec![&host[1..end]],
        },
        None => {
            let mut parts: Vec<&str> = host.split(':').collect();
            while parts.last().is_some_and(|p| p.is_empty()) {
                parts.pop();
            }
            parts
        }
    };
    let name = parts.first().ok_or_else(|| "Index 0 out of bounds for length 0".to_string())?;
    let port = match parts.get(1) {
        Some(text) => {
            let value = java_parse_int(text).ok_or_else(|| format!("For input string: \"{text}\""))?;
            if !(0..=65535).contains(&value) {
                return Err(format!("port out of range:{value}"));
            }
            value as u16
        }
        None if secure => 443,
        None => 80,
    };
    Ok((if name.is_empty() { "localhost".to_string() } else { name.to_string() }, port))
}

/// `Integer.parseInt(text)`: an optional sign and decimal digits, within the `int` range.
fn java_parse_int(text: &str) -> Option<i64> {
    let digits = text.strip_prefix(['+', '-']).unwrap_or(text);
    if digits.is_empty() || !digits.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let value: i64 = text.strip_prefix('+').unwrap_or(text).parse().ok()?;
    i32::try_from(value).ok().map(i64::from)
}

/// Where an unmatched WebSocket upgrade is relayed: the port-forward remote, else a non-local `Host` (port defaulting
/// by scheme). `None` when neither applies or the `Host` port is malformed.
fn websocket_target(state: &State, request: &HttpRequest) -> Option<(String, u16)> {
    remote_socket(state, request).or_else(|| host_target(state, request).and_then(Result::ok))
}

/// `scan`: the closest-match scan the request's log entries made, if any, reused when it is the same evaluation.
async fn no_match(state: &Arc<State>, request: &HttpRequest, scan: Option<ClosestScan>) -> (Reply, Vec<crate::recorded::LogEntry>) {
    if is_preflight(request) {
        // `CORSHeaders.isPreflightRequest(configuration, request)` turns `enableCORSForAPI` on for good.
        state.config.set_runtime("enableCORSForAPI", "true".to_string());
        return (data_plane_preflight(state, request), Vec::new());
    }
    let mut reply = Reply::not_found();
    let mut after = Vec::new();
    // `returnNotFound`: one `findClosestMatchHint` scan serves the DEBUG diff log and the hint header.
    let debug_diff = state.config.hot_bool(crate::config::Hot::DetailedVerificationFailures, true) && crate::log::debug_enabled(state);
    let hint_enabled = state.config.hot_bool(crate::config::Hot::ClosestMatchHintEnabled, true);
    let diagnostic = state.config.hot_bool(crate::config::Hot::AttachMismatchDiagnosticToResponse, false);
    let detailed_match_failures = state.config.hot_bool(crate::config::Hot::DetailedMatchFailures, true);
    if debug_diff || hint_enabled || diagnostic {
        // `findClosestMatchHint` checks at most the first `CLOSEST_MATCH_MAX_EVALUATIONS` expectations.
        let (candidates, truncated) = state.store.active_candidates().first(CLOSEST_MATCH_MAX_EVALUATIONS);
        let truncated_at = truncated.then_some(CLOSEST_MATCH_MAX_EVALUATIONS);
        let debug = crate::log::debug_enabled(state);
        // Without `debug` this scan is `closest_match` alone, records in every context when `detailedMatchFailures`.
        let reused = scan.filter(|_| !debug && detailed_match_failures).and_then(|scan| scan.reused_for(&candidates));
        let ((closest, notes), timeouts) = match reused {
            Some((closest, timeouts)) => ((closest, Vec::new()), timeouts),
            None => crate::matcher::regex_timeouts(regex_timeout_millis(state), || {
                closest_match_traced(&candidates, request, debug, trace_enabled(state), detailed_match_failures)
            }),
        };
        if !matches!(state.log_level.as_str(), "OFF" | "ERROR") {
            after.extend(timeouts.into_iter().map(regex_timeout_entry));
        }
        for note in notes {
            after.push(match_note_entry(note, request));
        }
        // `findClosestMatchHint` records in detailed contexts, except an OpenAPI matcher's own per-operation ones.
        // Under the server's own regex budget (outside a scope it was the 5000 ms default, which kept a
        // request with a catastrophic header regex past any client's timeout); the scan above already reported any
        // timeout these re-evaluations meet. Only the DEBUG diff and the diagnostic read them: the hint is the scan's.
        let (differences, _) = crate::matcher::regex_timeouts(regex_timeout_millis(state), || {
            closest
                .as_ref()
                .filter(|(closest, _)| (debug_diff || diagnostic) && (detailed_match_failures || !closest.matcher.is_openapi()))
                .map(|(closest, _)| closest.matcher.fail_fast_differences(request))
                .unwrap_or_default()
        });
        if debug_diff && !differences.is_empty() {
            let entry = match truncated_at {
                Some(checked) => crate::recorded::LogEntry::at(crate::recorded::Level::Debug, "closest match diff for unmatched request, among the first {} expectations only:{}")
                    .request(request)
                    .args([crate::recorded::Arg::from(serde_json::Value::from(checked)), format_differences(&differences).into()]),
                None => crate::recorded::LogEntry::at(crate::recorded::Level::Debug, "closest match diff for unmatched request:{}")
                    .request(request)
                    .args([format_differences(&differences)]),
            };
            after.push(entry);
        }
        if diagnostic {
            attach_mismatch_diagnostic(&mut reply, &differences, truncated_at);
        }
        if hint_enabled && let Some(hint) = closest.and_then(|(closest, differences)| closest_match_hint(&closest.id, &differences, truncated_at)) {
            reply.headers.push(("x-mockserver-closest-match-hint".into(), hint));
        }
    }
    (reply, after)
}

/// `MatchDifferenceFormatter.formatDifferences`: the fields in `MatchDifference.Field` order, each difference on
/// one line.
fn format_differences(differences: &[(&'static str, Vec<String>)]) -> String {
    let mut out = String::from("\n\nclosest match diff:\n");
    for field in crate::matcher::FIELDS {
        for (_, texts) in differences.iter().filter(|(f, texts)| *f == field && !texts.is_empty()).take(1) {
            out.push_str(&format!("  {field}:\n"));
            for text in texts {
                out.push_str(&format!("    {}\n", crate::matcher::diff_line(text)));
            }
        }
    }
    out
}

/// `HttpActionHandler.attachMismatchDiagnostic` (`attachMismatchDiagnosticToResponse`): the closest expectation's
/// differing fields in an `x-mockserver-closest-match` header and a JSON body; without one, only the header saying
/// so. Upstream's fields come from an enum-keyed `HashMap` (identity-hash order); here they are in field order.
fn attach_mismatch_diagnostic(reply: &mut Reply, differences: &[(&'static str, Vec<String>)], truncated_at: Option<usize>) {
    if differences.is_empty() {
        reply.headers.push(("x-mockserver-closest-match".into(), "no expectations configured".into()));
        return;
    }
    let names: Vec<&str> = differences.iter().map(|(field, _)| *field).collect();
    reply.headers.push(("x-mockserver-closest-match".into(), format!("fields differ: {}", names.join(", "))));
    const TOTAL_FIELDS: usize = crate::explain::TOTAL_FIELDS;
    let mut fields = serde_json::Map::new();
    for (field, texts) in differences {
        fields.insert((*field).to_string(), texts.iter().map(|t| serde_json::Value::from(crate::matcher::diff_line(t))).collect());
    }
    let mut body = serde_json::json!({
        "matchedFieldCount": TOTAL_FIELDS - differences.len(),
        "totalFieldCount": TOTAL_FIELDS,
        "differences": fields,
    });
    if let Some(checked) = truncated_at {
        body["truncated"] = true.into();
        body["expectationsChecked"] = checked.into();
    }
    reply.headers.push(("content-type".into(), "application/json; charset=utf-8".into()));
    reply.body = bytes::Bytes::from(crate::json::pretty(&body));
}

/// `HttpActionHandler.attachClosestMatchHint`: the expectation with the fewest differing fields, its first
/// difference, and how many more fields differ, capped at 256 characters.
fn closest_match_hint(id: &str, differences: &[(&'static str, crate::matcher::Difference)], truncated_at: Option<usize>) -> Option<String> {
    if differences.is_empty() {
        return None;
    }
    let (field, first) = &differences[0];
    use std::fmt::Write;
    let reason = first.hint_reason();
    // written once into a buffer of its length: `format!` grew it a few times
    let mut hint = String::with_capacity(id.len() + field.len() + reason.len() + 64);
    let _ = write!(hint, "expectation {id}: {field} did not match ({reason})");
    if differences.len() > 1 {
        let _ = write!(hint, "; +{} more field(s) differ", differences.len() - 1);
    }
    // each line break a space, the ends trimmed
    if hint.contains(['\r', '\n']) {
        hint = hint.replace(['\r', '\n'], " ");
    }
    if hint.trim().len() != hint.len() {
        hint = hint.trim().to_string();
    }
    // A capped scan says so after the (shortened) hint, within the 256 characters.
    let note = truncated_at.map(|checked| format!("; only the first {checked} expectations were checked")).unwrap_or_default();
    let max = 256 - note.chars().count();
    // no more characters than bytes
    if hint.len() > max && hint.chars().count() > max {
        hint = hint.chars().take(max - 3).collect::<String>() + "...";
    }
    hint.push_str(&note);
    Some(hint)
}

/// [`closest_match`] over every active expectation, whatever its namespace (`findClosestMatchHint`), with the
/// `would match` entries its fail-fast matches write when `debug`, and their differences' TRACE entries when `trace`.
fn closest_match_traced(
    candidates: &crate::store::Candidates,
    request: &HttpRequest,
    debug: bool,
    trace: bool,
    detailed_match_failures: bool,
) -> (Option<Closest>, Vec<crate::matcher::MatchNote>) {
    let notes = if debug { candidates.iter().flat_map(|e| e.matcher.match_notes(request, true, trace)).collect() } else { Vec::new() };
    let records = |e: &crate::store::Expectation| detailed_match_failures || !e.matcher.is_openapi();
    // `closest_match` over the candidates, skipping in one scan of the path index the run of them a closest one with
    // at most one difference makes it pass over
    let misses = candidates.path_misses(&request.path);
    let mut closest: Option<Closest> = None;
    let mut i = 0;
    while i < candidates.len() {
        if closest.as_ref().is_some_and(|(_, best)| best.len() <= 1) {
            i = misses.next_kept(i);
            if i >= candidates.len() {
                break;
            }
        }
        consider(&mut closest, candidates.get(i), misses.misses(i), request, &records);
        i += 1;
    }
    (closest, notes)
}

/// The unmatched expectation with the fewest differing fields: strictly-fewer wins, in match order.
/// `records(e)`: whether `e`'s `MatchDifference` context records anything (under `detailedMatchFailures=false` the
/// scan's shared context records nothing, nor do an OpenAPI matcher's per-operation contexts): one that records
/// nothing counts as no differences, so the first such one is the closest.
/// `candidates` come with whether their literal path alone fails the request ([`crate::store::Candidates::iter_with_path_misses`]).
fn closest_match<'a>(
    candidates: impl Iterator<Item = (&'a Arc<crate::store::Expectation>, bool)>,
    request: &HttpRequest,
    records: impl Fn(&crate::store::Expectation) -> bool,
) -> Option<Closest> {
    let mut closest: Option<Closest> = None;
    for (e, path_misses) in candidates {
        consider(&mut closest, e, path_misses, request, &records);
    }
    closest
}

/// One candidate of [`closest_match`].
fn consider(closest: &mut Option<Closest>, e: &Arc<crate::store::Expectation>, path_misses: bool, request: &HttpRequest, records: &impl Fn(&crate::store::Expectation) -> bool) {
    // At least one difference, which cannot beat a closest one with at most one: skipped without evaluating it.
    if path_misses && closest.as_ref().is_some_and(|(_, best)| best.len() <= 1) {
        return;
    }
    if e.matcher.matches(request, crate::matcher::Mode::DataPlane) {
        return;
    }
    let records = records(e);
    // One difference cannot beat a closest one with at most one: counted without building it.
    if records && closest.as_ref().is_some_and(|(_, best)| best.len() <= 1) && e.matcher.fails_at_method_or_path(request) {
        return;
    }
    let d = if records { e.matcher.differences(request) } else { Vec::new() };
    if closest.as_ref().is_none_or(|(_, best)| d.len() < best.len()) {
        *closest = Some((e.clone(), d));
    }
}

/// An `httpLlmResponse` answer on the wire.
/// A non-streaming LLM response is written through `writeResponseActionResponse` without chaos or a rate limit, so
/// `globalResponseDelayMillis` delays it again after its dispatch, and its log entry carries the `timing`.
async fn llm_written(state: &State, reply: Reply, logged: serde_json::Value) -> Result<(Reply, serde_json::Value), Cut> {
    chaos_and_delay(state, None, reply, logged, || None, || None).await
}

fn llm_reply(status: u32, headers: Vec<(String, String)>, body: String) -> Reply {
    let mut reply = Reply::status(status);
    reply.headers.extend(headers);
    reply.body = bytes::Bytes::from(body);
    reply
}

/// An `httpLlmResponse` answer as the event log holds it: headers in the order they were added.
fn llm_logged(status: u32, headers: &[(String, String)], body: String) -> serde_json::Value {
    let mut logged = serde_json::Map::new();
    logged.insert("statusCode".into(), status.into());
    if !headers.is_empty() {
        let mut map = serde_json::Map::new();
        for (k, v) in headers {
            match map.get_mut(k) {
                Some(serde_json::Value::Array(values)) => values.push(v.clone().into()),
                _ => {
                    map.insert(k.clone(), serde_json::json!([v]));
                }
            }
        }
        logged.insert("headers".into(), serde_json::Value::Object(map));
    }
    logged.insert("body".into(), body.into());
    serde_json::Value::Object(logged)
}

/// `action::respond` under the server's OpenAPI parse cache: a `generateFromSchema` body's schema problems are logged
/// at DEBUG when it is first parsed (`OpenAPIParser.buildOpenAPIForInlineJsonSchema`, 9.1.0).
fn respond_logged(state: &State, response: &serde_json::Value) -> action::Respond {
    crate::openapi::logging_load_problems(state, || action::respond(response))
}

#[cfg(test)]
#[path = "dataplane_tests.rs"]
mod tests;
