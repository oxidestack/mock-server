//! The control plane: `/mockserver/<op>` and its legacy aliases (§1).

use std::sync::Arc;

use serde_json::{Value, json};

use crate::action::Action;
use crate::matcher::{self, Mode, RequestMatcher};
use crate::recorded::Subject;
use crate::reply::Reply;
use crate::request::HttpRequest;
use crate::state::State;
use crate::store::Expectation;
use crate::{canonical, codegen, json, schema};

/// The MockServer version the oracle reports (`oracle.env` `ORACLE_VERSION`), and the upstream commit its
/// `mock_server_build_info{git_hash}` names (`ORACLE_REVISION`'s first eight characters).
pub const VERSION: &str = "9.2.0";
pub const UPSTREAM_GIT_HASH: &str = "789142c1";

/// Every operation path the control plane answers ([`route`], with `contractTest`, `replay` and `mcp`).
const OPERATIONS: &[&str] = &[
    "/mockserver/asyncapi",
    "/mockserver/asyncapi/http",
    "/mockserver/asyncapi/verify",
    "/mockserver/audit",
    "/mockserver/baseline/compare",
    "/mockserver/bind",
    "/mockserver/breakpoint/matcher",
    "/mockserver/breakpoint/matcher/clear",
    "/mockserver/breakpoint/matcher/remove",
    "/mockserver/breakpoint/matchers",
    "/mockserver/cassettes",
    "/mockserver/chaosExperiment",
    "/mockserver/chaosExperiment/history",
    "/mockserver/chaosExperiment/profiles",
    "/mockserver/clear",
    "/mockserver/clock",
    "/mockserver/cluster",
    "/mockserver/config",
    "/mockserver/configuration",
    "/mockserver/contractTest",
    "/mockserver/crud",
    "/mockserver/dashboard",
    "/mockserver/debugMismatch",
    "/mockserver/diff",
    "/mockserver/drift",
    "/mockserver/drift/clear",
    "/mockserver/expectation",
    "/mockserver/explain",
    "/mockserver/explainUnmatched",
    "/mockserver/files/delete",
    "/mockserver/files/list",
    "/mockserver/files/retrieve",
    "/mockserver/files/store",
    "/mockserver/generateExpectation",
    "/mockserver/graphql",
    "/mockserver/grpc/clear",
    "/mockserver/grpc/descriptors",
    "/mockserver/grpc/health",
    "/mockserver/grpc/services",
    "/mockserver/grpcChaos",
    "/mockserver/http3status",
    "/mockserver/import",
    "/mockserver/lint",
    "/mockserver/llm/diffRuns",
    "/mockserver/llm/optimisationReport",
    "/mockserver/loadScenario",
    "/mockserver/loadScenario/generateFromOpenAPI",
    "/mockserver/loadScenario/generateFromRecording",
    "/mockserver/loadScenario/start",
    "/mockserver/loadScenario/stop",
    "/mockserver/logEntryBody",
    "/mockserver/mcp",
    "/mockserver/metrics",
    "/mockserver/mode",
    "/mockserver/oidc",
    "/mockserver/openapi",
    "/mockserver/openapi.yaml",
    "/mockserver/pact",
    "/mockserver/pact/import",
    "/mockserver/pact/verify",
    "/mockserver/preemption",
    "/mockserver/proxyConfiguration",
    "/mockserver/ready",
    "/mockserver/recordings/promote",
    "/mockserver/replay",
    "/mockserver/reset",
    "/mockserver/retrieve",
    "/mockserver/saml",
    "/mockserver/scenario",
    "/mockserver/scim",
    "/mockserver/serviceChaos",
    "/mockserver/status",
    "/mockserver/stop",
    "/mockserver/tcpChaos",
    "/mockserver/template/test",
    "/mockserver/trafficValidate",
    "/mockserver/verify",
    "/mockserver/verifySLO",
    "/mockserver/verifySequence",
    "/mockserver/wasm/modules",
    "/mockserver/wasm/test",
    "/mockserver/wsdl",
];

/// The operations under a prefix whose rest names something (a profile, a scenario, a UI asset): their route.
const NAMED_OPERATIONS: &[(&str, &str)] = &[
    ("/chaosExperiment/apply/", "/mockserver/chaosExperiment/apply/{name}"),
    ("/chaosExperiment/profiles/", "/mockserver/chaosExperiment/profiles/{name}"),
    ("/dashboard/", "/mockserver/dashboard"),
    ("/mcp/", "/mockserver/mcp"),
    ("/scenario/", "/mockserver/scenario/{name}"),
];

/// The `http_route` of a request the control plane answered: its operation path, a fixed set, under
/// `/mockserver` whether it came by that path or a bare legacy alias, a name in it as `{name}`; `_OTHER` for a path
/// outside the set (an authentication refusal of an unknown operation, a `livenessHttpGetPath` elsewhere).
pub fn operation_route(path: &str) -> &'static str {
    let op = path.strip_prefix("/mockserver").filter(|op| op.is_empty() || op.starts_with('/')).unwrap_or(path);
    if let Some(found) = OPERATIONS.iter().find(|o| o.strip_prefix("/mockserver") == Some(op)) {
        return found;
    }
    if let Some(name) = op.strip_prefix("/loadScenario/").filter(|n| !n.is_empty()) {
        return if name.ends_with("/report") { "/mockserver/loadScenario/{name}/report" } else { "/mockserver/loadScenario/{name}" };
    }
    NAMED_OPERATIONS.iter().find(|(prefix, _)| op.len() > prefix.len() && op.starts_with(prefix)).map_or("_OTHER", |(_, route)| route)
}

/// The OpenAPI document `OpenAPISpecHandler` embeds (`mock-server-openapi-embedded-model.yaml`, byte for byte the
/// spec under `spec/`).
const OPENAPI_SPEC: &str = include_str!("../spec/mockserver/mockserver-openapi.yaml");

/// `HttpRequestHandler` / `OpenAPISpecHandler`: `GET /mockserver/openapi.yaml` behind the control-plane gate. The
/// handler writes straight to the channel, so no CORS, `version` or computed framing headers; `connection: keep-alive`
/// only for a keep-alive request, which a request without keep-alive has its connection closed after.
fn openapi_spec(state: &State, request: &HttpRequest) -> Option<Reply> {
    if request.method != "GET" || request.path != "/mockserver/openapi.yaml" {
        return None;
    }
    let liveness = state.config.read_hot(crate::config::Hot::LivenessHttpGetPath, |p| p.is_some_and(|p| !p.trim().is_empty() && p == request.path));
    if liveness {
        return None;
    }
    if let Some(reply) = crate::auth::control_plane_refusal(state, request) {
        return Some(reply);
    }
    let mut reply = Reply::status(200);
    reply.headers.push(("content-type".into(), "application/yaml; charset=utf-8".into()));
    reply.headers.push(("content-length".into(), OPENAPI_SPEC.len().to_string()));
    reply.suppress_connection_header = true;
    if request.keep_alive {
        reply.headers.push(("connection".into(), "keep-alive".into()));
    }
    reply.close_socket = Some(!request.keep_alive);
    reply.body = bytes::Bytes::from_static(OPENAPI_SPEC.as_bytes());
    Some(reply)
}

/// `MetricsHandler` for a scrape whose `Accept` header names `application/openmetrics-text`: the OpenMetrics
/// exposition, with CORS but no `version` or `connection` header (the plain Prometheus one is `control::route`'s).
fn open_metrics(state: &State, request: &HttpRequest) -> Option<Reply> {
    if request.method != "GET" || request.path != "/mockserver/metrics" || !crate::metrics::enabled(&state.config) {
        return None;
    }
    if !request.first_header("accept").is_some_and(|a| a.to_ascii_lowercase().contains("application/openmetrics-text")) {
        return None;
    }
    if state.config.read_hot(crate::config::Hot::LivenessHttpGetPath, |p| p.is_some_and(|p| !p.trim().is_empty() && p == request.path)) {
        return None;
    }
    if let Some(reply) = crate::auth::control_plane_refusal(state, request) {
        return Some(reply);
    }
    let body = crate::metrics::exposition_as(state, true)?;
    let mut reply = Reply::status(200);
    reply.add_control_plane_cors_headers(request, &state.config);
    reply.headers.push(("content-type".into(), "application/openmetrics-text; version=1.0.0; charset=utf-8".into()));
    reply.body = body.into();
    reply.suppress_connection_header = true;
    Some(reply)
}

/// `HttpState.handle`'s offload (`dispatchOffTheEventLoop`) once the scheduler is shut down (fe354ebd5):
/// a request that may load an OpenAPI spec or writes recorded bodies to files is dispatched on the scheduler, and when
/// the scheduler will not run it, answered `503` at once, after the origin gate and before authentication or routing.
/// `None` while the scheduler runs or for any other request.
pub fn unable_to_schedule(state: &State, request: &HttpRequest) -> Option<Reply> {
    if !state.scheduler_is_shut_down() || request.method != "PUT" {
        return None;
    }
    let op = request.path.strip_prefix("/mockserver").unwrap_or(&request.path);
    // `mayLoadOpenAPISpec`: `OPENAPI_SPEC_PUT_ROUTES`, or a `REQUEST_DEFINITION_PUT_ROUTES` body naming a spec
    const OPENAPI_SPEC_PUT_ROUTES: &[&str] = &["/openapi", "/loadScenario/generateFromOpenAPI"];
    const REQUEST_DEFINITION_PUT_ROUTES: &[&str] = &["/expectation", "/verify", "/verifySequence", "/retrieve", "/clear", "/breakpoint/matcher", "/recordings/promote"];
    let may_load_spec = OPENAPI_SPEC_PUT_ROUTES.contains(&op) || (REQUEST_DEFINITION_PUT_ROUTES.contains(&op) && request.body_json_or_xml_str().contains("specUrlOrPayload"));
    // `writesRecordedBodyFiles`
    let writes_files = op == "/retrieve" && crate::import::body_files::writes_files(request);
    if !may_load_spec && !writes_files {
        return None;
    }
    // `writeResponse(request, SERVICE_UNAVAILABLE, "unable to schedule request", "text/plain")`
    Some(Reply::api_header(503, "text/plain", "unable to schedule request"))
}

/// The routes `HttpRequestHandler`'s own else-if chain serves on TCP, after `HttpState.handle` declined (the
/// liveness path aside, see [`route`]). `Http3MockServerHandler` tries `HttpState.handle` alone before the data
/// plane, so over HTTP/3 these reach `DataPlaneAuthenticationGate` (which exempts `/mockserver/*`) and the data plane:
/// `PUT /mockserver/status` over HTTP/3 is a 404 when nothing matches it (
/// `Http3DataPlaneAuthenticationIntegrationTest.shouldNotGateControlPlaneOverHttp3WithoutDataPlaneCredentials`). The
/// OpenAPI spec and the OpenMetrics scrape, other TCP pipeline handlers, are not on HTTP/3's pipeline either.
fn served_by_http_request_handler(request: &HttpRequest) -> bool {
    let path = request.path.as_str();
    let either = |op: &str| path.strip_prefix("/mockserver").unwrap_or(path) == op;
    match request.method.as_str() {
        "GET" => {
            either("/ready")
                || either("/configuration")
                || either("/llm/optimisationReport")
                || either("/http3status")
                || path.starts_with("/mockserver/dashboard")
                || path == "/mockserver/openapi.yaml"
                || path == "/mockserver/metrics"
        }
        "PUT" => either("/status") || either("/bind") || either("/stop") || either("/configuration") || either("/llm/diffRuns"),
        _ => false,
    }
}

/// Answers `request` if it is a control-plane call; `None` sends it on to the data plane.
pub fn route(state: &Arc<State>, request: &HttpRequest) -> Option<Reply> {
    // A spec any handler parses goes through the server's parse cache, its problems logged once.
    crate::openapi::logging_load_problems(state, || route_unscoped(state, request))
}

fn route_unscoped(state: &Arc<State>, request: &HttpRequest) -> Option<Reply> {
    let http3 = request.protocol == "HTTP_3";
    if http3 && served_by_http_request_handler(request) {
        return None;
    }
    // `OpenAPISpecHandler` and the OpenMetrics scrape are answered before the rest of the control plane.
    if let Some(reply) = openapi_spec(state, request).or_else(|| open_metrics(state, request)) {
        return Some(reply);
    }
    // `HttpRequestHandler`: with `livenessHttpGetPath` set, a GET of exactly that path answers the status response —
    // after whatever `HttpState.handle` answers and the readiness probe, before the handler's own GETs (dashboard,
    // metrics, configuration, optimisation report, HTTP/3 status) and the data plane.
    // Over HTTP/3 the liveness path is not answered: `HttpRequestHandler` alone serves it.
    let liveness = !http3 && request.method == "GET" && state.config.read_hot(crate::config::Hot::LivenessHttpGetPath, |p| p.is_some_and(|p| !p.trim().is_empty() && p == request.path));
    if request.method == "GET" && request.path.starts_with("/mockserver/dashboard") && !liveness {
        if let Some(reply) = crate::auth::control_plane_refusal(state, request) {
            return Some(reply);
        }
        return Some(dashboard(state, request));
    }
    let op = request.path.strip_prefix("/mockserver").unwrap_or(&request.path);
    // Every control-plane operation but `status` takes the authentication decision first.
    const AUTHENTICATED: &[&str] = &["/expectation", "/retrieve", "/verify", "/verifySequence", "/clear", "/reset", "/stop", "/bind", "/openapi", "/crud", "/scim", "/oidc", "/saml", "/wsdl", "/graphql", "/pact", "/pact/verify", "/pact/import", "/import", "/recordings/promote", "/debugMismatch", "/explainUnmatched"];
    if request.method == "PUT" && AUTHENTICATED.contains(&op) && let Some(reply) = crate::auth::control_plane_refusal(state, request) {
        return Some(reply);
    }
    // `/mockserver/metrics` has no bare alias.
    if request.method == "GET" && request.path == "/mockserver/metrics" && !liveness {
        if let Some(reply) = crate::auth::control_plane_refusal(state, request) {
            return Some(reply);
        }
        // `MetricsHandler` writes the exposition itself: CORS, but no `version` or `connection` header.
        if let Some(body) = crate::metrics::exposition(state) {
            let mut reply = Reply::status(200);
            reply.add_control_plane_cors_headers(request, &state.config);
            reply.headers.push(("content-type".into(), "text/plain; version=0.0.4; charset=utf-8".into()));
            reply.body = body.into();
            reply.suppress_connection_header = true;
            return Some(reply);
        }
        // Disabled: `MetricsHandler` answers 404 the same way.
        let mut reply = Reply::status(404);
        reply.add_control_plane_cors_headers(request, &state.config);
        reply.suppress_connection_header = true;
        return Some(reply);
    }
    if op == "/cassettes" && matches!(request.method.as_str(), "GET" | "PUT" | "DELETE") {
        if let Some(reply) = crate::auth::control_plane_refusal(state, request) {
            return Some(reply);
        }
        return crate::cassettes::route(&state.cassettes, request);
    }
    if op == "/clock" && matches!(request.method.as_str(), "GET" | "PUT") {
        if let Some(reply) = crate::auth::control_plane_refusal(state, request) {
            return Some(reply);
        }
        return Some(crate::clock::route(state, request));
    }
    if crate::load::owns(&request.method, op) {
        if let Some(reply) = crate::auth::control_plane_refusal(state, request) {
            return Some(reply);
        }
        if let Some(reply) = crate::load::route(state, request, op) {
            return Some(reply);
        }
    }
    if crate::chaos::owns(&request.method, op) {
        if let Some(reply) = crate::auth::control_plane_refusal(state, request) {
            return Some(reply);
        }
        return crate::chaos::route(state, request, op);
    }
    if request.method == "PUT" && matches!(op, "/files/store" | "/files/retrieve" | "/files/list" | "/files/delete") {
        if let Some(reply) = crate::auth::control_plane_refusal(state, request) {
            return Some(reply);
        }
        if let Some(reply) = crate::files::route(state, request, op) {
            return Some(reply);
        }
    }
    if request.method == "PUT" && op == "/generateExpectation" {
        if let Some(reply) = crate::auth::control_plane_refusal(state, request) {
            return Some(reply);
        }
        return Some(crate::generate_expectation::route(state, request));
    }
    if op.starts_with("/wasm/") {
        if let Some(reply) = crate::auth::control_plane_refusal(state, request) {
            return Some(reply);
        }
        if let Some(reply) = crate::wasm::route(state, request, op) {
            return Some(reply);
        }
    }
    if op == "/scenario" || op.starts_with("/scenario/") {
        if matches!(request.method.as_str(), "GET" | "PUT") && let Some(reply) = crate::auth::control_plane_refusal(state, request) {
            return Some(reply);
        }
        if let Some(reply) = crate::scenario::route(state, request, op) {
            return Some(reply);
        }
    }
    if op == "/asyncapi" || op.starts_with("/asyncapi/") {
        if let Some(reply) = crate::auth::control_plane_refusal(state, request) {
            return Some(reply);
        }
        if let Some(reply) = crate::asyncapi::route(state, request, op) {
            return Some(reply);
        }
    }
    // `MockMode`: SIMULATE, SPY or CAPTURE, over `attemptToProxyIfNoMatchingExpectation` as `HttpState` sees it.
    if op == "/mode" && matches!(request.method.as_str(), "GET" | "PUT") {
        if let Some(reply) = crate::auth::control_plane_refusal(state, request) {
            return Some(reply);
        }
        return Some(mode(state, request));
    }
    if op.starts_with("/breakpoint/") {
        if let Some(reply) = crate::auth::control_plane_refusal(state, request) {
            return Some(reply);
        }
        if let Some(reply) = crate::breakpoint::route(state, request, op) {
            return Some(reply);
        }
    }
    // `HttpRequestHandler.handleOptimisationReport`: captured LLM traffic as an optimisation report.
    if request.method == "GET" && op == "/llm/optimisationReport" && !liveness {
        if let Some(reply) = crate::auth::control_plane_refusal(state, request) {
            return Some(reply);
        }
        return Some(crate::llm::report::endpoint(state, request));
    }
    // `HttpRequestHandler.handleDiffRuns`: a prompt-level diff of two recorded agent runs.
    if request.method == "PUT" && op == "/llm/diffRuns" {
        if let Some(reply) = crate::auth::control_plane_refusal(state, request) {
            return Some(reply);
        }
        let text = request.body_str();
        let body = if text.trim().is_empty() {
            Ok(json!({}))
        } else {
            crate::jnode::read_tree(&text).map_err(|e| e.message).and_then(|_| crate::json::parse_lenient(&request.body).map_err(|e| e.to_string()))
        };
        return Some(match body.and_then(|b| crate::llm::analysis::diff_runs(state, &b, None)) {
            Ok(diff) => Reply::api_header(200, "application/json", json::pretty(&diff)),
            // unreadable or mistyped JSON is a Jackson exception, a client error (`ControlPlaneFailureResponse.write`)
            Err(message) => client_error(state, request, &message),
        });
    }
    // `HttpRequestHandler`: the HTTP/3 listener's port and open connections, behind the control-plane gate.
    if request.method == "GET" && op == "/http3status" && !liveness {
        if let Some(reply) = crate::auth::control_plane_refusal(state, request) {
            return Some(reply);
        }
        return Some(Reply::api_header(200, "application/json", crate::http3::status_json(state)));
    }
    let reply = match (request.method.as_str(), op) {
        // `HttpState.handle`'s GETs and the readiness probe come first
        ("GET", _) if liveness && !matches!(op, "/ready" | "/grpc/health" | "/proxyConfiguration") => Reply { status_path: true, ..status(state) },
        ("PUT", "/status") => status(state),
        ("PUT", "/expectation") => crate::blocking::off_worker_when_large(request.body.len(), || create_expectations(state, request)),
        // Their filters' regex timeouts are logged.
        ("PUT", "/retrieve") => crate::dataplane::control_plane_regex_scope(state, || retrieve(state, request)),
        ("PUT", "/verify") => {
            let outcome = crate::dataplane::control_plane_regex_scope(state, || crate::verify::verify(state, request.body_json_or_xml_str().as_bytes()));
            verification_reply(state, request, outcome)
        }
        ("PUT", "/verifySequence") => {
            let outcome = crate::dataplane::control_plane_regex_scope(state, || crate::verify::verify_sequence(state, request.body_json_or_xml_str().as_bytes()));
            verification_reply(state, request, outcome)
        }
        ("PUT", "/verifySLO") => {
            if let Some(reply) = crate::auth::control_plane_refusal(state, request) {
                return Some(reply);
            }
            crate::slo::verify(state, request)
        }
        ("PUT", "/clear") => crate::dataplane::control_plane_regex_scope(state, || clear(state, request)),
        ("PUT", "/bind") => bind(state, request),
        ("PUT", "/openapi") => openapi_expectations(state, request),
        ("PUT", "/crud") => register_crud(state, request),
        ("PUT", "/scim") => scim(state, request),
        ("PUT", "/oidc") => oidc(state, request),
        ("PUT", "/saml") => saml(state, request),
        ("PUT", "/wsdl") => wsdl(state, request),
        ("PUT", "/graphql") => graphql(state, request),
        ("PUT", "/pact/verify") => match crate::pact::verify(state, &request.body_str()) {
            Ok((verified, result)) => Reply::api_body(if verified { 202 } else { 406 }, "application/json", json::pretty(&result)),
            Err(message) => Reply::api_body(400, "application/json", json::compact(&serde_json::json!({"error": message}))),
        },
        ("PUT", "/pact/import") => crate::import::pact_import(state, request),
        ("PUT", "/import") => crate::import::import(state, request),
        ("PUT", "/recordings/promote") => crate::import::promote(state, request),
        ("PUT", "/pact") => Reply::api_body(200, "application/json", crate::pact::export(state, query_param(request, "consumer"), query_param(request, "provider"))),
        ("PUT", "/debugMismatch") => debug_mismatch(state, request),
        ("PUT", "/explainUnmatched") => explain_unmatched(state, request),
        // `HttpState`: `/mockserver/explain` only, no bare alias (9.1.0)
        ("PUT", "/explain") if request.path == "/mockserver/explain" => {
            if let Some(reply) = crate::auth::control_plane_refusal(state, request) {
                return Some(reply);
            }
            crate::explain::explain(state, request)
        }
        // `HttpState`: `/mockserver/template/test` only, no bare alias; the mutate role (9.1.0)
        ("PUT", "/template/test") if request.path == "/mockserver/template/test" => {
            if let Some(reply) = crate::auth::control_plane_refusal(state, request) {
                return Some(reply);
            }
            crate::templates::dry_run::test(state, request)
        }
        // `HttpState`: `/mockserver/lint` only, no bare alias
        ("PUT", "/lint") if request.path == "/mockserver/lint" => {
            if let Some(reply) = crate::auth::control_plane_refusal(state, request) {
                return Some(reply);
            }
            lint(state, request)
        }
        ("PUT", "/reset") => {
            let reset_audit_entry = state.audit.take_reset_entry();
            if let Some(error) = reset_aborted(state) {
                log_exception(state, request, error);
                return Some(text(400, error));
            }
            // `RequestMatchers.reset`: one `removed expectation` per active expectation, logged before the event log
            // is emptied, so on a full log each evicts an entry (`mock_server_evicted_log_entries_total`).
            let removed = state.store.all();
            state.store.clear();
            log_removals(state, &removed, &uuid::Uuid::new_v4().to_string());
            state.scenarios().cancel_all_pending_transitions();
            crate::persistence::changed(state, None);
            state.crud.reset();
            state.files.reset();
            state.wasm.clear();
            state.config.metrics.reset();
            state.callbacks.reset();
            state.cassettes.reset();
            state.chaos.reset(state);
            state.load.reset();
            state.scim.reset();
            state.oidc.reset();
            state.saml.reset();
            state.audit.clear(reset_audit_entry);
            state.asyncapi.reset();
            state.llm_quotas.reset();
            state.rate_limits.reset();
            state.forward_connections.breaker.reset();
            state.drift.clear();
            state.breakpoints.clear();
            state.callbacks.release_held(None);
            crate::grpc_plane::reset_health();
            crate::llm::responses::reset();
            state.config.slo.reset();
            state.log.reset();
            // `setHttpRequest(request())`: an empty request, which a filter with headers does not match; INFO, so not kept
            // under `logLevel` WARN and above (`HttpState.reset`).
            if state.info_enabled() {
                let entry = crate::recorded::LogEntry::new(crate::recorded::Kind::Cleared, "resetting all expectations and request logs").default_request();
                state.log.message_about(entry, crate::recorded::Subject::Request(Arc::new(HttpRequest { method: String::new(), ..HttpRequest::default() })));
            }
            Reply::api(200)
        }
        ("PUT", "/stop") => {
            let state = state.clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                state.stop().await;
            });
            Reply::api(200)
        }
        ("GET", "/ready") => Reply::api_header(200, "application/json", r#"{"status":"READY"}"#),
        ("PUT", "/grpc/health") => crate::grpc_plane::put_health(&request.body_json_or_xml_str()),
        ("GET", "/grpc/health") => crate::grpc_plane::get_health(),
        ("GET", "/audit") => {
            if let Some(reply) = crate::auth::control_plane_refusal(state, request) {
                return Some(reply);
            }
            crate::audit::get(state, request)
        }
        // `HttpState.handleLogEntryBodyGet`: a dashboard row's request or response in full (upstream #102).
        ("GET", "/logEntryBody") => {
            if let Some(reply) = crate::auth::control_plane_refusal(state, request) {
                return Some(reply);
            }
            crate::dashboard::log_entry_body(state, request)
        }
        // `HttpState`'s drift and diff endpoints (`handleDriftGet`, `handleDiff`, the baseline comparison).
        ("GET", "/drift") | ("PUT", "/drift/clear" | "/diff" | "/baseline/compare") => {
            if let Some(reply) = crate::auth::control_plane_refusal(state, request) {
                return Some(reply);
            }
            match op {
                "/drift" => crate::drift::get(state, request),
                "/drift/clear" => crate::drift::clear(state),
                "/diff" => crate::drift::diff_endpoint(request),
                _ => match crate::drift::baseline_compare(state, request) {
                    Ok(reply) => reply,
                    Err(message) => {
                        if crate::log::error_enabled(state) {
                            let entry = crate::recorded::LogEntry::at(crate::recorded::Level::Error, "exception handling request for baseline compare:{}error:{}")
                                .args([crate::recorded::Arg::from(crate::recorded::logged(request)), message.as_str().into()]);
                            crate::log::entry_as(state, crate::recorded::Level::Error, &entry);
                            state.log.message_about(entry, Subject::Request(Arc::new(request.clone())));
                        }
                        text(400, message)
                    }
                },
            }
        }
        ("GET", "/cluster") => {
            if let Some(reply) = crate::auth::control_plane_refusal(state, request) {
                return Some(reply);
            }
            cluster(state)
        }
        ("PUT", "/grpc/descriptors" | "/grpc/services" | "/grpc/clear") => {
            if let Some(reply) = crate::auth::control_plane_refusal(state, request) {
                return Some(reply);
            }
            match op {
                "/grpc/descriptors" if request.body.is_empty() => text(400, "descriptor set body is empty"),
                "/grpc/descriptors" => match state.grpc.load(&request.body) {
                    Ok(()) => Reply::api_body(201, "application/json", r#"{"status":"loaded"}"#),
                    Err(e) => text(400, format!("failed to load gRPC descriptor: {e}")),
                },
                "/grpc/services" => Reply::api_body(200, "application/json", json::pretty(&state.grpc.services_json())),
                _ => {
                    state.grpc.clear();
                    Reply::api(200)
                }
            }
        }
        ("PUT", "/trafficValidate") => {
            if let Some(reply) = crate::auth::control_plane_refusal(state, request) {
                return Some(reply);
            }
            traffic_validate(state, request)
        }
        ("GET" | "PUT", "/configuration") => {
            if let Some(reply) = crate::auth::control_plane_refusal(state, request) {
                return Some(reply);
            }
            // `HttpRequestHandler` builds the request's `ResponseWriter`, and with it `DefaultResponseHeaders`, when the
            // request arrives: the answer to a PUT carries the defaultResponseHeaders in force before it (while its
            // CORS headers are read when written)..
            let in_force = state.config.property("defaultResponseHeaders").unwrap_or_default();
            let mut reply = configuration(state, request);
            reply.default_response_headers = Some(in_force);
            reply
        }
        ("GET", "/config") => {
            if let Some(reply) = crate::auth::control_plane_refusal(state, request) {
                return Some(reply);
            }
            effective_config(state, request)
        }
        ("GET", "/proxyConfiguration") => {
            if let Some(reply) = crate::auth::control_plane_refusal(state, request) {
                return Some(reply);
            }
            proxy_configuration(state, request)
        }
        _ => return None,
    };
    Some(reply)
}

/// `PUT /mockserver/trafficValidate` (`handleTrafficValidate`): every recorded request-response pair validated
/// against the OpenAPI spec named by `spec` (or `specUrlOrPayload`).
fn traffic_validate(state: &State, request: &HttpRequest) -> Reply {
    let error = |status: u32, message: &str| Reply::api_body(status, "application/json", json!({"error": message}).to_string());
    let body = request.body_json_or_xml_str();
    if body.trim().is_empty() {
        return error(400, "request body is required — must be a JSON document with a \"spec\" (URL, file path, or inline OpenAPI spec)");
    }
    let root = match crate::json::parse_lenient(request.body_json_or_xml_str().as_bytes()) {
        Ok(v) => v,
        Err(e) => return error(400, &e.to_string()),
    };
    let text_of = |key: &str| root.get(key).and_then(crate::openapi::spec_text).filter(|s| !s.trim().is_empty());
    let Some(spec) = text_of("spec").or_else(|| text_of("specUrlOrPayload")) else {
        return error(400, "request body must contain a \"spec\" — a URL, file path, or inline OpenAPI spec");
    };
    if let Some(reason) = crate::openapi_validation::spec_fetch_blocked(state, &spec) {
        crate::log::warn_event(state, crate::recorded::LogEntry::at(crate::recorded::Level::Warn, "traffic validation spec fetch blocked by SSRF policy:{}").args([reason.as_str()]));
        return error(403, &format!("traffic validation spec fetch blocked by SSRF policy: {reason}"));
    }
    // `runOffTheEventLoop` refused by a shut-down scheduler (fe354ebd5), logged as the offload's failure
    if state.scheduler_is_shut_down() {
        let entry = crate::recorded::LogEntry::at(crate::recorded::Level::Error, "exception offloading traffic validation request:{}error:{}")
            .request(request)
            .args([crate::recorded::logged(request), Value::String("MockServer is stopping".into())]);
        crate::log::error_event(state, entry);
        return error(503, "unable to schedule traffic validation: MockServer is stopping");
    }
    let rendered = validation_pairs(&state.log.exchanges());
    let pairs: Vec<(HttpRequest, crate::openapi_validation::Response)> =
        rendered.iter().map(|(r, h, s, b)| (r.clone(), crate::openapi_validation::Response { status: *s, headers: h, body: b })).collect();
    match crate::openapi_validation::traffic_report(&spec, &pairs) {
        Ok(report) => Reply::api_body(200, "application/json", json::pretty(&report)),
        Err(e) => error(400, &e),
    }
}

/// Recorded exchanges with a response as the traffic validator reads them: the request, and the response's
/// headers, status and body text.
pub fn validation_pairs(exchanges: &[Arc<crate::recorded::Exchange>]) -> Vec<(HttpRequest, crate::request::MultiMap, u32, String)> {
    exchanges
        .iter()
        .filter(|x| !x.response.is_null())
        .map(|x| {
            let response = &x.response;
            let mut headers = crate::request::MultiMap::new();
            for (k, vs) in response.get("headers").and_then(Value::as_object).into_iter().flatten() {
                let values = vs.as_array().map(|a| a.iter().map(|v| v.as_str().unwrap_or_default().to_string()).collect()).unwrap_or_default();
                headers.push((k.clone(), values));
            }
            let status = response.get("statusCode").and_then(Value::as_u64).unwrap_or(200) as u32;
            let (bytes, default_type) = response.get("body").map(|b| crate::action::response_body(b, None)).unwrap_or_default();
            if let Some(ct) = default_type.filter(|_| crate::request::first(&headers, "content-type").is_none()) {
                headers.push(("content-type".into(), vec![ct]));
            }
            (HttpRequest::clone(&x.request), headers, status, String::from_utf8_lossy(&bytes).into_owned())
        })
        .collect()
}

/// `ControlPlaneAuthenticationHandlerFactory.requireUsableControlPlaneMutualTls(update, configuration)`: an update that
/// would leave control-plane mTLS without a CA chain on the bundled CA is refused whole, before any of it is applied or
/// its TLS posture audited. Each of the four properties is the update's value when it gives one, else the value in
/// force; a value Jackson could not read fails the update as invalid JSON later, so it decides nothing here.
fn control_plane_mtls_refusal(state: &State, update: &serde_json::Map<String, Value>) -> Option<&'static str> {
    let given = |name: &str, default: Value| -> Result<Option<String>, ()> {
        update.get(name).map_or(Ok(None), |value| crate::config::coerce_update(name, value, &default))
    };
    let (Ok(dynamic), Ok(authority)) = (
        given("dynamicallyCreateCertificateAuthorityCertificate", Value::Bool(false)),
        given("certificateAuthorityCertificate", Value::String(String::new())),
    ) else {
        return None;
    };
    let config = &state.config;
    // 9.2.0: the control-plane mTLS settings are fixed at startup (the update never applies them), so only the
    // update's certificate authority settings are taken from it
    crate::auth::control_plane_mtls_refusal(
        config.bool_property("controlPlaneTLSMutualAuthenticationRequired", false),
        config.property("controlPlaneTLSMutualAuthenticationCAChain").as_deref(),
        dynamic.map_or_else(|| crate::tls::dynamic_authority(config), |t| t == "true"),
        authority.or_else(|| config.property("certificateAuthorityCertificate")).as_deref(),
    )
}

/// `DataPlaneMutualTlsTrust.requireUsableDataPlaneMutualTls(update, configuration)` (upstream cb3817ce3, 9.1.0): an
/// update that would make data-plane mTLS trust the bundled CA is refused whole, unless the startup-only
/// `tlsMutualAuthenticationAllowBundledCa` is set; with it, an update that makes mTLS trust the bundled CA is warned
/// about. Each of the four properties is the update's value when it gives one, else the value in force.
fn data_plane_mtls_refusal(state: &State, update: &serde_json::Map<String, Value>) -> Option<&'static str> {
    let given = |name: &str, default: Value| -> Result<Option<String>, ()> {
        update.get(name).map_or(Ok(None), |value| crate::config::coerce_update(name, value, &default))
    };
    let (Ok(required), Ok(chain), Ok(dynamic), Ok(authority)) = (
        given("tlsMutualAuthenticationRequired", Value::Bool(false)),
        given("tlsMutualAuthenticationCertificateChain", Value::String(String::new())),
        given("dynamicallyCreateCertificateAuthorityCertificate", Value::Bool(false)),
        given("certificateAuthorityCertificate", Value::String(String::new())),
    ) else {
        return None;
    };
    let config = &state.config;
    let after = crate::tls::DataPlaneTrust::of(
        required.map_or_else(|| config.hot_bool(crate::config::Hot::TlsMutualAuthenticationRequired, false), |t| t == "true"),
        chain.or_else(|| config.property("tlsMutualAuthenticationCertificateChain")).as_deref(),
        dynamic.map_or_else(|| crate::tls::dynamic_authority(config), |t| t == "true"),
        authority.or_else(|| config.property("certificateAuthorityCertificate")).as_deref(),
    );
    if !crate::tls::allow_bundled_authority(config) {
        return after.refusal();
    }
    if after != crate::tls::DataPlaneTrust::NotTrusted && crate::tls::DataPlaneTrust::of_config(config) == crate::tls::DataPlaneTrust::NotTrusted {
        crate::log::warn_event(state, crate::recorded::LogEntry::new(crate::log_entry::Kind::ServerConfiguration, crate::tls::BUNDLED_CA_TRUSTED_WARNING));
    }
    None
}

/// `GET /mockserver/configuration`: every property's effective value; `PUT` applies the properties given (a
/// `ConfigurationDTO`) at runtime and answers the same.
fn configuration(state: &State, request: &HttpRequest) -> Reply {
    // The reply carries the CORS headers of the configuration in force when it is written: an update's, those it set.
    let cors = || {
        let mut cors = Reply::api(200);
        cors.add_control_plane_cors_headers(request, &state.config);
        cors.headers
    };
    if request.method == "PUT" {
        let invalid = || Reply::api_header(400, "text/plain", "Invalid configuration JSON");
        // An empty body (no body sent at all, or an empty string) is indistinguishable on the wire — both are a
        // zero-length PUT — and upstream's handler reads it with Jackson's `ObjectMapper.readValue(String, Class)`,
        // whose own null-check on a null `content` argument throws `IllegalArgumentException: argument "content" is
        // null`, caught separately from the generic parse-failure path and echoed verbatim (harvested
        // from `ConfigurationSerializerTest.shouldHandleNullInput`/`shouldHandleEmptyInput`, both W and confirmed
        // against the oracle). A non-empty but unparsable body still falls through to `invalid()` below.
        if request.body_str().is_empty() {
            return Reply::api_header(400, "text/plain", "argument \"content\" is null");
        }
        let Ok(Value::Object(update)) = crate::json::parse_lenient(request.body_str().as_bytes()) else { return invalid() };
        let current = crate::config::effective_json(&state.config);
        // Credential-shaped properties arrive as text; everything else is read the way Jackson reads it into the
        // property's DTO field (`config::coerce_update`).
        let mut changes = Vec::new();
        for (name, value) in &update {
            // `ConfigurationDTO.applyTo` deliberately leaves the startup-only properties alone (9.2.0;
            // `apply_configuration_update` warns about each instead)
            if let Some(shown) = startup_only(name) {
                let default = current.get(name).cloned().or_else(|| crate::config::optional_default(name)).unwrap_or_else(|| shown.stand_in());
                if crate::config::coerce_update(name, value, &default).is_err() {
                    return invalid();
                }
                continue;
            }
            // Credential-shaped properties: the generic path below types against
            // `effective_json`'s output, which is the MASKED form for these — comparing an incoming real
            // secret against `"***REDACTED***"` would make masking itself corrupt every credential write.
            // Route them through the restore guard instead, using the real (unmasked) held value.
            if crate::config::credentials::is_credential_dispatch_property(name) {
                // a text field: a number or boolean becomes its text, an array or object cannot
                let Ok(coerced) = crate::config::coerce_update(name, value, &Value::String(String::new())) else { return invalid() };
                let Some(text) = coerced else { continue };
                let held = state.config.property(name).unwrap_or_default();
                if let Some(resolved) = crate::config::credentials::restore_redacted_value(name, &text, &held) {
                    changes.push((name.clone(), resolved));
                }
                continue;
            }
            let Some(default) = current.get(name).cloned().or_else(|| crate::config::optional_default(name)) else { continue };
            // A value that cannot become the property's type fails the whole update.
            match crate::config::coerce_update(name, value, &default) {
                Ok(Some(text)) => changes.push((name.clone(), text)),
                Ok(None) => {}
                Err(()) => return invalid(),
            }
        }
        // Control-plane mTLS with the bundled CA and no CA chain is refused before the posture audit
        if let Some(message) = control_plane_mtls_refusal(state, &update).or_else(|| data_plane_mtls_refusal(state, &update)) {
            return Reply::api_header(400, "text/plain", message);
        }
        // `warnIfLoweringTlsPosture` audits the update before it is validated, so a refused one is warned about too
        let lowered = crate::config::tls_posture_changes(&state.config, &update);
        if !lowered.is_empty() {
            let entry = crate::recorded::LogEntry::new(crate::recorded::Kind::Warn, "control plane PUT /mockserver/configuration changed TLS-sensitive configuration that lowers or alters security posture: {} — verify this was intended, especially as control plane authentication is disabled by default")
                .args([lowered.join("; ")]);
            crate::log::warn_event(state, entry);
        }
        // `ConfigurationDTO.validateFields` makes every check a setter would, before anything is written: a refused
        // update changes nothing
        if let Some(message) = invalid_configuration_field(&update) {
            return Reply::api_header(400, "text/plain", message);
        }
        // `ConfigurationDTO.applyTo` sets one property after another
        changes.sort_by_key(|(name, _)| crate::config::dto_apply_position(name));
        // the held `llmApiKey` is never sent to a new destination: cleared before the destination changes, and a key
        // supplied in this same update is applied after it
        let llm_api_key_cleared = clears_llm_api_key(state, &update);
        if llm_api_key_cleared.is_some() {
            state.config.set_runtime("llmApiKey", String::new());
        }
        // a set's null element still throws a NullPointerException in its setter (a fault, answered 500), after the
        // properties ahead of it are in force
        let mut refused: Option<crate::recorded::Failure> = None;
        for (name, text) in changes {
            // a set that takes no null element fails on one when it is applied
            if crate::config::NULL_REFUSING_SETS.contains(&name.as_str()) && text.contains("null") && serde_json::from_str::<Value>(&text).is_ok_and(|v| v.as_array().is_some_and(|a| a.iter().any(Value::is_null))) {
                refused = Some(crate::recorded::Failure { message: String::new(), bean: json!({"stackTrace": []}), classes: vec!["java.lang.NullPointerException"] });
                break;
            }
            state.config.set_runtime(&name, text);
        }
        if let Some(tls) = &state.tls {
            // a null or blank value changes nothing
            let given = |name: &str| update.get(name).is_some_and(|v| !v.is_null() && !matches!(v, Value::String(s) if s.trim().is_empty()));
            tls.reset_subject_alternative_names(given("sslSubjectAlternativeNameDomains"), given("sslSubjectAlternativeNameIps"));
        }
        if let Some(failure) = refused {
            // part of the update is in force; a fault is answered 500 (`writeUnexpectedFailure`)
            let mut reply = unexpected_failure(state, request, &failure);
            reply.headers.extend(cors());
            return reply;
        }
        apply_configuration_update(state, &update, llm_api_key_cleared == Some(true));
        if state.info_enabled() {
            crate::log::info(state, "configuration updated via API");
            state.log.message_about(crate::recorded::LogEntry::new(crate::recorded::Kind::Info, "configuration updated via API").request(request).correlation(correlation_of(request)), Subject::Request(Arc::new(request.clone())));
        }
    }
    if let Some((at, target, uri_message)) = crate::config::proxy_pass_failure(&state.config) {
        // the serializer's failure carries the configuration object's identity hash
        let hash = (crate::random::uniform() * f64::from(0x6fff_ffffu32)) as u32 + 0x1000_0000;
        let message = format!("Exception while serializing configuration to JSON with value org.mockserver.configuration.Configuration@{hash:x}");
        let (mapping_failure, wrapped) = unprintable_configuration_beans(at, &target, &uri_message, &message);
        // `ConfigurationSerializer.serialize`: the configuration as the argument (Jackson writes it `{}`), then the
        // handler's fault, answered 500 for a GET and a PUT alike (`ControlPlaneFailureResponse`)
        if crate::log::error_enabled(state) {
            let shown = format!("org.mockserver.configuration.Configuration@{hash:x}");
            let entry = crate::recorded::LogEntry::at(crate::recorded::Level::Error, "exception while serializing configuration to JSON with value:{}")
                .args([crate::recorded::Arg::with_text(json!({}), shown)])
                .throwable_bean(mapping_failure.clone());
            crate::log::error_with_throwable(state, &entry, None, &crate::log::throwable_text(&MAPPING_FAILURE_CLASSES, &mapping_failure));
            state.log.message(entry);
        }
        let trace = crate::log::throwable_text(&[&["java.lang.RuntimeException"][..], &MAPPING_FAILURE_CLASSES[..]].concat(), &wrapped);
        let mut reply = text(500, log_unexpected_throwable(state, request, wrapped, &trace));
        reply.headers.extend(cors());
        return reply;
    }
    let sans = state.tls.as_ref().map(|tls| tls.subject_alternative_names());
    let mut reply = Reply::api_header(200, "application/json", json::pretty(&crate::config::effective_json_live(&state.config, sans)));
    reply.headers.extend(cors());
    reply
}

/// `HttpState.applyConfigurationUpdate(supplied)`, after an update is applied: the event log, the expectation store, the
/// audit ring and the OpenAI Responses store take their new capacities (a shrink evicts at once), and an init-only
/// property the update supplied with a value other than the one in force is warned about and reset to it, as is each
/// startup-only property (9.2.0: never applied, see `startup_only`) and a held `llmApiKey` the update cleared. On the
/// 8.0.0 process all of this read `HttpState`'s startup copy of the configuration, so nothing changed and nothing was
/// warned about (upstream 0e8566814, docs/divergences.md).
fn apply_configuration_update(state: &State, update: &serde_json::Map<String, Value>, llm_api_key_cleared: bool) {
    let effective = crate::config::effective_json(&state.config);
    let int = |name: &str| effective.get(name).and_then(Value::as_i64).unwrap_or(0).max(0);
    state.log.resize(int("maxLogEntries") as usize, int("maxEventLogSizeInBytes") as u64, int("maxLoggedBodyBytes") as usize);
    state.store.resize(int("maxExpectations") as usize, int("maxExpectationsSizeInBytes") as u64);
    state.audit.apply_configuration(&state.config);
    crate::llm::responses::apply_configuration(&state.config);
    // `reportInitOnlyProperties`, in its order
    let warn = |name: &str, supplied: String, in_force: String, reason: &str| {
        crate::log::warn_event(state, crate::recorded::LogEntry::new(crate::log_entry::Kind::ServerConfiguration, format!(
            "{name} is fixed at startup and cannot be changed on a running server ({reason}) - the supplied value {supplied} has been IGNORED and {name} remains {in_force}; set it before the server starts (system property, environment variable or startup configuration) to change it"
        )));
    };
    let int_init_only = |name: &str, in_force: i64, reason: &str| {
        let supplied = int(name);
        if update.get(name).is_none_or(Value::is_null) || supplied == in_force {
            return;
        }
        warn(name, supplied.to_string(), in_force.to_string(), reason);
        state.config.set_runtime(name, in_force.to_string());
    };
    let startup_only = |properties: &[(&str, Shown, &str)]| {
        for &(name, shown, reason) in properties {
            if let Some((supplied, in_force)) = startup_only_change(state, &effective, update, name, shown) {
                warn(name, supplied, in_force, reason);
            }
        }
    };
    int_init_only("ringBufferSize", state.init_only_in_force.0, "the log event ring buffer is a fixed-size array allocated when the server started");
    startup_only(STARTUP_ONLY_BEFORE_LLM);
    if llm_api_key_cleared {
        crate::log::warn_event(state, crate::recorded::LogEntry::new(crate::log_entry::Kind::ServerConfiguration, "llmApiKey has been CLEARED because this update changed where the default LLM backend sends requests (llmBaseUrl, or llmProvider with no llmBaseUrl) without supplying llmApiKey, so the key held for the previous destination is never sent to the new one; supply llmApiKey again, in the same update as the destination, to use the backend"));
    }
    startup_only(STARTUP_ONLY_AFTER_LLM);
    int_init_only("maxWebSocketExpectations", state.init_only_in_force.1, "the local callback registries are sized once when first used");
}

/// `ConfigurationDTO.changesLlmDestination` with a held key (9.2.0): `Some(cleared without a new key)` when the update
/// moves the default LLM backend (a different `llmBaseUrl`, or a different `llmProvider` while no base URL is set) and
/// a key is held, so the held key must be cleared; `Some(false)` when the update supplies a key of its own.
fn clears_llm_api_key(state: &State, update: &serde_json::Map<String, Value>) -> Option<bool> {
    let config = &state.config;
    let supplied = |name: &str| update.get(name).and_then(|v| crate::config::coerce_update(name, v, &Value::String(String::new())).ok().flatten());
    let base_in_force = config.property("llmBaseUrl").unwrap_or_default().trim().to_string();
    let provider_in_force = config.property("llmProvider").unwrap_or_default().trim().to_uppercase();
    let base_after = supplied("llmBaseUrl").map_or_else(|| base_in_force.clone(), |v| v.trim().to_string());
    let provider_after = supplied("llmProvider").map_or_else(|| provider_in_force.clone(), |v| v.trim().to_uppercase());
    let moves = base_after != base_in_force || (base_after.is_empty() && provider_after != provider_in_force);
    if !moves || config.property("llmApiKey").is_none_or(|key| key.trim().is_empty()) {
        return None;
    }
    Some(supplied("llmApiKey").is_none_or(|key| crate::config::credentials::contains_redaction_mask(&key)))
}

/// How `warnInitOnlyProperty` shows a startup-only property's values.
#[derive(Clone, Copy)]
enum Shown {
    /// a string, in double quotes (`warnIfInitOnlyPathSupplied`)
    Quoted,
    /// a boolean or number, as `String.valueOf` writes it
    Plain,
    /// a credential: `(not shown)`
    Hidden,
    /// a `Set<String>` or `Map<String, String>`, as Java's `toString` writes it
    Collection,
    /// `controlPlaneScopeMapping`: a `Map<String, ControlPlaneRole>`, compared with an empty map when none is in force
    ScopeMapping,
}

impl Shown {
    /// The type `coerce_update` reads the property as when it has no value in the configuration dump.
    fn stand_in(self) -> Value {
        match self {
            Shown::Plain => Value::Bool(false),
            Shown::Collection | Shown::ScopeMapping => Value::Object(serde_json::Map::new()),
            Shown::Quoted | Shown::Hidden => Value::String(String::new()),
        }
    }
}

/// The supplied value and the value in force, as the WARN shows them, of a startup-only property the update gave a
/// value other than the one in force.
fn startup_only_change(state: &State, effective: &Value, update: &serde_json::Map<String, Value>, name: &str, shown: Shown) -> Option<(String, String)> {
    let given = update.get(name)?;
    let in_force_json = effective.get(name).cloned();
    let default = in_force_json.clone().or_else(|| crate::config::optional_default(name)).unwrap_or_else(|| shown.stand_in());
    let supplied = crate::config::coerce_update(name, given, &default).ok().flatten()?;
    match shown {
        Shown::Hidden => {
            let in_force = state.config.property(name).unwrap_or_default();
            (supplied != in_force).then(|| ("(not shown)".to_string(), "(not shown)".to_string()))
        }
        Shown::Quoted => {
            let in_force = match in_force_json {
                Some(Value::String(text)) => text,
                Some(other) if !other.is_null() => other.to_string(),
                _ => state.config.property(name).unwrap_or_default(),
            };
            (supplied != in_force).then(|| (format!("\"{supplied}\""), format!("\"{in_force}\"")))
        }
        Shown::Plain => {
            let in_force = in_force_json.map(|v| match v {
                Value::String(text) => text,
                other => other.to_string(),
            })?;
            (supplied != in_force).then_some((supplied, in_force))
        }
        Shown::Collection | Shown::ScopeMapping => {
            let supplied: Value = serde_json::from_str(&supplied).ok()?;
            let in_force = in_force_json.unwrap_or(Value::Null);
            let empty = match &supplied {
                Value::Array(_) => Value::Array(Vec::new()),
                _ => Value::Object(serde_json::Map::new()),
            };
            let compared = if in_force.is_null() { &empty } else { &in_force };
            if same_collection(&supplied, compared) {
                return None;
            }
            let in_force_text = match (&in_force, shown) {
                (Value::Null, Shown::ScopeMapping) => "null".to_string(),
                _ => java_collection_text(compared),
            };
            Some((java_collection_text(&supplied), in_force_text))
        }
    }
}

/// Java's `equals` of two sets (arrays, order aside) or two maps.
fn same_collection(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Array(x), Value::Array(y)) => {
            let set = |items: &Vec<Value>| items.iter().map(Value::to_string).collect::<std::collections::BTreeSet<_>>();
            set(x) == set(y)
        }
        (Value::Object(x), Value::Object(y)) => x.len() == y.len() && x.iter().all(|(k, v)| y.get(k) == Some(v)),
        _ => a == b,
    }
}

/// `String.valueOf` of a `HashSet<String>` (`[a, b]`, in hash order) or a `LinkedHashMap<String, …>` (`{k=v}`).
fn java_collection_text(value: &Value) -> String {
    let text = |v: &Value| match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    match value {
        Value::Array(items) => {
            let elements: Vec<String> = items.iter().map(text).collect();
            let order = crate::recorded::java_hashmap_order(&elements);
            format!("[{}]", order.into_iter().map(|i| elements[i].clone()).collect::<Vec<_>>().join(", "))
        }
        Value::Object(map) => format!("{{{}}}", map.iter().map(|(k, v)| format!("{k}={}", text(v))).collect::<Vec<_>>().join(", ")),
        other => text(other),
    }
}

/// The startup-only property `name` is, if it is one (9.2.0): `ConfigurationDTO.applyTo` never applies it.
fn startup_only(name: &str) -> Option<Shown> {
    STARTUP_ONLY_BEFORE_LLM.iter().chain(STARTUP_ONLY_AFTER_LLM).find(|(n, _, _)| *n == name).map(|&(_, shown, _)| shown)
}

const WHO_MAY_USE: &str = "it decides who may use the control plane, so a request to the control plane cannot change it";
const WHAT_EACH_MAY_DO: &str = "it decides what each control plane user may do, so a request to the control plane cannot change it";
const WIDEN_ORIGINS: &str = "it decides which web sites may use the control plane, so a request to the control plane cannot widen it";
const WRITES_FILES: &str = "it decides where the server writes files, so a request to the control plane cannot change it";
const SENDS_REQUESTS: &str = "it decides where the server may send requests, so a request to the control plane cannot widen it";
const EXTENSION_ADMIN: &str = "the extension admin route executor is built when the server starts";
const EXTENSION_LISTENERS: &str = "the extension listener queues are created when the server starts";
const EXTENSION_HELPERS: &str = "extension template helpers are set up when the server starts";
const EXTENSION_DATA_PLANE: &str = "the extension request filter and response transformer executor is built when the server starts";

/// `HttpState.reportInitOnlyProperties` up to the `llmApiKey` WARN: the properties `applyTo` leaves alone, each with how
/// its values are shown and the reason its WARN gives (`ringBufferSize` is warned about ahead of them).
const STARTUP_ONLY_BEFORE_LLM: &[(&str, Shown, &str)] = &[
    ("controlPlaneCorsAllowOrigin", Shown::Quoted, WIDEN_ORIGINS),
    ("controlPlaneTrustedHostSuffixes", Shown::Quoted, WIDEN_ORIGINS),
    ("controlPlaneBasicAuthenticationRequired", Shown::Plain, WHO_MAY_USE),
    ("controlPlaneBasicAuthenticationAllowInsecure", Shown::Plain, "it lets control plane passwords cross the network without TLS, so a request to the control plane cannot enable it"),
    ("controlPlaneBasicAuthenticationUsersFile", Shown::Quoted, WHO_MAY_USE),
    ("controlPlaneBasicAuthenticationCredentials", Shown::Hidden, WHO_MAY_USE),
    // `reportStartupOnlyControlPlaneTrust`
    ("controlPlaneTLSMutualAuthenticationRequired", Shown::Plain, WHO_MAY_USE),
    ("controlPlaneTLSMutualAuthenticationCAChain", Shown::Quoted, WHO_MAY_USE),
    ("controlPlaneJWTAuthenticationRequired", Shown::Plain, WHO_MAY_USE),
    ("controlPlaneJWTAuthenticationJWKSource", Shown::Quoted, WHO_MAY_USE),
    ("controlPlaneJWTAuthenticationExpectedAudience", Shown::Quoted, WHO_MAY_USE),
    ("controlPlaneJWTAuthenticationMatchingClaims", Shown::Collection, WHO_MAY_USE),
    ("controlPlaneJWTAuthenticationRequiredClaims", Shown::Collection, WHO_MAY_USE),
    ("controlPlaneOidcAuthenticationRequired", Shown::Plain, WHO_MAY_USE),
    ("controlPlaneOidcIssuer", Shown::Quoted, WHO_MAY_USE),
    ("controlPlaneOidcJwksUri", Shown::Quoted, WHO_MAY_USE),
    ("controlPlaneOidcAudience", Shown::Quoted, WHO_MAY_USE),
    ("controlPlaneOidcRequiredScopes", Shown::Collection, WHO_MAY_USE),
    ("controlPlaneOidcScopeClaim", Shown::Quoted, WHO_MAY_USE),
    ("controlPlaneAuthorizationEnabled", Shown::Plain, WHAT_EACH_MAY_DO),
    ("controlPlaneScopeMapping", Shown::ScopeMapping, WHAT_EACH_MAY_DO),
    // back in `reportInitOnlyProperties`
    ("controlPlaneAuditEnabled", Shown::Plain, "switching it off would hide the control plane changes that follow, so a request to the control plane cannot change it"),
    ("dashboardAnalyticsEndpoint", Shown::Quoted, "it decides where every dashboard viewer's browser sends usage events, so a request to the control plane cannot change it"),
];

/// `HttpState.reportInitOnlyProperties` after the `llmApiKey` WARN (`maxWebSocketExpectations` is warned about after them).
const STARTUP_ONLY_AFTER_LLM: &[(&str, Shown, &str)] = &[
    ("forwardProxyBlockPrivateNetworks", Shown::Plain, "it decides whether the server may send requests to private-network and cloud-metadata addresses, so a request to the control plane cannot widen it"),
    ("forwardProxyAllowedHosts", Shown::Quoted, SENDS_REQUESTS),
    ("forwardProxyDeniedHosts", Shown::Quoted, SENDS_REQUESTS),
    ("noProxyHosts", Shown::Quoted, "it decides which forwarded requests bypass the upstream proxy, so a request to the control plane cannot change it"),
    ("tlsMutualAuthenticationAllowBundledCa", Shown::Plain, "it lets mTLS trust client certificates anyone can create, so a request to the control plane cannot enable it"),
    ("recordedBodyFilesDirectory", Shown::Quoted, WRITES_FILES),
    ("auditLogFile", Shown::Quoted, WRITES_FILES),
    ("persistedExpectationsPath", Shown::Quoted, WRITES_FILES),
    ("persistedRecordedExpectationsPath", Shown::Quoted, WRITES_FILES),
    ("persistedRecordedRequestsPath", Shown::Quoted, WRITES_FILES),
    ("memoryUsageCsvDirectory", Shown::Quoted, WRITES_FILES),
    ("directoryToSaveDynamicSSLCertificate", Shown::Quoted, "it decides where the server writes certificate and private key files, so a request to the control plane cannot change it"),
    ("grpcProtocPath", Shown::Quoted, "it names an executable the server runs, so a request to the control plane cannot change it"),
    ("staticFilesDirectory", Shown::Quoted, "it decides which server files a request can read, so a request to the control plane cannot change it"),
    ("templateSystemValueAllowList", Shown::Quoted, "it decides which environment variables and system properties templates can read, so a request to the control plane cannot widen it"),
    ("extensions", Shown::Quoted, "extensions are trusted code loaded when the server starts, so a request to the control plane cannot add, remove or replace them"),
    ("extensionScanning", Shown::Plain, "extensions are trusted code loaded when the server starts, so a request to the control plane cannot load more"),
    ("extensionStartTimeoutMillis", Shown::Plain, "extensions are started when the server starts"),
    ("extensionAdminMaxInFlight", Shown::Plain, EXTENSION_ADMIN),
    ("extensionAdminTimeoutMillis", Shown::Plain, EXTENSION_ADMIN),
    ("extensionListenerQueueSize", Shown::Plain, EXTENSION_LISTENERS),
    ("extensionListenerMaxBytes", Shown::Plain, EXTENSION_LISTENERS),
    ("extensionHelperTimeoutMillis", Shown::Plain, EXTENSION_HELPERS),
    ("extensionHelperMaxInFlight", Shown::Plain, EXTENSION_HELPERS),
    ("extensionDataPlaneMaxInFlight", Shown::Plain, EXTENSION_DATA_PLANE),
    ("extensionDataPlaneTimeoutMillis", Shown::Plain, EXTENSION_DATA_PLANE),
    ("logRawNetworkTraffic", Shown::Plain, "it writes the traffic of every connection, credentials and bodies included, to the server's log, so a request to the control plane cannot change it"),
    ("clusterVerifyFanInPeers", Shown::Quoted, "the cluster peer authentication token is sent to every peer, so a request to the control plane cannot choose where it goes"),
    ("clusterFanInPeerAuthToken", Shown::Hidden, "the cluster peer client reads the token once, when the server starts"),
    ("asyncKafkaSaslJaasConfig", Shown::Hidden, "a JAAS configuration chooses which login module class the Kafka client loads, so a request to the control plane cannot set it"),
    ("asyncKafkaBootstrapServers", Shown::Quoted, "every Kafka SASL credential is held by the server and is sent only to the Kafka brokers chosen at startup"),
];

/// The exception classes of the serializer's failure, outermost first, as the console prints them.
const MAPPING_FAILURE_CLASSES: [&str; 3] =
    ["shaded_package.com.fasterxml.jackson.databind.JsonMappingException", "java.lang.IllegalArgumentException", "java.net.URISyntaxException"];

/// The throwables the configuration serializer's failure logs for a mapping whose `targetUri` Java refuses: the
/// `JsonMappingException` (through `URI.create`'s `IllegalArgumentException` and the `URISyntaxException`), and that wrapped
/// in the `RuntimeException` the request handler reports. Jackson's bean form; the frames cannot be reproduced.
fn unprintable_configuration_beans(at: usize, target: &str, uri_message: &str, wrapper_message: &str) -> (Value, Value) {
    let (reason, index) = match uri_message.split_once(" at index ") {
        Some((reason, rest)) => (reason, rest.split(':').next().and_then(|n| n.parse::<i64>().ok()).unwrap_or(-1)),
        None => (uri_message, -1),
    };
    let syntax = json!({"index": index, "input": target, "localizedMessage": uri_message, "message": uri_message, "reason": reason, "stackTrace": []});
    let illegal = json!({"cause": syntax, "localizedMessage": uri_message, "message": uri_message, "stackTrace": []});
    let reference = format!("org.mockserver.serialization.model.ConfigurationDTO[\"proxyPassMappings\"]->java.util.ArrayList[{at}]->org.mockserver.model.ProxyPassMapping[\"targetHost\"]");
    let text = format!("{uri_message} (through reference chain: {reference})");
    let mapping = json!({
        "cause": illegal,
        "localizedMessage": text,
        "message": text,
        "originalMessage": uri_message,
        "path": [
            {"description": "org.mockserver.serialization.model.ConfigurationDTO[\"proxyPassMappings\"]", "fieldName": "proxyPassMappings", "index": -1},
            {"description": format!("java.util.ArrayList[{at}]"), "index": at},
            {"description": "org.mockserver.model.ProxyPassMapping[\"targetHost\"]", "fieldName": "targetHost", "index": -1}
        ],
        "pathReference": reference,
        "stackTrace": []
    });
    let wrapped = json!({"cause": mapping.clone(), "localizedMessage": wrapper_message, "message": wrapper_message, "stackTrace": []});
    (mapping, wrapped)
}

/// `GET /mockserver/config` (bare `/config` too): the effective-configuration diagnostic, each recognised property's
/// resolved value with the tier that supplied it and sensitive values redacted (the text form is `--print-config`).
/// `?nonDefault=true` (any case) leaves out the properties at their built-in default.
fn effective_config(state: &State, request: &HttpRequest) -> Reply {
    let non_default_only = query_param(request, "nonDefault").is_some_and(|v| v.eq_ignore_ascii_case("true"));
    let mut reply = Reply::api_body(200, "application/json", state.config.effective_configuration_json(non_default_only));
    let mut cors = Reply::api(200);
    cors.add_control_plane_cors_headers(request, &state.config);
    reply.headers.extend(cors.headers);
    reply
}

/// `ConfigurationDTO.validateFields`: the first field of a `PUT /mockserver/configuration` update (in upstream's check
/// order) whose value is out of range or malformed, as the 400 text upstream's `IllegalArgumentException` carries. The
/// whole update is refused, none of it applied (found by the validation-parity audit).
fn invalid_configuration_field(update: &serde_json::Map<String, Value>) -> Option<String> {
    // Jackson coerces a numeric string or a float to the DTO's Integer/Long
    let number = |name: &str| -> Option<i64> {
        match update.get(name)? {
            Value::Number(n) => n.as_i64().or_else(|| n.as_f64().map(|f| f as i64)),
            Value::String(s) => s.trim().parse::<i64>().ok().or_else(|| s.trim().parse::<f64>().ok().map(|f| f as i64)),
            _ => None,
        }
    };
    // a number or boolean becomes the text of its field
    let text = |name: &str| match update.get(name)? {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    };
    if let Some(level) = text("logLevel") && !["TRACE", "DEBUG", "INFO", "WARN", "ERROR"].contains(&level.as_str()) {
        return Some(format!("Invalid logLevel: \"{level}\", valid values are TRACE, DEBUG, INFO, WARN, ERROR"));
    }
    let ranges: [(&str, i64, Option<i64>); 10] = [
        ("maxExpectations", 0, Some(100_000)),
        ("maxLogEntries", 0, Some(1_000_000)),
        ("maxEventLogSizeInBytes", 0, None),
        ("maxExpectationsSizeInBytes", 0, None),
        ("maxOpenAiResponsesSizeInBytes", 0, None),
        ("maxLoggedBodyBytes", 0, None),
        ("ringBufferSize", 0, Some(1_073_741_824)),
        ("maxWebSocketExpectations", 0, Some(100_000)),
        ("webSocketProxyMaxRecordedFrames", 0, Some(1_000_000)),
        ("webSocketProxyIdleTimeoutSeconds", 0, Some(86_400)),
    ];
    for (name, low, high) in ranges {
        let Some(value) = number(name) else { continue };
        if value < low || high.is_some_and(|h| value > h) {
            return Some(match high {
                Some(h) => format!("{name} must be between {low} and {h}, got: {value}"),
                None => format!("{name} must be greater than or equal to {low}, got: {value}"),
            });
        }
    }
    // Read back by upstream's `shouldSetAndGetBinaryMessageLengthPrefixProperties`.
    if let Some(framing) = text("binaryMessageFraming") && !["RAW", "POSTGRESQL", "MYSQL", "REDIS", "LENGTH_PREFIX"].contains(&framing.trim().to_uppercase().as_str()) {
        return Some(format!("Invalid binaryMessageFraming: \"{framing}\", the supported values are [RAW, POSTGRESQL, MYSQL, REDIS, LENGTH_PREFIX]"));
    }
    if let Some(bytes) = number("binaryMessageLengthPrefixBytes").filter(|b| ![1, 2, 4, 8].contains(b)) {
        return Some(format!("binaryMessageLengthPrefixBytes must be 1, 2, 4 or 8, got: {bytes}"));
    }
    if let Some(order) = text("binaryMessageLengthPrefixByteOrder") && !["BIG_ENDIAN", "LITTLE_ENDIAN"].contains(&order.trim().to_uppercase().as_str()) {
        return Some(format!("Invalid binaryMessageLengthPrefixByteOrder: \"{order}\", the supported values are [BIG_ENDIAN, LITTLE_ENDIAN]"));
    }
    if let Some(offset) = number("binaryMessageLengthPrefixOffset").filter(|o| *o < 0) {
        return Some(format!("binaryMessageLengthPrefixOffset must be zero or more, got: {offset}"));
    }
    if let Some(kind) = text("forwardProxyTLSX509CertificatesTrustManagerType") && !["ANY", "JVM", "CUSTOM"].contains(&kind.as_str()) {
        return Some(format!("Invalid forwardProxyTLSX509CertificatesTrustManagerType: \"{kind}\""));
    }
    for name in ["forwardHttpProxy", "forwardHttpsProxy", "forwardSocksProxy"] {
        if let Some(address) = text(name) && !is_host_and_port(&address) {
            return Some(format!("Invalid host:port format: \"{address}\", expected format \"host:port\""));
        }
    }
    if let Some(delay) = number("globalResponseDelayMillis").filter(|d| *d < 0) {
        return Some(format!("globalResponseDelayMillis must be >= 0, got: {delay}"));
    }
    // `requireExistingFile`, in `validateFields`' order; the two private-key paths are left alone when they carry the
    // redaction mask (`restoreRedactedValue` never writes one)
    let files = [
        ("controlPlaneTLSMutualAuthenticationCAChain", false),
        ("controlPlaneX509CertificatePath", false),
        ("tlsMutualAuthenticationCertificateChain", false),
        ("forwardProxyTLSCustomTrustX509Certificates", false),
        ("forwardProxyCertificateChain", false),
        ("controlPlanePrivateKeyPath", true),
        ("forwardProxyPrivateKey", true),
    ];
    for (name, masked_passes) in files {
        let Some(path) = text(name) else { continue };
        if masked_passes && crate::config::credentials::contains_redaction_mask(&path) {
            continue;
        }
        if !crate::config::file_exists_or_blank(&path) {
            return Some(format!("Invalid {name}: {path} does not exist or is not accessible"));
        }
    }
    None
}

/// `new URI("dummy://" + s)` with a host and a port: a registry name or IPv4 literal (letters, digits, `-`, `.`) or a
/// bracketed IPv6 literal, then `:` and digits.
fn is_host_and_port(address: &str) -> bool {
    let authority = address.split(['/', '?', '#']).next().unwrap_or("");
    let server = authority.rsplit('@').next().unwrap_or("");
    let (host, port) = if let Some(rest) = server.strip_prefix('[') {
        let Some((v6, tail)) = rest.split_once(']') else { return false };
        (v6.to_string(), tail.strip_prefix(':').map(str::to_string))
    } else {
        match server.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), Some(p.to_string())),
            None => (server.to_string(), None),
        }
    };
    let host_ok = !host.is_empty() && host.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | ':'));
    host_ok && port.is_some_and(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
}

/// `GET /mockserver/proxyConfiguration` (`handleProxyConfiguration`): the CA certificate in effect (written to
/// `mockserver-ca.pem` first; never its key), the proxy URL and environment blocks, as JSON or, for an `Accept` of
/// `text/plain`, the copy-paste block.
fn proxy_configuration(state: &State, request: &HttpRequest) -> Reply {
    // The endpoint's own key-and-certificate factory loads a dynamic CA, writing it first if it is not on disk yet,
    // and logs both (scenario `tls_dynamic_ca_lazy_proxy_configuration`).
    if crate::tls::dynamic_authority(&state.config) {
        crate::tls::log_authority_loaded(state, false);
    }
    let setup = match crate::tls::ProxySetup::new(&state.config, state.ports().first().copied()) {
        Ok(s) => s,
        Err(e) => {
            crate::log::entry(state, &crate::recorded::LogEntry::at(crate::recorded::Level::Error, "exception handling request for proxy configuration:{}").args([e.to_string()]));
            return Reply::api_body(400, "application/json", r#"{"error":"failed to get proxy configuration"}"#);
        }
    };
    if request.first_header("accept").is_some_and(|a| a.to_ascii_lowercase().contains("text/plain")) {
        return Reply::api_body(200, "text/plain", setup.copy_paste_text());
    }
    let pem = std::fs::read_to_string(&setup.ca_certificate_path).unwrap_or_default();
    let body = json!({
        "caCertificatePath": setup.ca_certificate_path,
        "caCertificatePem": pem,
        "httpsProxy": setup.https_proxy,
        "environmentVariables": {"unix": setup.unix_env(), "powershell": setup.powershell_env()},
        "usingDefaultCa": setup.using_default_ca,
        "warning": setup.warning(),
    });
    Reply::api_body(200, "application/json", json::pretty(&body))
}

/// The dashboard UI bundle `build.rs` embedded (`make dashboard`, or its own build); empty when none was built.
mod embedded_dashboard {
    include!(concat!(env!("OUT_DIR"), "/dashboard.rs"));
}

/// The embedded bundle's file at `path` (`/index.html`, `/assets/…`), inflated on first use and kept.
fn embedded_dashboard_file(path: &str) -> Option<bytes::Bytes> {
    use std::io::Read;
    use std::sync::OnceLock;
    static INFLATED: OnceLock<Vec<OnceLock<bytes::Bytes>>> = OnceLock::new();
    let files = embedded_dashboard::FILES;
    let index = files.iter().position(|(p, _)| *p == path)?;
    let cache = INFLATED.get_or_init(|| files.iter().map(|_| OnceLock::new()).collect());
    let bytes = cache[index].get_or_init(|| {
        let mut bytes = Vec::new();
        flate2::read::GzDecoder::new(files[index].1).read_to_end(&mut bytes).expect("embedded dashboard file inflates");
        bytes.into()
    });
    Some(bytes.clone())
}

/// `URI.normalize` on an absolute path without `..` (the caller rejects those): drops `.` segments and empty ones
/// (`//`), keeping a trailing `/` when the path ends in one or in `.`.
fn normalize_path(path: &str) -> String {
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty() && *s != ".").collect();
    let trailing = path.ends_with('/') || path.ends_with("/.");
    let mut normalized = format!("/{}", segments.join("/"));
    if trailing && !segments.is_empty() {
        normalized.push('/');
    }
    normalized
}

/// `DashboardHandler.renderDashboard`: the file at the path (normalized, then percent-decoded) in the dashboard
/// bundle, `index.html` for the bare path, an empty body for one of the bundle's directories (as the jar's class
/// loader finds them); 404 when there is none or the path climbs out. Upstream reads the bundle from
/// `org/mockserver/dashboard/` on the classpath; here the bundle embedded at build time answers first (MockServer's
/// own jar), then a file under `org/mockserver/dashboard/` on the class path roots (`class_path`), then one relative
/// to the working directory, which stands in for the test resources upstream's tests add to the classpath
/// (`docs/divergences.md`). Upstream writes the response straight to the channel, so the
/// only `Connection` header is `keep-alive` on a 200 to a keep-alive request.
/// A path `java.net.URI.create` refuses (`a[b`, `%zz`) throws out of the handler: `HttpRequestHandler` logs the
/// exception and answers 400 with the `URISyntaxException` message. (Over HTTP/1.1 a malformed `%` escape never gets
/// here: `http1` closes the connection first, as `CallbackWebSocketServerHandler`'s path decoding does.)
fn dashboard(state: &State, request: &HttpRequest) -> Reply {
    let path = request.path.strip_prefix("/mockserver/dashboard").unwrap_or_default();
    if !path.contains("..") && !path.is_empty() && path != "/" && let Err(message) = crate::java_uri::parse(&format!("/org/mockserver/dashboard{path}")) {
        log_exception(state, request, &message);
        return text(400, message);
    }
    dashboard_in(request, "org/mockserver/dashboard")
}

/// [`dashboard`] with the directory that stands in for the test resources (`org/mockserver/dashboard`).
fn dashboard_in(request: &HttpRequest, local_root: &str) -> Reply {
    let mut path = request.path.strip_prefix("/mockserver/dashboard").unwrap_or_default().to_string();
    if path.is_empty() || path == "/" {
        path = "/index.html".into();
    }
    let not_found = |close: bool| {
        let mut reply = Reply::status(404);
        reply.close_socket = Some(close || !request.keep_alive);
        reply.suppress_connection_header = true;
        reply
    };
    if path.contains("..") {
        return not_found(true);
    }
    let resource = normalize_path(&format!("/org/mockserver/dashboard{path}"));
    let relative = resource.strip_prefix("/org/mockserver/dashboard").filter(|r| r.is_empty() || r.starts_with('/'));
    let Some(relative) = relative else {
        return not_found(true);
    };
    // `URI.getPath` decodes; the class loader then looks the decoded path up as is, so `.`/`..` it spells find nothing.
    let relative = percent_encoding::percent_decode_str(relative).decode_utf8_lossy().into_owned();
    let relative = relative.as_str();
    if relative.split('/').any(|s| s == "." || s == "..") {
        return not_found(false);
    }
    let local = format!("{local_root}{relative}");
    let bytes = if relative.ends_with('/') || relative.is_empty() {
        // A directory: only the bundle's own, or one in the working directory.
        let directory = relative.trim_end_matches('/');
        let found = embedded_dashboard::DIRECTORIES.contains(&directory) || std::path::Path::new(&local).is_dir();
        found.then(bytes::Bytes::new)
    } else {
        embedded_dashboard_file(relative)
            .or_else(|| embedded_dashboard::DIRECTORIES.contains(&relative).then(bytes::Bytes::new))
            .or_else(|| crate::class_path::resource(&format!("org/mockserver/dashboard{relative}")).map(bytes::Bytes::from))
            .or_else(|| std::fs::read(&local).ok().map(bytes::Bytes::from))
            .or_else(|| std::path::Path::new(&local).is_dir().then(bytes::Bytes::new))
    };
    let Some(bytes) = bytes else {
        return not_found(false);
    };
    let extension = path.rsplit_once('.').map(|(_, e)| e).unwrap_or_default();
    let content_type = match extension {
        "css" => "text/css; charset=utf-8",
        "js" => "application/javascript; charset=UTF-8",
        "map" | "json" => "application/json; charset=UTF-8",
        "html" => "text/html; charset=utf-8",
        "ico" => "image/x-icon",
        "svg" => "image/svg+xml",
        "woff2" => "application/font-woff2",
        "png" => "image/png",
        _ => "application/octet-stream",
    };
    let mut reply = Reply::status(200);
    reply.headers.push(("content-type".into(), content_type.into()));
    reply.headers.push(("content-length".into(), bytes.len().to_string()));
    reply.suppress_connection_header = true;
    if request.keep_alive {
        reply.headers.push(("connection".into(), "keep-alive".into()));
    }
    reply.body = bytes;
    reply
}

/// `PUT /mockserver/crud`: registers (or replaces) a CRUD resource from a `CrudExpectationsDefinition`.
fn register_crud(state: &State, request: &HttpRequest) -> Reply {
    let failed = |message: &str| text(400, format!("failed to register CRUD resource: {message}"));
    let definition = match crate::json::parse_lenient(request.body_json_or_xml_str().as_bytes()) {
        Ok(Value::Object(o)) => o,
        Ok(_) => return failed("definition must be a JSON object"),
        Err(e) => return failed(&e.to_string()),
    };
    let Some(base_path) = definition.get("basePath").and_then(Value::as_str).filter(|p| !p.is_empty()) else {
        return text(400, "basePath is required".to_string());
    };
    let id_field = definition.get("idField").and_then(Value::as_str).unwrap_or("id").to_string();
    // An unknown strategy reads as null, i.e. the default.
    let strategy = match definition.get("idStrategy").and_then(Value::as_str) {
        Some("UUID") => crate::crud::IdStrategy::Uuid,
        _ => crate::crud::IdStrategy::AutoIncrement,
    };
    let initial = definition.get("initialData").and_then(Value::as_array).cloned().unwrap_or_default();
    let store = crate::crud::Store::new(id_field.clone(), strategy, &initial);
    let item_count = store.len();
    if let Err(message) = state.crud.register(base_path, store) {
        return failed(&message);
    }
    if state.info_enabled() {
        state.log.message(crate::recorded::LogEntry::new(crate::recorded::Kind::Info, "registered CRUD resource at base path:{}").args([base_path]));
    }
    let body = json!({
        "basePath": base_path,
        "idField": id_field,
        "idStrategy": if strategy == crate::crud::IdStrategy::Uuid { "UUID" } else { "AUTO_INCREMENT" },
        "itemCount": item_count,
    });
    Reply::api_body(201, "application/json", json::pretty(&body))
}

/// `MatchDifference.Field.values().length`: `debugMismatch`'s (deliberately approximate) field count.
const DEBUG_MISMATCH_TOTAL_FIELDS: usize = crate::explain::TOTAL_FIELDS;
/// `DEBUG_MISMATCH_MAX_EXPECTATIONS`
const DEBUG_MISMATCH_MAX_EXPECTATIONS: usize = 100;

/// `PUT /mockserver/lint` (`HttpState.lint`): the expectations in the body (one or an array), not stored, or the
/// stored ones when the body is blank. A body that is no expectation or array, or no JSON, is answered 400 in the
/// `explainError` form.
fn lint(state: &State, request: &HttpRequest) -> Reply {
    let body = request.body_json_or_xml_str();
    if body.trim().is_empty() {
        let stored: Vec<crate::lint::Stored> = state
            .store
            .all()
            .iter()
            .map(|e| crate::lint::Stored { input: e.input.clone(), canonical: e.current(), active: e.is_active(), match_count: e.match_count() })
            .collect();
        return Reply::api_body(200, "application/json", json::pretty(&crate::lint::lint_stored(&stored)));
    }
    let error = |message: String| {
        let error = json!({"error": format!("failed to lint expectations: {message}"), "timestamp": crate::scim::now_text()});
        Reply::api_body(400, "application/json", json::pretty(&error))
    };
    if let Err(e) = crate::jnode::read_tree(&body) {
        return error(e.message);
    }
    let entries = match crate::json::parse_lenient(body.as_bytes()) {
        Ok(Value::Array(items)) => items,
        Ok(item @ Value::Object(_)) => vec![item],
        Ok(_) => return error("expected an expectation or an array of expectations".to_string()),
        Err(e) => return error(e.to_string()),
    };
    let result = crate::lint::lint_entries(&entries, |text, format| {
        crate::log::error_event(state, crate::recorded::LogEntry::at(crate::recorded::Level::Error, format).args([text]));
    });
    Reply::api_body(200, "application/json", json::pretty(&result))
}

/// `PUT /mockserver/debugMismatch`: how a probe request (a request definition in the body) fares against every
/// expectation, all fields evaluated, and which expectation comes closest (`HttpState.debugMismatch`).
/// `explainUnmatched`: for each recent request no expectation matched (newest first, `limit` of 1 to 100, default
/// 10), every active expectation (at most 50, 500 evaluations in all) ranked by how many fields differ, with the
/// differences and remediation hints.
fn explain_unmatched(state: &State, request: &HttpRequest) -> Reply {
    const MAX_EXPECTATIONS: usize = 50;
    const EVALUATION_BUDGET: usize = 500;
    let correlation_id = uuid::Uuid::new_v4().to_string();
    let timestamp = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Nanos, true);
    let mut limit = 10;
    let mut suggest_fixes = false;
    if !request.body_json_or_xml_str().trim().is_empty() && let Ok(body) = crate::json::parse_lenient(request.body_json_or_xml_str().as_bytes()) {
        // `body.path("suggestFixes").asBoolean(false)`
        suggest_fixes = match body.get("suggestFixes") {
            Some(Value::Bool(b)) => *b,
            Some(Value::String(s)) => s.trim() == "true",
            Some(Value::Number(n)) => n.as_i64().is_some_and(|n| n != 0),
            _ => false,
        };
        if let Some(l) = body.get("limit") {
            limit = match l {
                Value::Number(n) => n.as_i64().or_else(|| n.as_f64().map(|f| f as i64)).unwrap_or(10),
                Value::String(s) => s.trim().parse().unwrap_or(10),
                Value::Bool(b) => *b as i64,
                _ => 10,
            };
        }
    }
    let expectations = state.store.active();
    let mut evaluations = 0;
    let mut truncated = false;
    let mut unmatched = Vec::new();
    for exchange in state.log.unmatched(limit) {
        if truncated {
            break;
        }
        let r = &exchange.request;
        // the differences quote the recorded request's values: scrubbed of its credentials under `redactSecretsInLog`
        // (upstream c76143e4a)
        let logged = crate::recorded::logged(r);
        let redaction = crate::recorded::redact_fields(&state.config).map(|f| crate::log_redaction::Redaction::new(&f, &[&logged], &[], &[]));
        let scrub = |text: &str| redaction.as_ref().map_or_else(|| text.to_string(), |r| r.scrub(text));
        let mut results: Vec<(usize, serde_json::Map<String, Value>, &crate::store::Expectation)> = Vec::new();
        for e in expectations.iter().take(MAX_EXPECTATIONS) {
            if evaluations >= EVALUATION_BUDGET {
                truncated = true;
                break;
            }
            evaluations += 1;
            let (result, _, differing) = crate::explain::compare_fields(e, r, &scrub);
            results.push((differing, result, e));
        }
        results.sort_by_key(|(n, _, _)| *n);
        // `"suggestFixes": true`: the closest non-matching expectations each carry a `suggestedFix` (upstream e97463a08)
        let mut fixes = 0;
        let results: Vec<Value> = results
            .into_iter()
            .map(|(_, mut result, e)| {
                if suggest_fixes && fixes < crate::fix_suggest::FIXES_PER_REQUEST && result.get("matches") != Some(&Value::Bool(true)) {
                    let fields = crate::fix_suggest::differing_fields(&result);
                    let fix = crate::fix_suggest::suggest(&e.canonical["httpRequest"], r, &fields, redaction.as_ref());
                    result.insert("suggestedFix".into(), fix);
                    fixes += 1;
                }
                Value::Object(result)
            })
            .collect();
        let mut o = serde_json::Map::new();
        o.insert("timestamp".into(), exchange.timestamp.format("%Y-%m-%d %H:%M:%S%.3f").to_string().into());
        o.insert("method".into(), r.method.clone().into());
        o.insert("path".into(), r.path.clone().into());
        let evaluated = results.len();
        o.insert("closestExpectations".into(), Value::Array(results));
        o.insert("totalExpectationsEvaluated".into(), evaluated.into());
        unmatched.push(Value::Object(o));
    }
    let mut body = serde_json::Map::new();
    body.insert("correlationId".into(), correlation_id.into());
    body.insert("timestamp".into(), timestamp.into());
    body.insert("unmatchedRequestCount".into(), unmatched.len().into());
    body.insert("truncated".into(), truncated.into());
    body.insert("unmatchedRequests".into(), Value::Array(unmatched));
    let mut body = Value::Object(body);
    // `explainUnmatchedWithOptionalNarration` (9.1.0)
    if crate::explain::narration_requested(request) {
        let mut quoted: Vec<Value> = state.log.unmatched(limit).iter().map(|x| crate::recorded::logged(&x.request)).collect();
        quoted.extend(state.store.active().iter().take(MAX_EXPECTATIONS).map(|e| e.canonical["httpRequest"].clone()));
        body = crate::explain::narrate(state, body, &quoted);
    }
    Reply::api_body(200, "application/json", json::pretty(&body))
}

fn debug_mismatch(state: &State, request: &HttpRequest) -> Reply {
    let correlation_id = uuid::Uuid::new_v4().to_string();
    let timestamp = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Nanos, true);
    let error = |message: String| {
        let body = json!({"error": message, "correlationId": correlation_id, "timestamp": timestamp});
        Reply::api_body(400, "application/json", json::pretty(&body))
    };
    // `HttpState.debugMismatch` logs what reading the definition throws, under this answer's correlation id.
    let thrown = |message: String| {
        if crate::log::error_enabled(state) {
            let entry = crate::recorded::LogEntry::at(crate::recorded::Level::Error, "exception handling debugMismatch request:{}error:{}")
                .correlation(&correlation_id)
                .args([crate::recorded::Arg::from(crate::recorded::logged(request)), message.as_str().into()]);
            crate::log::entry_as(state, crate::recorded::Level::Error, &entry);
            state.log.message(entry);
        }
        error(format!("failed to debug request mismatch: {message}"))
    };
    let raw = request.body_json_or_xml_str().into_owned();
    let definition = if raw.trim().is_empty() {
        json!({})
    } else {
        let Ok(v) = crate::json::parse_lenient(request.body_json_or_xml_str().as_bytes()) else {
            let token: String = raw.trim_start().chars().take_while(|c| !c.is_whitespace() && !matches!(c, ',' | ']' | '}' | ':')).collect();
            let report = format!(
                "JsonParseException - Unrecognized token '{token}': was expecting (JSON String, Number (or 'NaN'/'+INF'/'-INF'), Array, Object or token 'null', 'true' or 'false')\n at [Source: REDACTED (`StreamReadFeature.INCLUDE_SOURCE_IN_LOCATION` disabled); line: 1, column: 1]"
            );
            return thrown(schema::incorrect_request_matcher(&raw, &report));
        };
        if let Err(report) = schema::validate_request_definition(&v) {
            return thrown(schema::incorrect_request_matcher(&raw, &report));
        }
        if let Some(message) = unreadable_request_definition(state, &raw, &v) {
            return thrown(message);
        }
        v
    };
    if definition.get("specUrlOrPayload").is_some() {
        return error("debugMismatch only supports HttpRequest definitions".into());
    }
    let mut probe = pseudo_request(&canonical::request_definition(&definition));
    // `"body": ""` reads as `StringBody("")`, which the canonical form drops: the matchers see `""`, not null.
    probe.empty_body_given = probe.body.is_empty() && definition.get("body").is_some_and(|b| !b.is_null());
    // The probe is deserialised as given: its headers are compared in the order the definition lists them.
    let given: Vec<String> = match definition.get("headers") {
        Some(Value::Object(o)) => o.keys().cloned().collect(),
        Some(Value::Array(items)) => items.iter().filter_map(|i| i.get("name").and_then(Value::as_str).map(str::to_string)).collect(),
        _ => Vec::new(),
    };
    probe.headers.sort_by_key(|(k, _)| given.iter().position(|g| g == k).unwrap_or(usize::MAX));
    let expectations = state.store.active();
    let evaluated = expectations.len().min(DEBUG_MISMATCH_MAX_EXPECTATIONS);
    let mut closest: Option<(usize, String, usize)> = None;
    let mut results = Vec::new();
    for e in expectations.iter().take(evaluated) {
        let mut result = serde_json::Map::new();
        result.insert("expectationId".into(), e.id.clone().into());
        let http_request = &e.canonical["httpRequest"];
        if http_request.get("specUrlOrPayload").is_none() && !canonical::is_conditional_request(http_request) {
            let printed = |k: &str| http_request.get(k).and_then(Value::as_str).map(|s| s.trim_start_matches('!').to_string()).unwrap_or_default();
            result.insert("expectationPath".into(), printed("path").into());
            result.insert("expectationMethod".into(), printed("method").into());
        }
        // the probe is a request definition: a `!value` in its maps is a negated value
        let matches = crate::matcher::with_definition_values(|| e.matcher.matches(&probe, Mode::DataPlane));
        result.insert("matches".into(), matches.into());
        if matches {
            result.insert("matchedFieldCount".into(), DEBUG_MISMATCH_TOTAL_FIELDS.into());
            result.insert("totalFieldCount".into(), DEBUG_MISMATCH_TOTAL_FIELDS.into());
        } else {
            let differences = crate::matcher::with_definition_values(|| e.matcher.all_differences(&probe));
            let matched = DEBUG_MISMATCH_TOTAL_FIELDS.saturating_sub(differences.len());
            result.insert("matchedFieldCount".into(), matched.into());
            result.insert("totalFieldCount".into(), DEBUG_MISMATCH_TOTAL_FIELDS.into());
            result.insert("differences".into(), Value::Object(differences.iter().map(|(f, texts)| (f.to_string(), json!(texts))).collect()));
            if let Some(any_of) = crate::matcher::with_definition_values(|| e.matcher.any_of_branches(&probe)) {
                result.insert("anyOf".into(), any_of);
            }
            if closest.as_ref().is_none_or(|(failures, _, _)| differences.len() < *failures) {
                closest = Some((differences.len(), e.id.clone(), matched));
            }
        }
        results.push(Value::Object(result));
    }
    let mut body = serde_json::Map::new();
    body.insert("correlationId".into(), correlation_id.clone().into());
    body.insert("timestamp".into(), timestamp.clone().into());
    body.insert("totalExpectations".into(), expectations.len().into());
    body.insert("evaluatedExpectations".into(), evaluated.into());
    if expectations.len() > DEBUG_MISMATCH_MAX_EXPECTATIONS {
        body.insert("truncated".into(), true.into());
        body.insert("maxExpectationsEvaluated".into(), DEBUG_MISMATCH_MAX_EXPECTATIONS.into());
    }
    if let Some((_, id, matched)) = closest {
        body.insert("closestMatch".into(), json!({"expectationId": id, "matchedFields": matched, "totalFields": DEBUG_MISMATCH_TOTAL_FIELDS}));
    }
    body.insert("results".into(), Value::Array(results));
    Reply::api_body(200, "application/json", json::pretty(&Value::Object(body)))
}

/// `PUT /mockserver/status`: the bound ports and, while `dnsEnabled` runs a DNS listener, its UDP port
/// (`HttpRequestHandler.dnsPort`); a bind's answer leaves the DNS port out.
fn status(state: &State) -> Reply {
    port_binding(&state.ports(), state.dns.get().map(|dns| dns.port))
}

/// Upstream's `PortBinding` document, keys in Jackson's alphabetical order; an empty port list and an absent DNS
/// port are left out.
fn port_binding(ports: &[u16], dns_port: Option<u16>) -> Reply {
    let mut body = json!({"artifactId": "mockserver-core"});
    if let Some(port) = dns_port.filter(|port| *port > 0) {
        body["dnsPort"] = json!(port);
    }
    body["gitHash"] = json!(UPSTREAM_GIT_HASH);
    body["groupId"] = json!("org.mock-server");
    if !ports.is_empty() {
        body["ports"] = json!(ports);
    }
    body["version"] = json!(VERSION);
    Reply::api_header(200, "application/json", json::pretty(&body))
}

/// `PUT /mockserver/bind` with `{"ports": [..]}`: answers the `PortBinding` of the ports just bound.
fn bind(state: &Arc<State>, request: &HttpRequest) -> Reply {
    let unparsable = || text(400, format!("exception while parsing PortBinding for [{}]", request.body_str()));
    // 9.2.0 (#83): an empty, blank or `null` body is answered 400 `invalid or missing port binding` (it used to get no
    // answer at all).
    let missing = || text(400, "invalid or missing port binding");
    if request.body_str().trim().is_empty() {
        return missing();
    }
    let Ok(input) = crate::json::parse_lenient(request.body_str().as_bytes()) else { return unparsable() };
    if input.is_null() {
        return missing();
    }
    let requested: Option<Vec<u16>> = match input.get("ports") {
        None | Some(Value::Null) => Some(Vec::new()),
        Some(Value::Array(items)) => items.iter().map(|p| p.as_u64().and_then(|p| u16::try_from(p).ok())).collect(),
        Some(_) => None,
    };
    let Some(requested) = requested.filter(|_| input.is_object()) else { return unparsable() };
    match crate::server::bind(state, &requested) {
        Ok(bound) => port_binding(&bound, None),
        Err(message) => text(400, message),
    }
}

/// A `ResponseWriter.writeResponse(request, status, message, "text/plain")` answer: `content-type` comes first.
fn text(status: u32, message: impl Into<String>) -> Reply {
    Reply::api_header(status, "text/plain", message.into())
}

/// A retrieve's text answer, `response().withBody(…, MediaType.PLAIN_TEXT_UTF_8)`: `content-type` comes last.
fn retrieved_text(status: u32, message: impl Into<String>) -> Reply {
    Reply::api_body(status, "text/plain", message.into())
}

/// `ControlPlaneFailureResponse.UNEXPECTED_FAILURE_MESSAGE`.
pub(crate) const UNEXPECTED_FAILURE_MESSAGE: &str = "unexpected error processing request, see the MockServer log for correlation id: ";

/// `ControlPlaneFailureResponse.isClientError`, over the exception's Java class: an `IllegalArgumentException` (or a
/// subclass), an `UnsupportedOperationException`, or a Jackson `JsonProcessingException` other than a
/// `StreamWriteException` or an `InvalidDefinitionException`. Anything else is a fault in MockServer.
pub(crate) fn is_client_error(class: &str) -> bool {
    const ILLEGAL_ARGUMENT: &[&str] = &[
        "java.lang.IllegalArgumentException",
        "java.lang.NumberFormatException",
        "java.util.regex.PatternSyntaxException",
        "java.nio.charset.IllegalCharsetNameException",
        "java.nio.charset.UnsupportedCharsetException",
        "java.nio.file.InvalidPathException",
        "java.security.InvalidParameterException",
        "java.lang.UnsupportedOperationException",
    ];
    if ILLEGAL_ARGUMENT.contains(&class) {
        return true;
    }
    let jackson = class.strip_prefix("shaded_package.").unwrap_or(class);
    jackson.starts_with("com.fasterxml.jackson.") && !jackson.ends_with(".StreamWriteException") && !jackson.ends_with(".InvalidDefinitionException")
}

/// `ControlPlaneFailureResponse.logUnexpectedFailure`: a fault in MockServer logged once at ERROR, with the request's
/// correlation id (a new one when it has none), the request, and the exception; the generic message naming that id.
pub(crate) fn log_unexpected_failure(state: &State, request: &HttpRequest, failure: &crate::recorded::Failure) -> String {
    log_unexpected_throwable(state, request, failure.bean.clone(), &crate::log::throwable_text(&failure.classes, &failure.bean))
}

/// [`log_unexpected_failure`] for an exception given as its JSON bean and its stack trace's text.
fn log_unexpected_throwable(state: &State, request: &HttpRequest, bean: Value, trace: &str) -> String {
    let id = correlation_of(request);
    if crate::log::error_enabled(state) {
        let logged = crate::recorded::logged(request);
        let entry = crate::recorded::LogEntry::at(crate::recorded::Level::Error, "unexpected exception processing request:{}correlation id:{}")
            .request_json(logged.clone())
            .correlation(id.clone())
            .args([crate::recorded::Arg::from(logged), id.as_str().into()])
            .throwable(trace)
            .throwable_bean(bean);
        crate::log::error_with_throwable(state, &entry, Some(request), trace);
        state.log.message_about(entry, Subject::Request(Arc::new(request.clone())));
    }
    format!("{UNEXPECTED_FAILURE_MESSAGE}{id}")
}

/// `ControlPlaneFailureResponse.writeUnexpectedFailure`: 500, text, the generic message.
pub(crate) fn unexpected_failure(state: &State, request: &HttpRequest, failure: &crate::recorded::Failure) -> Reply {
    text(500, log_unexpected_failure(state, request, failure))
}

/// `HttpRequestHandler`'s catch around `processAction`: a data-plane request whose processing threw, client error or
/// not, is logged as [`log_unexpected_failure`] and answered `dataPlaneFailureResponse`: 500 with its reason phrase and
/// the generic message as text, written as a mock response (no `version`; CORS only with `enableCORSForAllResponses`).
pub(crate) fn data_plane_failure(state: &State, request: &HttpRequest, failure: &crate::recorded::Failure) -> Reply {
    let message = log_unexpected_failure(state, request, failure);
    let mut reply = Reply::status(500);
    reply.reason = Some("Internal Server Error".into());
    reply.headers.push(("content-type".into(), "text/plain; charset=utf-8".into()));
    reply.body = message.into();
    reply
}

/// `HttpState.unexpectedFailure`, for the endpoints that answer in JSON: 500, `{"error": <the generic message>}`.
pub(crate) fn unexpected_failure_json(state: &State, request: &HttpRequest, failure: &crate::recorded::Failure) -> Reply {
    Reply::api_body(500, "application/json", json!({ "error": log_unexpected_failure(state, request, failure) }).to_string())
}

/// `ControlPlaneFailureResponse.write` for a client error: `exception processing request:{}error:{}` with the
/// request and the exception's message, then 400 with that message as text.
pub(crate) fn client_error(state: &State, request: &HttpRequest, message: &str) -> Reply {
    if crate::log::error_enabled(state) {
        let logged = crate::recorded::logged(request);
        let entry = crate::recorded::LogEntry::at(crate::recorded::Level::Error, "exception processing request:{}error:{}")
            .request_json(logged.clone())
            .correlation(correlation_of(request))
            .args([crate::recorded::Arg::from(logged), message.into()]);
        crate::log::entry_as(state, crate::recorded::Level::Error, &entry);
        state.log.message_about(entry, Subject::Request(Arc::new(request.clone())));
    }
    text(400, message)
}

/// Netty's `QueryStringDecoder` failing on a request's query (a `%` not followed by two hex digits): the message of
/// the `IllegalArgumentException` it throws, which the transport logs and then drops every parameter.
fn netty_query_failure(request: &HttpRequest) -> Option<String> {
    let raw = request.raw_query.as_deref().filter(|q| q.contains('%'))?;
    let uri = format!("{}?{raw}", request.path);
    let prefix = request.path.chars().count() + 1;
    let chars: Vec<char> = raw.split('#').next().unwrap_or_default().chars().collect();
    for (i, c) in chars.iter().enumerate() {
        if *c != '%' {
            continue;
        }
        let at = prefix + i;
        let (first, second) = (chars.get(i + 1).filter(|c| **c != '&'), chars.get(i + 2).filter(|c| **c != '&'));
        let (Some(first), Some(second)) = (first, second) else {
            return Some(format!("unterminated escape sequence at index {at} of: {uri}"));
        };
        if !(first.is_ascii_hexdigit() && second.is_ascii_hexdigit()) {
            return Some(format!("invalid hex byte '{first}{second}' at index {} of '{uri}'", at + 1));
        }
    }
    None
}

/// The request as the control plane sees it after the transport failed to decode its query: every parameter dropped
/// (the raw string stays, for the filter's own refusal), the failure logged first as `exception{}while parsing query
/// string{}`. `None` when the query decodes.
fn undecodable_query(state: &State, request: &HttpRequest) -> Option<HttpRequest> {
    let message = netty_query_failure(request)?;
    if crate::log::error_enabled(state) {
        let uri = format!("{}?{}", request.path, request.raw_query.as_deref().unwrap_or_default());
        let partial = HttpRequest { path: request.path.clone(), query: request.query.clone(), ..HttpRequest::default() };
        let entry = crate::recorded::LogEntry::at(crate::recorded::Level::Error, "exception{}while parsing query string{}").args([uri, message]);
        crate::log::entry_as(state, crate::recorded::Level::Error, &entry);
        state.log.message_about(entry, Subject::Request(Arc::new(partial)));
    }
    Some(HttpRequest { query: Default::default(), ..request.clone() })
}

fn query_param<'a>(request: &'a HttpRequest, name: &str) -> Option<&'a str> {
    crate::request::first(&request.query, name)
}

/// `ExpectationSerializer.deserializeArray(json, false)` over the entries `splitJSONArrayToJSONNodes` gave: each one
/// validated against the schema (an entry with `specUrlOrPayload` as an OpenAPI expectation, expanded into its
/// operations' expectations), the expectations in input form, or the failure's message. `parse_failure` gets the
/// pretty entry and the log format of an entry whose DTO cannot be read (`deserialize` logs it). Shared by
/// the control plane and `mockserver import`, which validates before it connects (`MockServerClient.importExpectations`).
pub(crate) fn deserialize_expectations(
    given: &[Value],
    realistic: bool,
    mut processing: impl FnMut(usize, &Value),
    mut parse_failure: impl FnMut(&str, &str),
) -> Result<Vec<Value>, String> {
    // `deserializeArray(json, false)`: an empty array is no expectation (ExpectationSerializationErrorsTest).
    if given.is_empty() {
        return Err("1 error:\n - an expectation or array of expectations is required".to_string());
    }
    let mut errors = Vec::new();
    let mut items = Vec::new();
    for (index, item) in given.iter().enumerate() {
        processing(index, item);
        // `ExpectationSerializer.deserializeArray`: an item with `specUrlOrPayload` is an OpenAPI expectation,
        // expanded into its operations' expectations (`OpenAPIExpectationSerializer.deserializeToExpectations`).
        if let Some(definition) = item.as_object().filter(|o| o.contains_key("specUrlOrPayload")) {
            if let Err(report) = schema::validate_openapi_expectation(item) {
                errors.push(schema::incorrect_openapi_expectation(item, &report));
                continue;
            }
            match crate::openapi_expectations::build(definition, realistic) {
                Ok(built) => items.extend(built.into_iter().map(Value::Object)),
                Err(message) => errors.push(message),
            }
        } else if let Err(report) = schema::validate_expectation(item) {
            errors.push(schema::incorrect_expectation(item, &report));
        } else if let Some((cause, chain)) = crate::matcher::expectation_body_failure(item) {
            // `ExpectationSerializer.deserialize`: what reading the DTO throws is logged and reported, the
            // entry as `splitJSONArrayToJSONNodes` printed it (arrays over lines too).
            let text = json::pretty_multiline(item);
            parse_failure(&text, &format!("exception while parsing{{}}for Expectation {cause} (through reference chain: {chain})"));
            // 9.2.0 appends the root cause's message (`rootCauseMessage`): the exception Jackson wrapped, without the chain
            errors.push(format!("exception while parsing [{text}] for Expectation because {cause}"));
        } else if let Some((cause, chain)) = item.get("httpRequest").and_then(crate::matcher::date_time_failure) {
            // `NottableStringDeserializer`: a date-time value it cannot read
            let text = json::pretty_multiline(item);
            let chain = format!("org.mockserver.serialization.model.ExpectationDTO[\"httpRequest\"]{chain}");
            parse_failure(&text, &format!("exception while parsing{{}}for Expectation {cause} (through reference chain: {chain})"));
            errors.push(format!("exception while parsing [{text}] for Expectation because {cause}"));
        } else if item.get("metadata").and_then(Value::as_object).is_some_and(|m| m.keys().any(|k| k.trim().is_empty())) {
            // `Expectation.withMetadata`: a blank key is refused when the DTO is built
            let cause = "expectation metadata keys must not be blank";
            let text = json::pretty_multiline(item);
            parse_failure(&text, &format!("exception while parsing{{}}for Expectation {cause}"));
            errors.push(format!("exception while parsing [{text}] for Expectation because {cause}"));
        } else if let Some(cause) = item.get("httpRequest").and_then(crate::matcher::client_ip_failure) {
            // thrown by `buildObject`, after the DTO was read; 9.2.0 appends the root cause's message
            let text = json::pretty_multiline(item);
            parse_failure(&text, &format!("exception while parsing{{}}for Expectation {cause}"));
            errors.push(format!("exception while parsing [{text}] for Expectation because {cause}"));
        } else {
            items.push(item.clone());
        }
    }
    if errors.is_empty() {
        return Ok(items);
    }
    // `ExpectationSerializer.deserializeArray`: several reports joined by a blank line, indented, in brackets.
    Err(if errors.len() == 1 { errors.remove(0) } else { format!("{}\n]", format!("[\n{}", errors.join(",\n\n")).replace('\n', "\n  ")) })
}

/// `PUT /mockserver/expectation`: one expectation or an array, all validated before any is stored (§1.2).
fn create_expectations(state: &State, request: &HttpRequest) -> Reply {
    if request.body_str().bytes().all(|b| b.is_ascii_whitespace()) {
        return text(400, "1 error:\n - an expectation or expectation array is required but value was \"null\"");
    }
    let body = request.body_json_or_xml_str();
    let input: Value = match crate::json::parse_lenient(body.as_bytes()) {
        Ok(v) => v,
        // `splitJSONArrayToJSONNodes`: text of comments only reads as a `MissingNode`, one entry printed `null`
        Err(_) if crate::jnode::read_tree(&body).is_ok_and(|node| node.is_missing()) => Value::Null,
        // `ExpectationSerializer` answers Jackson's exception, under the image's relocated package.
        Err(e) => return text(
            400,
            crate::jnode::read_tree(&body).err().map_or_else(|| e.to_string(), |e| format!("shaded_package.{}: {}", e.class, e.message)),
        ),
    };
    let given = match input {
        Value::Array(items) => items,
        other => vec![other],
    };
    let realistic = state.config.bool_property("generateRealisticExampleValues", false);
    // `deserializeArray` announces each element of an array of more than 100 before reading it: at DEBUG with the
    // pretty-printed element, else at INFO without it.
    let processing = |index: usize, item: &Value| {
        if given.len() <= 100 {
            return;
        }
        let format = format!("processing JSON expectation {} of {}", index + 1, given.len());
        if crate::log::debug_enabled(state) {
            let entry = crate::recorded::LogEntry::at(crate::recorded::Level::Debug, format!("{format}:{{}}")).args([json::pretty(item)]);
            crate::log::entry(state, &entry);
            state.log.message(entry);
        } else {
            crate::log::info_event(state, crate::recorded::LogEntry::at(crate::recorded::Level::Info, format));
        }
    };
    let items = match deserialize_expectations(&given, realistic, processing, |text, format| {
        crate::log::error_event(state, crate::recorded::LogEntry::at(crate::recorded::Level::Error, format).args([text]));
    }) {
        Ok(items) => items,
        Err(message) => {
            log_exception(state, request, &message);
            return text(400, message);
        }
    };
    // each form of the expectations is let go once the next is built: a large array was held in every form at once
    drop(given);
    // `HttpState.add`.
    if let Some(error) = items.iter().filter_map(Value::as_object).find_map(crate::side_actions::validate_steps) {
        return text(400, format!("invalid expectation steps: {error}"));
    }
    if let Some(error) = items.iter().filter_map(Value::as_object).find_map(crate::side_actions::validate_respond_before_body) {
        return text(400, error);
    }
    let expectations: Vec<Expectation> = items
        .into_iter()
        .filter_map(|item| match item {
            Value::Object(o) => Some(o),
            _ => None,
        })
        .map(|o| compile_expectation_owned(state, o))
        .collect();
    if let Some(error) = expectations.iter().find_map(|e| e.matcher.load_error()) {
        return text(400, error);
    }
    if let Some(error) = expectations.iter().find_map(|e| e.matcher.body_argument_error()) {
        log_exception(state, request, error);
        return text(400, error);
    }
    let mut created: Vec<Value> = Vec::with_capacity(expectations.len());
    // `ExpectationLinter.adviseOnUpsert` of each upserted expectation (input, canonical form), as it is stored; an MCP
    // tool calls `httpState.add` directly, which the lint advice is not part of
    let mut advice = (!request.trusted).then(crate::lint::UpsertAdvice::default);
    let unwritable = expectations.iter().any(unwritable);
    // `HttpState.add` takes the expectations one at a time: it throws when the clustered backend's `put` fails (an
    // over-long expectation), after that one's local mutation, so the ones after it are never added or logged, and
    // the ones before it were already announced to the persistence listeners. `HttpRequestHandler` answers any other
    // exception with 400, the exception's message as the body (the marshalling failure has none) and no content type.
    let mut accepted = 0;
    // `RequestMatchers.add` asks for the primary action (`getAction()`, for the action metrics), which throws for
    // several action types without exactly one primary: an update asks the stored expectation first, before any
    // change; a new one is asked after its matcher joined this node's view but before it is logged or put in the
    // backend (it stays unbacked until the next backend change); an update in place is logged first. The array add
    // stops there.
    let bad_action = |accepted: usize, error: &str| {
        if accepted > 0 {
            crate::persistence::changed(state, None);
        }
        log_exception(state, request, error);
        text(400, error)
    };
    for e in expectations {
        let existing = state.store.get(&e.id);
        if let Some(error) = existing.as_ref().and_then(|old| primary_action_error(old)) {
            return bad_action(accepted, error);
        }
        // the body matcher is built as the expectation joins the matchers (`HttpRequestPropertiesMatcher.apply`), so
        // the ones before it stay added; its constructor's exception reaches `HttpRequestHandler`
        if let Some(error) = e.matcher.body_error() {
            if accepted > 0 {
                crate::persistence::changed(state, None);
            }
            return body_matcher_failure(state, request, &e, &error);
        }
        if let Some(error) = primary_action_error(&e) {
            if existing.is_some() {
                log_upsert(state, "updated", &e);
            }
            state.store.insert_unbacked(e);
            return bad_action(accepted, error);
        }
        // `httpRequestMatcher.update` returns false for an equal expectation: the stored one stays, unlogged, and is
        // what the answer shows (an update changing only `rateLimit`)
        if let Some(old) = existing.as_ref().filter(|old| old.upstream_equals(&e)) {
            created.push(old.canonical.clone());
            if let Some(advice) = &mut advice {
                advice.add(&old.input, &old.current());
            }
            accepted += 1;
            continue;
        }
        let verb = if existing.is_some() { "updated" } else { "creating" };
        log_upsert(state, verb, &e);
        created.push(e.canonical.clone());
        if let Some(advice) = &mut advice {
            advice.add(&e.input, &e.canonical);
        }
        if let Err(error) = state.store.try_upsert(vec![e]) {
            if accepted > 0 {
                crate::persistence::changed(state, None);
            }
            // the clustered backend's failure is no client error: a fault, answered 500 (`ControlPlaneFailureResponse`)
            return unexpected_failure(state, request, &crate::recorded::Failure::of("java.lang.RuntimeException", error.to_string(), Vec::new(), &[]));
        }
        accepted += 1;
    }
    crate::persistence::changed(state, None);
    // the answer's body is written first: an unwritable one fails before the lint advice
    if unwritable {
        return unwritable_failure(state, request);
    }
    let advice = advice.and_then(crate::lint::UpsertAdvice::finish);
    if let Some((count, lines)) = &advice {
        crate::log::warn_event(state, crate::recorded::LogEntry::at(crate::recorded::Level::Warn, crate::lint::upsert_warning_format(*count)).args([lines.as_str()]));
    }
    let mut reply = Reply::api_body(201, "application/json", json::pretty_expectations_owned(Value::Array(created)));
    if let Some((count, _)) = advice {
        reply.headers.insert(0, (crate::lint::LINT_WARNINGS_HEADER.into(), count.to_string()));
    }
    reply
}

/// An expectation [`canonical::unwritable_json_body`] reports: `ExpectationSerializer` cannot write it.
fn unwritable(e: &Expectation) -> bool {
    e.input.as_object().is_some_and(canonical::unwritable_json_body)
}

/// `ExpectationSerializer.failure`: the RuntimeException a JSON rendering of an [`unwritable`] expectation throws,
/// a fault answered 500 (`ControlPlaneFailureResponse`). Its cause, Jackson's parse error, is not reproduced.
fn unwritable_failure(state: &State, request: &HttpRequest) -> Reply {
    let message = "Exception while serializing expectation to JSON";
    unexpected_failure(state, request, &crate::recorded::Failure::of("java.lang.RuntimeException", message, Vec::new(), &[]))
}

/// `RequestDefinitionSerializer.failure`: a recorded request whose JSON body Jackson cannot read is logged at ERROR
/// with `SerializationFailure.describe`, and the RuntimeException it throws is a fault answered 500. Its cause,
/// Jackson's parse error, is not reproduced.
fn unwritable_requests(state: &State, request: &HttpRequest, count: usize, index: usize) -> Reply {
    let description = crate::recorded::serialization_failure_description(count, index);
    serialization_failure_logged(state, "RequestDefinition", &description);
    let message = format!("Exception while serializing RequestDefinition to JSON ({description})");
    unexpected_failure(state, request, &crate::recorded::Failure::of("java.lang.RuntimeException", message, Vec::new(), &[]))
}

/// `HttpRequestAndHttpResponseSerializer.serialize` failing on a request's JSON body inside `HttpState.retrieve`,
/// which logs `exception handling request` and rethrows it as a client error: 400 with the message.
fn unwritable_request_responses(state: &State, request: &HttpRequest, count: usize, index: usize) -> Reply {
    let description = crate::recorded::serialization_failure_description(count, index);
    serialization_failure_logged(state, "HttpRequestAndHttpResponse", &description);
    let message = format!("Exception while serializing HttpRequestAndHttpResponse to JSON ({description})");
    retrieve_client_error(state, request, &message)
}

/// `LogEntrySerializer.failure`: the entries of a `LOG_ENTRIES` retrieval, when Jackson cannot write one of them
/// (see [`crate::recorded::unwritable_log_entry`]): the failure logged at ERROR with the entry's identity, and the
/// RuntimeException it throws is a fault answered 500. Its cause, Jackson's error, is not reproduced.
fn unwritable_log_entries(state: &State, request: &HttpRequest, entries: &[Value]) -> Option<Reply> {
    let index = entries.iter().position(crate::recorded::unwritable_log_entry)?;
    let description = crate::recorded::log_entry_failure_description(entries.len(), index, &entries[index]);
    serialization_failure_logged(state, "LogEntry", &description);
    let message = format!("Exception while serializing LogEntry to JSON ({description})");
    Some(unexpected_failure(state, request, &crate::recorded::Failure::of("java.lang.RuntimeException", message, Vec::new(), &[])))
}

/// An `IllegalArgumentException` thrown inside `HttpState.retrieve`: logged as `exception handling request` and
/// rethrown as a client error, 400 with the message.
fn retrieve_client_error(state: &State, request: &HttpRequest, message: &str) -> Reply {
    if crate::log::error_enabled(state) {
        let entry = crate::recorded::LogEntry::at(crate::recorded::Level::Error, "exception handling request:{}error:{}")
            .correlation(correlation_of(request))
            .args([crate::recorded::Arg::from(crate::recorded::logged(request)), message.into()]);
        crate::log::entry_as(state, crate::recorded::Level::Error, &entry);
        state.log.message(entry);
    }
    client_error(state, request, message)
}

/// The serializers' `exception while serializing <what> to JSON:{}` ERROR entry.
fn serialization_failure_logged(state: &State, what: &str, description: &str) {
    if crate::log::error_enabled(state) {
        let entry = crate::recorded::LogEntry::at(crate::recorded::Level::Error, format!("exception while serializing {what} to JSON:{{}}")).args([crate::recorded::Arg::from(description)]);
        crate::log::entry_as(state, crate::recorded::Level::Error, &entry);
        state.log.message(entry);
    }
}

/// The exception networknt throws building a `JSON_SCHEMA` body's schema, a `SchemaException`.
fn schema_unbuilt_failure(error: &str) -> crate::recorded::Failure {
    crate::recorded::Failure::of("com.networknt.schema.SchemaException", error, Vec::new(), &[])
}

/// An expectation whose body matcher cannot be built: its constructor's exception is no client error, so
/// `HttpRequestHandler` answers 500 (`ControlPlaneFailureResponse`). An unbuildable XML schema first logs
/// `XmlSchemaValidator`'s `exception parsing schema{}` with the SAXParseException; the unexpected-failure entry
/// carries the constructor's RuntimeException caused by it. A `JSON_SCHEMA` schema networknt cannot build throws a
/// `SchemaException` on its own; an unreadable file body a `FileBodyException` (its cause is not
/// reproduced).
fn body_matcher_failure(state: &State, request: &HttpRequest, e: &Expectation, error: &str) -> Reply {
    if e.matcher.body_schema_unbuilt() {
        return unexpected_failure(state, request, &schema_unbuilt_failure(error));
    }
    let Some(schema_entry) = e.matcher.body_error_entry() else {
        return unexpected_failure(state, request, &crate::recorded::Failure::of("org.mockserver.file.FileBodyException", error, Vec::new(), &[]));
    };
    let cause = schema_entry.throwable_bean.clone().unwrap_or(Value::Null);
    let cause_text = schema_entry.throwable.as_ref().map(|lines| lines.join("\n")).unwrap_or_default();
    state.log.message(schema_entry);
    let wrapped = json!({"cause": cause, "localizedMessage": error, "message": error, "stackTrace": []});
    let trace = format!("java.lang.RuntimeException: {error}\nCaused by: {cause_text}");
    text(500, log_unexpected_throwable(state, request, wrapped, &trace))
}

/// `HttpState.add`: generated expectations (input form) upserted and logged like created ones; their canonical form.
pub fn add_generated(state: &State, items: &[Value]) -> Vec<Value> {
    let expectations: Vec<Expectation> = items.iter().filter_map(Value::as_object).map(|o| compile_expectation(state, o)).collect();
    let created: Vec<Value> = expectations.iter().map(|e| e.canonical.clone()).collect();
    // `RequestMatchers.add`: `updated expectation` only for one whose definition changed
    for e in &expectations {
        match state.store.get(&e.id) {
            None => log_upsert(state, "creating", e),
            Some(existing) if existing.canonical != e.canonical => log_upsert(state, "updated", e),
            Some(_) => {}
        }
    }
    state.store.upsert(expectations);
    crate::persistence::changed(state, None);
    created
}

/// `GET /mockserver/cluster` (`HttpState.handleClusterGet`): `StateBackend.clusterInfo()` as JSON. `clusterName` is
/// absent outside a clustered backend; `coordinator` is the coordinator's member id, not a flag.
fn cluster(state: &State) -> Reply {
    let info = state.state_backend.cluster_info();
    let mut out = serde_json::Map::new();
    out.insert("clustered".into(), info.clustered.into());
    out.insert("nodeId".into(), info.node_id.into());
    out.insert("coordinator".into(), info.coordinator.into());
    if let Some(name) = info.cluster_name {
        out.insert("clusterName".into(), name.into());
    }
    out.insert("memberCount".into(), info.members.len().into());
    let members: Vec<Value> = info
        .members
        .iter()
        .map(|m| {
            let mut member = serde_json::Map::new();
            member.insert("id".into(), m.id.clone().into());
            member.insert("coordinator".into(), m.coordinator.into());
            member.insert("local".into(), m.local.into());
            Value::Object(member)
        })
        .collect();
    out.insert("members".into(), Value::Array(members));
    Reply::api_body(200, "application/json", json::pretty(&Value::Object(out)))
}

/// `exception handling request for <what>:{}error:{}`, the ERROR entry of the event log (`LogEntry` with the request
/// and the message as its arguments) that HttpState writes when a generator endpoint (wsdl, graphql, scim, oidc,
/// saml) fails, with the exception as its throwable (`setThrowable`), before answering 400 with the message.
/// Since `writeEndpointFailure` (upstream master), only a client error is answered so; a fault is answered 500 and
/// logged once as an unexpected failure, without the provider entry.
fn generator_error(state: &State, request: &HttpRequest, what: &str, failure: crate::recorded::Failure) -> Reply {
    if !failure.classes.first().is_some_and(|class| is_client_error(class)) {
        return unexpected_failure(state, request, &failure);
    }
    if crate::log::error_enabled(state) {
        let format = format!("exception handling request for {what}:{{}}error:{{}}");
        let entry = crate::recorded::LogEntry::at(crate::recorded::Level::Error, format)
            .args([crate::recorded::Arg::from(crate::recorded::logged(request)), failure.message.as_str().into()])
            .throwable_bean(failure.bean.clone());
        crate::log::error_with_throwable(state, &entry, None, &crate::log::throwable_text(&failure.classes, &failure.bean));
        state.log.message(entry);
    }
    text(400, failure.message)
}

/// `PUT /mockserver/scim`.
fn scim(state: &State, request: &HttpRequest) -> Reply {
    match crate::scim::generate(state, &request.body_json_or_xml_str()) {
        Ok(items) => Reply::api_body(201, "application/json", json::pretty_expectations(&Value::Array(add_generated(state, &items)))),
        Err(failure) => generator_error(state, request, "scim provider", failure),
    }
}

/// `PUT /mockserver/wsdl`.
fn wsdl(state: &State, request: &HttpRequest) -> Reply {
    match crate::wsdl::generate(&request.body_json_or_xml_str()) {
        Ok(items) => Reply::api_body(201, "application/json", json::pretty_expectations(&Value::Array(add_generated(state, &items)))),
        Err(failure) => generator_error(state, request, "wsdl expectation", failure),
    }
}

/// `PUT /mockserver/graphql`: the raw body (SDL or an introspection result) and an optional `path` query parameter.
fn graphql(state: &State, request: &HttpRequest) -> Reply {
    match crate::graphql_schema::generate(&request.body_str(), query_param(request, "path")) {
        Ok(items) => Reply::api_body(201, "application/json", json::pretty_expectations(&Value::Array(add_generated(state, &items)))),
        Err(failure) => generator_error(state, request, "graphql expectation", failure),
    }
}

/// `PUT /mockserver/oidc`.
fn oidc(state: &State, request: &HttpRequest) -> Reply {
    match crate::oidc::generate(state, &request.body_json_or_xml_str()) {
        Ok(items) => Reply::api_body(201, "application/json", json::pretty_expectations(&Value::Array(add_generated(state, &items)))),
        Err(failure) => generator_error(state, request, "oidc provider", failure),
    }
}

/// `PUT /mockserver/saml`.
fn saml(state: &State, request: &HttpRequest) -> Reply {
    match crate::saml::generate(state, &request.body_json_or_xml_str()) {
        Ok(items) => Reply::api_body(201, "application/json", json::pretty_expectations(&Value::Array(add_generated(state, &items)))),
        Err(failure) => generator_error(state, request, "saml provider", failure),
    }
}

/// `creating expectation` / `updated expectation`, a log line about the expectation's request matcher.
/// An OpenAPI or a conditional definition is no `HttpRequest`: the entry's `httpRequest` is written `null`
/// (`LogEntry.updateBody` returns `null` for any definition but an `HttpRequest`, DNS or binary one).
pub(crate) fn log_upsert(state: &State, verb: &str, e: &Expectation) {
    use crate::recorded::{Arg, Kind, LogEntry};
    let shown = canonical::logged_expectation_ending(&e.canonical, e.end_date_millis());
    let kind = if verb == "creating" { Kind::CreatedExpectation } else { Kind::UpdatedExpectation };
    let subject = e.request_definition();
    // (A binary one is written as it prints since upstream #102: `LogEntry.updateBody` passes it through.)
    let attached = if subject.get("specUrlOrPayload").is_some() || canonical::is_conditional_request(&subject) {
        Value::Null
    } else {
        logged_request_definition(&subject)
    };
    log_openapi_matcher_created(state, e, &subject);
    // `LOG.logEvent` is gated on INFO: below it the line is neither printed nor recorded.
    if !state.info_enabled() {
        return;
    }
    let format = format!("{verb} expectation:{{}}with id:{{}}");
    let entry = LogEntry::new(kind, format).request_json(attached).args([Arg::from(shown), (&e.id).into()]);
    crate::log::entry(state, &entry);
    state.log.message_about(entry, Subject::Definition(subject));
}

/// `HttpRequestsPropertiesMatcher.apply`'s TRACE `created request matcher{}for open api definition{}`, logged as an
/// OpenAPI expectation's matcher is built, before its `creating expectation`; both arguments print the definition
/// (the matcher's `toString`). An update builds it again only when the stored matcher is an OpenAPI one whose
/// definition differs: a matcher keeps its class, so an HTTP expectation updated into an OpenAPI one logs nothing.
/// Called before the store holds `e`. A filter's matcher writes the same entry ([`OpenApiScan`]).
fn log_openapi_matcher_created(state: &State, e: &Expectation, definition: &Value) {
    if definition.get("specUrlOrPayload").is_none() || !crate::dataplane::trace_enabled(state) {
        return;
    }
    if let Some(old) = state.store.get(&e.id) {
        match old.canonical.get("httpRequest") {
            Some(previous) if previous.get("specUrlOrPayload").is_some() && previous != definition => {}
            _ => return,
        }
    }
    log_openapi_matcher_trace(state, definition);
}

/// The TRACE `created request matcher{}for open api definition{}` entry itself.
fn log_openapi_matcher_trace(state: &State, definition: &Value) {
    use crate::recorded::{Arg, Level, LogEntry};
    let entry = LogEntry::at(Level::Trace, "created request matcher{}for open api definition{}")
        .request_json(Value::Null)
        .args([Arg::from(definition), Arg::from(definition)]);
    crate::log::entry(state, &entry);
    state.log.message_about(entry, Subject::Definition(definition.clone()));
}

/// `PUT /mockserver/openapi`: one OpenAPI expectation or an array; each spec's operations become expectations
/// (`openapi_expectations`), stale ones of the same spec are removed, and the new ones are upserted.
fn openapi_expectations(state: &State, request: &HttpRequest) -> Reply {
    // The handler's `catch (IllegalArgumentException iae)`: an ERROR entry with the request and the exception's
    // message (its throwable the exception), then 400 with the message, prefixed when it lacks the load-error text.
    let load_error = |message: String| {
        // An MCP tool calls `addOpenAPI` itself, not this handler, so it logs no such entry.
        if crate::log::error_enabled(state) && !request.trusted {
            let entry = crate::recorded::LogEntry::at(crate::recorded::Level::Error, "exception handling request for open api expectation:{}error:{}")
                .args([crate::recorded::Arg::from(crate::recorded::logged(request)), message.as_str().into()])
                .throwable_bean(json!({"localizedMessage": message, "message": message, "stackTrace": []}));
            let trace = crate::log::throwable_text(&[crate::recorded::ILLEGAL_ARGUMENT], &json!({"message": message}));
            crate::log::error_with_throwable(state, &entry, None, &trace);
            state.log.message(entry);
        }
        let prefix = crate::openapi::OPEN_API_LOAD_ERROR;
        text(400, if message.starts_with(prefix) { message } else { format!("{prefix}{}{message}", if message.trim().is_empty() { "" } else { ", " }) })
    };
    let mut body = request.body_json_or_xml_str();
    // `YamlToJsonConverter.convertYamlToJson` under a YAML content type (`HttpState`, `PUT /openapi` only).
    let yaml = request.first_header("content-type").is_some_and(|ct| {
        let base = ct.split(';').next().unwrap_or("").trim().to_lowercase();
        matches!(base.as_str(), "application/yaml" | "application/x-yaml" | "text/yaml")
    });
    if yaml && !body.is_empty() {
        match jackson::yaml::read_tree(&body, jackson::yaml::YamlReadFeatures::swagger_core()) {
            Ok(node) => body = jackson::convert::node_to_json_string(&node, false, false).into(),
            Err(e) => return load_error(format!("failed to convert YAML to JSON: {}", e.message)),
        }
    }
    // `OpenAPIExpectationSerializer.deserializeArray`: a blank body (an empty one reads as Java `null`).
    if body.trim().is_empty() {
        let shown = if request.body.is_empty() { "null" } else { &body };
        return load_error(format!("1 error:\n - an expectation or expectation array is required but value was \"{shown}\""));
    }
    let input: Value = match crate::json::parse_lenient(body.as_bytes()) {
        Ok(v) => v,
        // `splitJSONArray` wraps Jackson's exception: `IllegalArgumentException(e)` carries `e.toString()`.
        Err(e) => return load_error(crate::jnode::read_tree(&body).err().map_or_else(|| e.to_string(), |e| format!("shaded_package.{}: {}", e.class, e.message))),
    };
    let items = match input {
        Value::Array(items) => items,
        other => vec![other],
    };
    // `deserializeArray(body, false)`: an empty array is rejected, and every item is validated before any is added,
    // its errors listed together.
    if items.is_empty() {
        return load_error("1 error:\n - an expectation or array of expectations is required".into());
    }
    let errors: Vec<String> = items
        .iter()
        .filter_map(|item| schema::validate_openapi_expectation(item).err().map(|report| schema::incorrect_openapi_expectation(item, &report)))
        .collect();
    match errors.as_slice() {
        [] => {}
        [one] => return load_error(one.clone()),
        many => return load_error(format!("[\n{}", many.join(",\n\n")).replace('\n', "\n  ") + "\n]"),
    }
    let mut upserted = Vec::new();
    // `addOpenAPI` (9.1.0): each spec's advisory load problems, numbered by the spec's place in the body.
    let mut load_problems = Vec::new();
    for (spec_index, item) in items.iter().enumerate() {
        let definition = item.as_object().expect("validated as an object");
        // A spec URL may have changed since it was parsed: re-importing it parses it again (`OpenAPIParser.clearCache`).
        if let Some(spec) = definition.get("specUrlOrPayload").and_then(Value::as_str).filter(|s| crate::openapi::is_spec_url(s)) {
            state.openapi_parses.clear(spec);
        }
        let built = crate::openapi::logging_load_problems(state, || {
            crate::openapi_expectations::build_with_problems(definition, state.config.bool_property("generateRealisticExampleValues", false))
        });
        let (built, problems) = match built {
            Ok(built) => built,
            Err(message) => return load_error(message),
        };
        for problem in problems {
            let mut node = serde_json::Map::new();
            node.insert("specIndex".into(), Value::from(spec_index));
            problem.write_to(&mut node);
            load_problems.push(Value::Object(node));
        }
        let ids: std::collections::HashSet<String> = built.iter().filter_map(|e| e.get("id").and_then(Value::as_str).map(str::to_string)).collect();
        let namespaces: std::collections::HashSet<String> =
            ids.iter().filter_map(|id| crate::openapi_expectations::namespace(id).map(str::to_string)).collect();
        if !namespaces.is_empty() {
            state.store.remove_where(|e| !ids.contains(&e.id) && namespaces.iter().any(|n| e.id.starts_with(n.as_str())));
        }
        let expectations: Vec<Expectation> = built.iter().map(|o| compile_expectation(state, o)).collect();
        // `RequestMatchers.add`: `updated expectation` only for one whose definition changed, as in [`add_generated`].
        for e in &expectations {
            match state.store.get(&e.id) {
                None => log_upsert(state, "creating", e),
                Some(existing) if existing.canonical != e.canonical => log_upsert(state, "updated", e),
                Some(_) => {}
            }
        }
        upserted.extend(expectations.iter().map(|e| e.canonical.clone()));
        state.store.upsert(expectations);
    }
    crate::persistence::changed(state, None);
    // `ExpectationSerializer.serialize` writes an empty list as `[]`, not the pretty printer's `[ ]`.
    let expectations = if upserted.is_empty() { "[]".to_string() } else { json::pretty_expectations(&Value::Array(upserted.clone())) };
    // The default body stays the bare list of expectations every client parses; `?includeLoadProblems=true` wraps it
    // with the problems, through Jackson's default pretty printer.
    let body = if query_param(request, "includeLoadProblems").is_some_and(|v| v.eq_ignore_ascii_case("true")) {
        let mut body = serde_json::Map::new();
        body.insert("expectations".into(), Value::Array(upserted));
        body.insert("loadProblems".into(), Value::Array(load_problems.clone()));
        json::pretty_expectations(&Value::Object(body))
    } else {
        expectations
    };
    let mut reply = Reply::api_body(201, "application/json", body);
    if !load_problems.is_empty() {
        reply.headers.insert(0, ("x-mockserver-openapi-load-problems".into(), load_problems.len().to_string()));
    }
    reply
}

pub fn compile_expectation(state: &State, input: &serde_json::Map<String, Value>) -> Expectation {
    compile_expectation_owned(state, input.clone())
}

/// [`compile_expectation`] of an input no longer needed, which the expectation keeps rather than a copy of it.
pub fn compile_expectation_owned(state: &State, input: serde_json::Map<String, Value>) -> Expectation {
    let id = input.get("id").and_then(Value::as_str).map(str::to_string).unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let canonical = canonical::expectation(&input, &id);
    let default_values = canonical::expectation_with_default_values(&input, &id);
    // SECURITY: every compile from untrusted input carries the server's remote-`$ref` policy.
    let matcher = matcher::string::with_remote_refs_policy(state.json_schema_allow_remote_refs(), || {
        matcher::with_exact_case(state.config.match_exact_case(), || {
            // `XPathEvaluator` takes its `xpathMatchingTimeoutMillis` from the server's configuration.
            let xpath_millis = state.config.startup_property("xpathMatchingTimeoutMillis").and_then(|v| v.trim().parse().ok()).unwrap_or(5000);
            matcher::with_xpath_timeout(xpath_millis, || {
                crate::openapi::with_context_path_prefix(&state.config.property("openAPIContextPathPrefix").unwrap_or_default(), || {
                    crate::openapi::logging_load_problems(state, || input.get("httpRequest").map(RequestMatcher::compile).unwrap_or_else(RequestMatcher::any))
                })
            })
        })
    });
    let priority = input.get("priority").and_then(Value::as_i64).unwrap_or(0);
    let action = match crate::side_actions::primary(&input) {
        // `getPrimaryAction` throws: the data plane answers a request that matches it as a fault before reaching the
        // action (`dataplane::handle`), so this stand-in is never served.
        Err(_) => Action::Error { delay: None, drop_connection: false, reset_connection: false, response_bytes: None, stream_error: None },
        Ok(_) => crate::openapi_examples::with_static_realistic(state.config.bool_property("generateRealisticExampleValues", false), || {
            Action::compile(&crate::side_actions::primary_input(&input))
        }),
    };
    Expectation::new(id, priority, canonical, default_values, Value::Object(input), matcher, action)
}

/// A verification's answer; a rejected one is `HttpState.handle`'s `IllegalArgumentException`, logged with the request.
fn verification_reply(state: &State, request: &HttpRequest, outcome: crate::verify::Outcome) -> Reply {
    if let crate::verify::Outcome::BadRequest(message) = &outcome {
        log_exception(state, request, message);
    }
    outcome.into_reply()
}

/// `getAction()` on an expectation: why it throws (several action types without exactly one primary), if it does.
pub(crate) fn primary_action_error(e: &Expectation) -> Option<&'static str> {
    crate::side_actions::primary(e.input.as_object()?).err()
}

/// `removeHttpRequestMatcher` over `candidates` (match order), as `RequestMatchers.reset` and `clear` walk them: each
/// is removed and logged, then asked for its primary action (`getAction()`), which throws for several action types
/// without exactly one primary and ends the walk. Removing a backed expectation fires the backend's invalidation
/// listener (`trimEvictedFromBackend`), which drops every unbacked one (`Store::insert_unbacked`) silently, so a
/// later unbacked candidate is already gone when its turn comes: that is why a reset trips only on the first
/// expectation in match order. Returns the ids the walk removes, in order, and the error that ended it.
fn removal_walk(state: &State, candidates: &[std::sync::Arc<Expectation>]) -> (Vec<String>, Option<&'static str>) {
    let mut removed = Vec::new();
    let mut backed_removed = false;
    for e in candidates {
        let unbacked = state.store.is_unbacked(&e.id);
        if unbacked && backed_removed {
            continue;
        }
        removed.push(e.id.clone());
        if let Some(error) = primary_action_error(e) {
            return (removed, Some(error));
        }
        backed_removed |= !unbacked;
    }
    (removed, None)
}

/// `RequestMatchers.reset` when [`removal_walk`] throws: the expectations up to the throwing one are removed (each
/// logged with a correlation id of its own, no listener notified) and the reset stops there; the others stay, and
/// the event log and the other registries are not reset. `None` when the reset can go ahead.
fn reset_aborted(state: &State) -> Option<&'static str> {
    let (ids, error) = removal_walk(state, &state.store.all());
    let error = error?;
    let removed = state.store.take_where(|e| ids.contains(&e.id));
    for e in &removed {
        log_removals(state, std::slice::from_ref(e), &uuid::Uuid::new_v4().to_string());
    }
    Some(error)
}

/// `HttpState.clear` catching a removal's `IllegalArgumentException`: logged with the clear's correlation id, then
/// rethrown as an invalid `type` parameter (whatever the parameter was), which `HttpRequestHandler` answers with 400
/// and logs with the request.
fn clear_failed(state: &State, request: &HttpRequest, correlation: &str, error: &str) -> Reply {
    if state.info_enabled() && !request.trusted {
        let entry = crate::recorded::LogEntry::at(crate::recorded::Level::Error, "exception handling request:{}error:{}")
            .correlation(correlation)
            .args([crate::recorded::Arg::from(crate::recorded::logged(request)), error.into()]);
        crate::log::entry_as(state, crate::recorded::Level::Error, &entry);
        state.log.message(entry);
    }
    let kind = query_param(request, "type").unwrap_or("");
    let message = format!("\"{kind}\" is not a valid value for \"type\" parameter, only the following values are supported [log, expectations, all]");
    log_exception(state, request, &message);
    text(400, message)
}

/// [`removal_walk`] for a clear: removes and logs what it reaches; the error, if it threw.
fn clear_walk(state: &State, candidates: &[std::sync::Arc<Expectation>], correlation: &str) -> Option<&'static str> {
    let (ids, error) = removal_walk(state, candidates);
    let removed = state.store.take_where(|e| ids.contains(&e.id));
    log_removals(state, &removed, correlation);
    error
}

/// `requestMatchers.retrieveActiveExpectations(null)` as an MCP tool calls it: no `retrieved …` log line.
pub(crate) fn active_expectations_quiet(state: &State) -> Vec<Value> {
    retrievable_logged(state).iter().map(|e| e.current()).collect()
}

fn log_exception(state: &State, request: &HttpRequest, message: &str) {
    // An MCP tool calls `httpState`/the serializers itself, not `HttpStateHandler`, so no request is processed to fail.
    if state.info_enabled() && !request.trusted {
        let entry = crate::recorded::LogEntry::at(crate::recorded::Level::Error, "exception processing request:{}error:{}")
            .args([crate::recorded::Arg::from(crate::recorded::logged(request)), message.into()]);
        crate::log::entry_as(state, crate::recorded::Level::Error, &entry);
        state.log.message_about(entry, Subject::Request(std::sync::Arc::new(request.clone())));
    }
}

/// `handleProxyPass` reaching a mapping whose `targetUri` `URI.create` refuses: the exception (an
/// `IllegalArgumentException` over the `URISyntaxException`) escapes `processAction`, so it is a [`data_plane_failure`].
pub(crate) fn proxy_pass_refused(state: &State, request: &HttpRequest, target: &str, uri_message: &str) -> Reply {
    let (reason, index) = match uri_message.split_once(" at index ") {
        Some((reason, rest)) => (reason, rest.split(':').next().and_then(|n| n.parse::<i64>().ok()).unwrap_or(-1)),
        None => (uri_message, -1),
    };
    let syntax = json!({"index": index, "input": target, "localizedMessage": uri_message, "message": uri_message, "reason": reason, "stackTrace": []});
    let bean = json!({"cause": syntax, "localizedMessage": uri_message, "message": uri_message, "stackTrace": []});
    let failure = crate::recorded::Failure { message: uri_message.to_string(), bean, classes: MAPPING_FAILURE_CLASSES[1..].to_vec() };
    data_plane_failure(state, request, &failure)
}

/// A control-plane filter: nothing, a request matcher, or `{"id": …}` naming an expectation.
enum Filter {
    None,
    Matcher(Value),
    /// The id, and the request matcher it resolved to.
    Expectation(String, Value),
}

impl Filter {
    fn matcher_json(&self) -> Option<&Value> {
        match self {
            Filter::None => None,
            Filter::Matcher(v) | Filter::Expectation(_, v) => Some(v),
        }
    }

    /// `RequestMatchers.isUnfiltered`: no filter, or the empty HTTP filter `{}` (an empty retrieve body and the
    /// dashboard's "show all"), selects everything without reverse matching, which a `not(...)`, conditional, DNS or
    /// binary definition would fail.
    fn unfiltered(&self) -> bool {
        match self {
            Filter::None => true,
            Filter::Matcher(v) => is_empty_filter(v),
            Filter::Expectation(..) => false,
        }
    }
}

/// A log line's definition an unfiltered log read shows: every one, a `not(...)`, conditional, DNS or binary one too,
/// which reverse matching the empty filter would refuse (`MockServerEventLog.filterMatcher`, upstream #89).
pub(crate) fn unfiltered_admits_definition(_definition: &Value) -> bool {
    true
}

/// `new HttpRequest().equals(filter)`: a request definition that sets nothing.
pub(crate) fn is_empty_filter(v: &Value) -> bool {
    v.as_object().is_some_and(|o| o.is_empty())
}

/// `{"id": "…"}` and nothing else (`ExpectationIdSerializer`).
fn expectation_id(v: &Value) -> Option<String> {
    let o = v.as_object()?;
    (o.len() == 1).then(|| o.get("id")?.as_str().map(str::to_string)).flatten()
}

/// An OpenAPI definition a filter met, with the index of the OpenAPI filter's operation matcher that met it.
type OpenApiMet = (Option<usize>, Value);

thread_local! {
    /// The OpenAPI definitions a filter met during the running [`OpenApiScan`] (`None` outside one), with the index
    /// of an OpenAPI filter's operation matcher that met it.
    static OPENAPI_MET: std::cell::RefCell<Option<Vec<OpenApiMet>>> = const { std::cell::RefCell::new(None) };
}

/// A control-plane filter's matcher at work: `MatcherBuilder.transformsToMatcher(filter)` takes it from
/// the log's or the expectations' cache (`FilterMatchers`), and each OpenAPI definition it meets in
/// [`definition_matches`] is turned into a matcher by the filter matcher's own `MatcherBuilder`. Building an OpenAPI
/// matcher, the filter's or a met definition's, logs TRACE `created request matcher{}for open api definition{}`
/// (`HttpRequestsPropertiesMatcher.apply`); a cached one logs nothing. [`OpenApiScan::flush`] writes the entries
/// (before the operation's own entry, as the oracle does); dropping the scan flushes what is left.
struct OpenApiScan<'a> {
    state: &'a State,
    cache: &'a parking_lot::Mutex<crate::recorded::FilterMatchers>,
    filter: Value,
    looked_up: std::cell::Cell<bool>,
}

impl<'a> OpenApiScan<'a> {
    /// `expectations`: the filter is `RequestMatchers`' (active expectations, clearing expectations), else the
    /// event log's. `filter` is the request definition (`{}`, upstream's `request()`, when there is none).
    fn begin(state: &'a State, expectations: bool, filter: Value) -> OpenApiScan<'a> {
        OPENAPI_MET.with(|m| *m.borrow_mut() = Some(Vec::new()));
        let caches = &state.log.filter_matchers;
        let cache = if expectations { &caches.expectations } else { &caches.event_log };
        // (keyed, and printed, as the definition upstream deserialises: `RequestDefinition.equals`)
        OpenApiScan { state, cache, filter: canonical::request_definition(&filter), looked_up: std::cell::Cell::new(false) }
    }

    fn flush(&self) {
        let met = OPENAPI_MET.with(|m| m.borrow_mut().as_mut().map(std::mem::take).unwrap_or_default());
        if self.looked_up.replace(true) && met.is_empty() {
            return;
        }
        let (created, built) = self.cache.lock().meet(&self.filter, met);
        if !crate::dataplane::trace_enabled(self.state) {
            return;
        }
        if created && self.filter.get("specUrlOrPayload").is_some() {
            log_openapi_matcher_trace(self.state, &self.filter);
        }
        for definition in &built {
            log_openapi_matcher_trace(self.state, definition);
        }
    }
}

impl Drop for OpenApiScan<'_> {
    fn drop(&mut self) {
        self.flush();
        OPENAPI_MET.with(|m| *m.borrow_mut() = None);
    }
}

/// Inside an [`OpenApiScan`], `filter` meets the OpenAPI definition `definition`, whose operations are `requests`:
/// an HTTP filter's matcher builds one matcher for it; an OpenAPI filter tries its operation matchers in order up to
/// the first that matches (`HttpRequestsPropertiesMatcher.matches`), each building its own.
fn met_openapi_definition(filter: &RequestMatcher, definition: &Value, requests: &[Value]) {
    OPENAPI_MET.with(|m| {
        let mut m = m.borrow_mut();
        let Some(met) = m.as_mut() else { return };
        match filter.alternatives() {
            Some(operations) => {
                for (i, operation) in operations.iter().enumerate() {
                    met.push((Some(i), definition.clone()));
                    if requests.iter().any(|r| operation.matches_definition(r)) {
                        break;
                    }
                }
            }
            None => met.push((None, definition.clone())),
        }
    });
}

/// `RequestDefinitionSerializer.deserialize`: a schema-valid definition (sent as `body`) whose DTO cannot be read,
/// logged; the message it throws.
fn unreadable_request_definition(state: &State, body: &str, definition: &Value) -> Option<String> {
    // `NottableStringDeserializer`: a date-time value it refuses, the reference chain starting at the
    // multimap value's array (`java.lang.Object[][i]`), since a bare request definition has no DTO above it.
    let date_time = |d: &Value| {
        crate::matcher::date_time_failure(d).map(|(cause, chain)| match chain.strip_prefix("->") {
            Some(chain) => format!("{cause} (through reference chain: {chain})"),
            None => cause,
        })
    };
    let cause = crate::matcher::body_deserialization_failure(definition).map(str::to_string).or_else(|| date_time(definition)).or_else(|| crate::matcher::client_ip_failure(definition))?;
    let format = format!("exception while parsing{{}}for RequestDefinition {cause}");
    crate::log::error_event(state, crate::recorded::LogEntry::at(crate::recorded::Level::Error, &format).args([body]));
    Some(format!("exception while parsing [{body}] for RequestDefinition"))
}

/// `HttpRequestHandler` answering an `IllegalArgumentException` from `HttpState`: logged, then 400. An MCP tool calls
/// `httpState` itself, so no request is processed to fail.
fn filter_failure(state: &State, request: &HttpRequest, message: &str) -> Reply {
    match request.trusted {
        true => text(400, message),
        false => client_error(state, request, message),
    }
}

/// The optional filter of retrieve/clear; `Err` is the message of the `IllegalArgumentException` upstream throws.
/// Unknown ids fail closed (`HttpState.retrieve`).
fn filter_or_message(state: &State, request: &HttpRequest) -> Result<Filter, String> {
    if request.body_json_or_xml_str().bytes().all(|b| b.is_ascii_whitespace()) {
        return Ok(Filter::None);
    }
    let mut body = request.body_json_or_xml_str().to_string();
    // `ExpectationIdSerializer` / `RequestDefinitionSerializer`: a body naming `"httpRequest"` (else
    // `"openAPIDefinition"`) is read as a tree and, when that is a top-level field, replaced by its value.
    if let Some(key) = ["httpRequest", "openAPIDefinition"].into_iter().find(|k| body.contains(&format!("\"{k}\""))) {
        match crate::jnode::read_tree(&body) {
            Ok(tree) => {
                if let Some(inner) = tree.get(key) {
                    body = inner.to_string();
                }
            }
            Err(e) => {
                for class in ["ExpectationId", "RequestDefinition"] {
                    let message = format!("exception while parsing{body}for {class} {}", e.message);
                    crate::log::error_event(state, crate::recorded::LogEntry::at(crate::recorded::Level::Error, &message));
                }
                return Err(format!("exception while parsing [{body}] for RequestDefinition"));
            }
        }
    }
    if let Err(e) = crate::jnode::read_tree(&body) {
        // `ExpectationIdSerializer` and then `RequestDefinitionSerializer` each run `JsonSchemaValidator.isValid`,
        // which logs what it throws and reports it as `<exception class> - <message>`.
        for _ in 0..2 {
            crate::log::error_event(state, crate::recorded::LogEntry::at(crate::recorded::Level::Error, "exception validating JSON"));
        }
        let class = e.class.rsplit('.').next().unwrap_or_default();
        return Err(schema::incorrect_request_matcher(&body, &format!("{class} - {}", e.message)));
    }
    let v: Value = crate::json::parse_lenient(body.as_bytes()).map_err(|e| e.to_string())?;
    if let Some(id) = expectation_id(&v) {
        // `RequestMatchers.retrieveRequestDefinitions` rejects a blank id before looking it up.
        if id.trim().is_empty() {
            return Err(format!("No expectation id specified found \"{id}\""));
        }
        return match state.store.definition(&id) {
            Some(definition) => Ok(Filter::Expectation(id, definition)),
            None => Err(format!("No expectation found with id {id}")),
        };
    }
    if let Err(report) = schema::validate_request_definition(&v) {
        return Err(schema::incorrect_request_matcher(&body, &report));
    }
    if let Some(error) = unreadable_request_definition(state, &body, &v) {
        return Err(error);
    }
    Ok(Filter::Matcher(v))
}

/// Does an expectation's own `httpRequest` satisfy a control-plane filter? The expectation's matcher is treated
/// as a request, and both sides' `not` flags apply (`HttpRequestPropertiesMatcher.applyNotOperators`).
pub(crate) fn expectation_matches_filter(expectation: &Expectation, filter: &RequestMatcher) -> bool {
    definition_matches(&expectation.request_definition(), filter, false)
}

/// [`expectation_matches_filter`] for a request matcher on its own (`LogEntry.matches` for a log line about one).
pub(crate) fn definition_matches_filter(http_request: &Value, filter: &RequestMatcher) -> bool {
    definition_matches(http_request, filter, true)
}

/// `logged`: the definition is a log line's (`LogEntry.matches`), not an expectation's.
fn definition_matches(http_request: &Value, filter: &RequestMatcher, logged: bool) -> bool {
    let definition_not = http_request.get("not").and_then(Value::as_bool).unwrap_or(false);
    // `ConditionalRequestMatcher`: each branch judges the definition itself, then both `not`s apply once more.
    if let Some(conditional) = filter.conditional() {
        return conditional.evaluate(|branch| definition_matches(http_request, branch, logged)) ^ definition_not ^ filter.is_not();
    }
    // Any other matcher refuses a conditional definition (`HttpRequestPropertiesMatcher.matches`).
    if canonical::is_conditional_request(http_request) {
        return false;
    }
    // A binary filter describes binary definitions only (`BinaryRequestPropertiesMatcher`: equal bytes, an empty
    // matcher matching all, both `not`s applying); an HTTP one never matches a binary definition.
    if let Some(expected) = filter.binary_data() {
        return canonical::is_binary_request(http_request) && {
            use base64::Engine;
            let decode = |v: &Value| v.get("binaryData").and_then(Value::as_str).and_then(|s| base64::engine::general_purpose::STANDARD.decode(s).ok()).unwrap_or_default();
            ((expected.is_empty() || expected == decode(http_request)) != definition_not) != filter.is_not()
        };
    }
    // (An expectation listing keeps a binary definition for an HTTP filter: the oracle lists it for `{}`.)
    if logged && canonical::is_binary_request(http_request) {
        return false;
    }
    // A DNS filter describes DNS definitions only; an HTTP one never matches a DNS definition.
    if let Some(dns) = filter.dns() {
        return canonical::is_dns_request(http_request) && dns.evaluate(http_request).0;
    }
    if canonical::is_dns_request(http_request) {
        return false;
    }
    let expectation_not = definition_not;
    // An OpenAPI expectation stands for its operations' request matchers (`HttpRequestPropertiesMatcher.matches`
    // given an `OpenAPIDefinition`): it satisfies the filter when one of them does.
    let requests: Vec<Value> = match http_request.as_object().filter(|o| o.contains_key("specUrlOrPayload")) {
        Some(definition) => {
            let requests = crate::openapi::request_matchers(definition).unwrap_or_default();
            met_openapi_definition(filter, http_request, &requests);
            requests
        }
        None => {
            // `HttpRequestsPropertiesMatcher.matches`: at TRACE an OpenAPI filter gives a plain HTTP definition a
            // context, so each operation tried logs its differences, about the definition.
            if let Some(operations) = filter.alternatives().filter(|_| crate::matcher::tracing()) {
                for operation in operations {
                    if operation.matches_definition(http_request) {
                        break;
                    }
                    crate::matcher::note_definition_differences(operation.definition_differences(http_request), http_request);
                }
            }
            vec![http_request.clone()]
        }
    };
    requests.iter().any(|r| filter.matches_definition(r) != expectation_not)
}

fn pseudo_request(v: &Value) -> HttpRequest {
    let raw = |k: &str| v.get(k).and_then(Value::as_str).unwrap_or_default();
    let s = |k: &str| raw(k).trim_start_matches('!').to_string();
    let map = |k: &str| -> crate::request::MultiMap {
        v.get(k)
            .and_then(Value::as_object)
            .map(|o| {
                o.iter()
                    .filter(|(k, _)| *k != "keyMatchStyle")
                    .map(|(k, vs)| (k.clone(), vs.as_array().into_iter().flatten().filter_map(|v| v.as_str().map(str::to_string)).collect()))
                    .collect()
            })
            .unwrap_or_default()
    };
    let body = match v.get("body") {
        Some(Value::String(s)) => s.clone().into(),
        // A `JsonBody` whose `json` is a scalar (the canonical form keeps it typed): its text, a string as written.
        Some(Value::Object(o)) if o.get("type").and_then(Value::as_str) == Some("JSON") && o.get("json").is_some_and(|j| !j.is_object() && !j.is_array()) => {
            match &o["json"] {
                Value::String(s) => s.clone().into(),
                other => other.to_string().into(),
            }
        }
        // A `BinaryBody` is its bytes.
        Some(Value::Object(o)) if o.get("type").and_then(Value::as_str) == Some("BINARY") => {
            use base64::Engine as _;
            let encoded = o.get("base64Bytes").and_then(Value::as_str).unwrap_or_default();
            base64::engine::general_purpose::STANDARD.decode(encoded).unwrap_or_default().into()
        }
        // A `JsonBody`'s text is its JSON as Jackson's pretty printer writes it (oracle: `user_schema_reports`).
        Some(other) if other.is_object() || other.is_array() => crate::json::pretty(other).into(),
        Some(other) if other.is_number() || other.is_boolean() => other.to_string().into(),
        _ => bytes::Bytes::new(),
    };
    HttpRequest {
        method: s("method"),
        path: s("path"),
        query: map("queryStringParameters"),
        headers: map("headers"),
        cookies: v
            .get("cookies")
            .and_then(Value::as_object)
            .map(|o| o.iter().filter_map(|(k, v)| v.as_str().map(|v| (k.clone(), v.to_string()))).collect())
            .unwrap_or_default(),
        body,
        keep_alive: v.get("keepAlive").and_then(Value::as_bool).unwrap_or(true),
        keep_alive_null: v.get("keepAlive").and_then(Value::as_bool).is_none(),
        secure: v.get("secure").and_then(Value::as_bool).unwrap_or(false),
        // No protocol is `null` upstream, which a protocol filter does not match.
        protocol: match raw("protocol") {
            "HTTP_1_1" => "HTTP_1_1",
            "HTTP_2" => "HTTP_2",
            "HTTP_3" => "HTTP_3",
            _ => "",
        },
        ..HttpRequest::default()
    }
}

/// `HttpState.enableRecordAndForward`: `upstream` (`host`, `host:port`, or an `http://`/`https://` URL) becomes the
/// live `proxyRemoteHost`/`proxyRemotePort`, with `attemptToProxyIfNoMatchingExpectation` on, so later unmatched
/// requests are forwarded there and recorded. The URL's `https` only shows in the log line: the forward is plain HTTP
/// as upstream's. `None` once armed, else the 400 (unparseable, no host) or 403 (SSRF policy) to answer with.
fn enable_record_and_forward(state: &State, upstream: &str, correlation_id: &str) -> Option<Reply> {
    let error = |status: u32, message: &str| Some(Reply::api_body(status, "application/json", json::compact(&json!({ "error": message }))));
    // `String.trim()`: every char up to U+0020
    let trimmed = upstream.trim_matches(|c: char| c <= ' ');
    let (host, port, https) = if trimmed.contains("://") {
        let uri = match crate::java_uri::parse(trimmed) {
            Ok(uri) => uri,
            Err(message) => return error(400, &format!("invalid forwardUnmatchedTo value: {message}")),
        };
        let https = uri.scheme.as_deref().is_some_and(|s| s.eq_ignore_ascii_case("https"));
        let port = if uri.port != -1 { i64::from(uri.port) } else if https { 443 } else { 80 };
        (uri.host.unwrap_or_default(), port, https)
    } else {
        // `hostPort[0]` of an all-colon value is `ArrayIndexOutOfBoundsException`
        let Some((host, port)) = java_split_host_port(trimmed) else {
            return error(400, "invalid forwardUnmatchedTo value: Index 0 out of bounds for length 0");
        };
        let port = match port.filter(|p| !p.trim().is_empty()) {
            // `Integer.parseInt`: an optional sign, then ASCII digits, within `int`
            Some(p) => match Some(p.strip_prefix(['+', '-']).unwrap_or(&p)).filter(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit())).and_then(|_| p.parse::<i32>().ok()) {
                Some(port) => i64::from(port),
                None => return error(400, &format!("invalid forwardUnmatchedTo value: For input string: \"{p}\"")),
            },
            None => 80,
        };
        (host, port, false)
    };
    if host.trim().is_empty() {
        return error(400, "forwardUnmatchedTo must include a host e.g. localhost:8080 or http://localhost:8080");
    }
    // `InetAddressValidator.validateForwardTarget`, before any state changes
    if let Some(reason) = crate::ws_relay::blocked_blocking(state, &host) {
        crate::log::warn_event(state, crate::recorded::LogEntry::at(crate::recorded::Level::Warn, "record-and-forward blocked by SSRF policy:{}").args([reason.as_str()]));
        return error(403, &format!("record-and-forward blocked by SSRF policy: {reason}"));
    }
    state.config.set_runtime("proxyRemoteHost", host.clone());
    state.config.set_runtime("proxyRemotePort", port.to_string());
    state.config.set_runtime("attemptToProxyIfNoMatchingExpectation", "true".to_string());
    let message = format!("enabled record-and-forward of unmatched requests to upstream {host}:{port}{}", if https { " (https)" } else { "" });
    crate::log::info_event(state, crate::recorded::LogEntry::new(crate::recorded::Kind::Info, message).correlation(correlation_id));
    None
}

/// `HttpRequest.splitHostPort`: a bracketed IPv6 host, else `String.split(":")` (trailing empty parts dropped); the
/// host and the second part; `None` when the split leaves no part (only colons).
fn java_split_host_port(host_port: &str) -> Option<(String, Option<String>)> {
    if host_port.starts_with('[') && let Some(end) = host_port.find(']') {
        let port = host_port[end..].find(':').map(|p| host_port[end + p + 1..].to_string());
        return Some((host_port[1..end].to_string(), port));
    }
    let mut parts: Vec<&str> = host_port.split(':').collect();
    if parts.len() > 1 {
        while parts.last().is_some_and(|p| p.is_empty()) {
            parts.pop();
        }
    }
    Some((parts.first()?.to_string(), parts.get(1).map(|p| p.to_string())))
}

/// `PUT /mockserver/retrieve?type=…&format=…` (§1.4).
fn mode(state: &State, request: &HttpRequest) -> Reply {
    let body = |mode: &str| Reply::api_body(200, "application/json", format!("{{\"mode\":\"{mode}\",\"proxyUnmatchedRequests\":{}}}", mode != "SIMULATE"));
    if request.method == "GET" {
        // the mode last set while it still agrees with the flag, which a `PUT /mockserver/configuration` also moves
        let flag = state.config.hot_bool(crate::config::Hot::AttemptToProxyIfNoMatchingExpectation, true);
        let mode = state.mode.lock().filter(|m| (*m != "SIMULATE") == flag).unwrap_or(if flag { "SPY" } else { "SIMULATE" });
        return body(mode);
    }
    match set_mode(state, query_param(request, "mode")) {
        Ok(mode) => body(mode),
        Err(message) => text(400, message),
    }
}

/// `HttpState.setMode(MockMode.parse(value))`.
pub fn set_mode(state: &State, value: Option<&str>) -> Result<&'static str, String> {
    const MODES: [&str; 3] = ["SIMULATE", "SPY", "CAPTURE"];
    let Some(value) = value.filter(|v| !v.trim().is_empty()) else {
        return Err("mode is required (one of SIMULATE, SPY, CAPTURE)".into());
    };
    let Some(mode) = MODES.iter().find(|m| m.eq_ignore_ascii_case(value.trim())) else {
        return Err(format!("unknown mode '{value}' (expected one of SIMULATE, SPY, CAPTURE)"));
    };
    // One configuration (upstream 0e8566814): the flag set here is the one the data plane reads. The 8.0.0
    // process wrote it only into `HttpState`'s copy, so a SIMULATE server kept forwarding.
    let mut current = state.mode.lock();
    *current = Some(mode);
    state.config.set_runtime("attemptToProxyIfNoMatchingExpectation", (*mode != "SIMULATE").to_string());
    drop(current);
    Ok(mode)
}

/// `mockServerLog.retrieveRequests(filter)`: the recorded requests matching `filter` (all when `None`), in input form.
pub fn recorded_requests(state: &State, filter: Option<&Value>) -> Vec<Value> {
    let matcher = matcher::string::with_remote_refs_policy(state.json_schema_allow_remote_refs(), || filter.map(RequestMatcher::compile));
    state.log.matching_requests(matcher.as_ref()).iter().map(|r| crate::recorded::ordered(r)).collect()
}

/// The fan-in coordinator when this retrieve is to use it: enabled, and not a peer's own query
/// (`?fanInLocalOnly=true`, `Boolean.parseBoolean`, the recursion guard).
fn fan_in_for(state: &State, request: &HttpRequest) -> Option<std::sync::Arc<crate::cluster_fanin::ClusterFanIn>> {
    let local_only = query_param(request, "fanInLocalOnly").is_some_and(|v| v.eq_ignore_ascii_case("true"));
    let fan_in = state.cluster_fan_in();
    (!local_only && fan_in.enabled()).then_some(fan_in)
}

/// `WARN` entries for the peers a fan-in could not reach (`ClusterFanIn.logUnreachable`).
fn log_unreachable(state: &State, failures: &[(String, String)]) {
    for (peer, error) in failures {
        crate::log::warn_event(state, crate::recorded::LogEntry::new(crate::recorded::Kind::Warn, "cluster verify/retrieve fan-in could not reach peer{}error:{}").args([peer.as_str(), error.as_str()]));
    }
}

/// `HttpState.retrieve`'s `catch (ClusterFanInException)`: fail closed with a 502 naming the peers.
fn fan_in_failed(state: &State, peers: Vec<String>) -> Reply {
    let message = crate::cluster_fanin::ClusterFanInException::new(peers).message();
    crate::log::error_event(state, crate::recorded::LogEntry::new(crate::recorded::Kind::Error, "cluster retrieve fan-in failed:{}").args([message.as_str()]));
    Reply::api_body(502, "application/json", json::compact(&serde_json::json!({"error": message})))
}

/// The peers' recorded requests; `Err` names the unreachable peers ([`fan_in_failed`]).
fn fan_in_requests(state: &State, fan_in: &crate::cluster_fanin::ClusterFanIn, filter: Option<&Value>) -> Result<Vec<std::sync::Arc<HttpRequest>>, Vec<String>> {
    let remote = fan_in.fan_in_requests(filter);
    log_unreachable(state, &remote.failures);
    if remote.has_unreachable_peers() {
        return Err(remote.unreachable_peers);
    }
    Ok(remote.merged.iter().map(|v| std::sync::Arc::new(crate::cluster_fanin::request_from_json(v))).collect())
}

/// The peers' request-response pairs; `Err` names the unreachable peers ([`fan_in_failed`]).
fn fan_in_request_responses(state: &State, fan_in: &crate::cluster_fanin::ClusterFanIn, filter: Option<&Value>) -> Result<Vec<std::sync::Arc<crate::recorded::Exchange>>, Vec<String>> {
    let remote = fan_in.fan_in_request_responses(filter);
    log_unreachable(state, &remote.failures);
    if remote.has_unreachable_peers() {
        return Err(remote.unreachable_peers);
    }
    Ok(remote.merged.iter().map(|v| std::sync::Arc::new(crate::cluster_fanin::exchange_from_json(v))).collect())
}

fn retrieve(state: &State, request: &HttpRequest) -> Reply {
    let dropped = undecodable_query(state, request);
    let request = dropped.as_ref().unwrap_or(request);
    const TYPES: &[&str] = &["logs", "requests", "request_responses", "recorded_expectations", "active_expectations", "metrics"];
    const FORMATS: &[&str] = &[
        "java", "javascript", "python", "go", "csharp", "ruby", "rust", "php", "json", "log_entries", "har", "openapi",
        "postman", "bruno", "curl",
    ];
    // `defaultIfEmpty`: an empty parameter is the default.
    let raw_kind = query_param(request, "type").filter(|v| !v.is_empty()).unwrap_or("REQUESTS");
    let raw_format = query_param(request, "format").filter(|v| !v.is_empty()).unwrap_or("JSON");
    // `HttpState.retrieve` reads the body first, then `format`, then `type`, and logs any `IllegalArgumentException`
    // before rethrowing it to `HttpRequestHandler`; one whose message names `RetrieveType` or `Format` (a report
    // echoing such a body, the cookie examples' `exampleFormatSchemaCookie`) is rethrown as that parameter's error.
    let failed = |message: &str| {
        if crate::log::error_enabled(state) {
            let entry = crate::recorded::LogEntry::at(crate::recorded::Level::Error, "exception handling request:{}error:{}")
                .correlation(uuid::Uuid::new_v4().to_string())
                .args([crate::recorded::Arg::from(crate::recorded::logged(request)), message.into()]);
            crate::log::entry_as(state, crate::recorded::Level::Error, &entry);
            state.log.message(entry);
        }
        let invalid = |name: &str, values: &[&str]| {
            let value = query_param(request, name).unwrap_or_default();
            format!("\"{value}\" is not a valid value for \"{name}\" parameter, only the following values are supported [{}]", values.join(", "))
        };
        let shown = match message {
            m if m.contains("RetrieveType") => invalid("type", TYPES),
            m if m.contains("Format") => invalid("format", FORMATS),
            m => m.to_string(),
        };
        filter_failure(state, request, &shown)
    };
    let filter = match filter_or_message(state, request) {
        Ok(f) => f,
        Err(message) => return failed(&message),
    };
    // `Format.valueOf` / `RetrieveType.valueOf` of the upper-cased parameter.
    if !FORMATS.contains(&raw_format.to_ascii_lowercase().as_str()) {
        return failed(&format!("No enum constant org.mockserver.model.Format.{}", raw_format.to_uppercase()));
    }
    if !TYPES.contains(&raw_kind.to_ascii_lowercase().as_str()) {
        return failed(&format!("No enum constant org.mockserver.model.RetrieveType.{}", raw_kind.to_uppercase()));
    }
    let (kind, format) = (raw_kind.to_ascii_uppercase(), raw_format.to_ascii_uppercase());
    // `ExpectationFilter.fromControlPlaneRequest(request).requireComplete(false)` (upstream 9.2.0).
    let expectation_filter = match crate::expectation_filter::ExpectationFilter::from_request(request).and_then(|f| f.require_complete(false)) {
        Ok(f) => f,
        Err(message) => return failed(&message),
    };
    if expectation_filter.has_selection() && kind != "ACTIVE_EXPECTATIONS" {
        return failed("metadata and unmatched filters only apply to active_expectations retrieval");
    }
    if expectation_filter.has_paging() && kind != "ACTIVE_EXPECTATIONS" && kind != "RECORDED_EXPECTATIONS" {
        return failed("limit and offset only apply to active_expectations and recorded_expectations retrieval");
    }
    // `?forwardUnmatchedTo=<upstream>` arms record-and-forward of unmatched requests, whatever the type.
    if let Some(upstream) = query_param(request, "forwardUnmatchedTo").filter(|v| !v.trim().is_empty()) && let Some(reply) = enable_record_and_forward(state, upstream, &request.log_correlation_id) {
        return reply;
    }
    let matcher = matcher::string::with_remote_refs_policy(state.json_schema_allow_remote_refs(), || filter.matcher_json().map(RequestMatcher::compile));
    let any = RequestMatcher::any();
    let unfiltered = filter.unfiltered();
    // An unfiltered read admits every definition (`MockServerEventLog.filterMatcher`: no matcher).
    let admits_definition = |d: &Value, m: &RequestMatcher| if unfiltered { unfiltered_admits_definition(d) } else { definition_matches_filter(d, m) };
    let filter_json = filter.matcher_json().cloned().unwrap_or_else(|| json!({}));
    // An OpenAPI filter is logged as upstream deserialised it (`OpenAPIDefinition`: the spec as JSON, the
    // operation first); a later filter meets that definition.
    let filter_json = logged_definition(&filter_json);
    let correlation = query_param(request, "correlationId").filter(|c| !c.trim().is_empty());
    // The filter's matcher: none for logs by correlation id, metrics, or expectations listed by id.
    let builds_matcher = match kind.as_str() {
        "LOGS" => correlation.is_none(),
        "METRICS" => false,
        "ACTIVE_EXPECTATIONS" => !matches!(filter, Filter::Expectation(..)),
        _ => true,
    };
    let scan = builds_matcher.then(|| OpenApiScan::begin(state, kind == "ACTIVE_EXPECTATIONS", filter_json.clone()));
    let log_retrieved = |message: String| {
        if let Some(scan) = &scan {
            scan.flush();
        }
        crate::dataplane::flush_regex_timeouts(state);
        // `HttpState.retrieve` asks `isEnabledForInstance(INFO)` before each `RETRIEVED` entry
        if !state.info_enabled() {
            return;
        }
        let entry = attached_definition(
            crate::recorded::LogEntry::new(crate::recorded::Kind::Retrieved, message).correlation(uuid::Uuid::new_v4().to_string()),
            &filter_json,
        );
        state.log.message_about(entry, Subject::Definition(filter_json.clone()));
    };
    let port = Some(state.first_port());
    let log_entries =|scope: crate::recorded::EntryScope| {
        let filter = matcher.as_ref().unwrap_or(&any);
        let entries = expectation_filter.page(state.log.log_entries(scope, |r| filter.matches(r, Mode::ControlPlane), |d| admits_definition(d, filter), port, &state.config));
        if let Some(failure) = unwritable_log_entries(state, request, &entries) {
            return failure;
        }
        let body = if entries.is_empty() { "[]".to_string() } else { json::pretty_multiline(&Value::Array(entries)) };
        Reply::api_body(200, "application/json", body)
    };
    let fmt = format.to_ascii_lowercase();
    let language = codegen::Language::parse(&format);
    match kind.as_str() {
        "ACTIVE_EXPECTATIONS" => {
            let tenant = crate::namespace::filter(state, request);
            // `retrieveActiveExpectations`: a used-up expectation still serving a request is listed.
            let active: Vec<_> = state
                .store
                .retrievable()
                .into_iter()
                .filter(|e| match &filter {
                    // An id names exactly one expectation (`HttpState.retrieve`, ACTIVE_EXPECTATIONS).
                    Filter::Expectation(id, _) => e.id == *id,
                    _ if unfiltered => true,
                    // `notFilterableByRequest`: an HTTP filter (or none) cannot describe a DNS expectation, which is
                    // always listed; a DNS or binary filter narrows it.
                    _ if e.dns.is_some() && matcher.as_ref().is_none_or(|m| m.dns().is_none() && m.binary_data().is_none()) => true,
                    // Nor a conditional one, which only a conditional, DNS or binary filter narrows.
                    _ if canonical::is_conditional_request(&e.canonical["httpRequest"])
                        && matcher.as_ref().is_none_or(|m| m.dns().is_none() && m.conditional().is_none() && m.binary_data().is_none()) =>
                    {
                        true
                    }
                    _ => expectation_matches_filter(e, matcher.as_ref().unwrap_or(&any)),
                })
                // The tenant view: this namespace's expectations and the global ones.
                .filter(|e| tenant.as_deref().is_none_or(|t| crate::namespace::admits(e.namespace.as_deref(), Some(t))))
                .filter(|e| !expectation_filter.has_selection() || expectation_filter.matches(e))
                .collect();
            let active = expectation_filter.page(active);
            let current: Vec<Value> = active.iter().map(|e| e.current()).collect();
            let reply = match (format.as_str(), language) {
                ("JSON", _) if active.iter().any(|e| unwritable(e)) => return unwritable_failure(state, request),
                ("JSON", _) => json_array(&current),
                ("JAVA", _) => {
                    let sources: Vec<_> = active
                        .iter()
                        .zip(&current)
                        .map(|(e, c)| codegen::java::Source { input: &e.input, id: Some(&e.id), times: &c["times"], time_to_live: &c["timeToLive"] })
                        .collect();
                    match codegen::java::expectations(&sources) {
                        Ok(code) => Reply::api_typed(200, "application/java", code),
                        Err(message) => return java_codegen_failure(state, request, message),
                    }
                }
                (_, Some(language)) => code_reply(language, &active.iter().map(|e| e.current_default_values()).collect::<Vec<_>>()),
                ("LOG_ENTRIES" | "CURL", _) => retrieved_text(200, format!("{format} not supported for ACTIVE_EXPECTATIONS")),
                ("HAR", _) => har(active.iter().filter_map(|e| expectation_pair(&e.input, &e.canonical)).collect()),
                ("OPENAPI", _) => openapi(active.iter().map(|e| export_expectation(&e.id, &e.input, &e.canonical)).collect()),
                ("POSTMAN", _) => postman(active.iter().map(|e| export_expectation(&e.id, &e.input, &e.canonical)).collect()),
                ("BRUNO", _) => bruno(active.iter().map(|e| export_expectation(&e.id, &e.input, &e.canonical)).collect(), "expectations"),
                _ => return unsupported(raw_kind, raw_format),
            };
            // `scheduleLazyRemoval` runs on the scheduler, which logs the removal while the listing is written: its
            // entry lands just before the listing's own.
            log_lazy_removals(state, None);
            log_retrieved(format!("retrieved {} active expectations in {fmt} that match:{{}}", active.len()));
            reply
        }
        // A DNS or binary filter selects the definitions DNS queries and binary messages are recorded as (upstream #97);
        // an HTTP request never passes it.
        "REQUESTS" if matches!(format.as_str(), "JSON" | "JAVA" | "LOG_ENTRIES") && filter.matcher_json().is_some_and(|f| canonical::is_dns_request(f) || canonical::is_binary_request(f)) => {
            let m = matcher.as_ref().unwrap_or(&any);
            let reply = if format == "LOG_ENTRIES" {
                let entries = state.log.log_entries(crate::recorded::EntryScope::ReceivedDefinitions, |_| false, |d| definition_matches_filter(d, m), port, &state.config);
                let body = if entries.is_empty() { "[]".to_string() } else { json::pretty_multiline(&Value::Array(entries)) };
                Reply::api_body(200, "application/json", body)
            } else {
                let definitions = state.log.received_definitions(|d| definition_matches_filter(d, m));
                let body = if definitions.is_empty() { "[]".to_string() } else { json::pretty(&Value::Array(definitions)) };
                Reply::api_body(200, if format == "JAVA" { "application/java" } else { "application/json" }, body)
            };
            log_retrieved(format!("retrieved requests in {fmt} that match:{{}}"));
            reply
        }
        "REQUESTS" => {
            // `MockServerEventLog.retrieveRequests`'s `getRedactedHttpRequests`: every format below shares this
            // one (possibly redacted, under `redactSecretsInLog`) list — verified against the oracle.
            let mut requests = crate::recorded::redact_requests(state.log.matching_requests(matcher.as_ref()), &state.config);
            // `retrieveRequestsPossiblyFanIn`, in the formats that read the list (`LOG_ENTRIES` and the
            // unsupported ones do not).
            if matches!(format.as_str(), "JSON" | "JAVA" | "CURL" | "HAR" | "OPENAPI" | "POSTMAN" | "BRUNO") && let Some(fan_in) = fan_in_for(state, request) {
                match fan_in_requests(state, &fan_in, filter.matcher_json()) {
                    Ok(remote) => requests.extend(remote),
                    Err(peers) => return fan_in_failed(state, peers),
                }
            }
            // `RequestDefinitionSerializer.serializeRecordedRequests` (both formats) cannot write a JSON-typed body
            // that is not JSON.
            if matches!(format.as_str(), "JSON" | "JAVA") && let Some(index) = requests.iter().position(|r| crate::recorded::unwritable_request(r)) {
                return unwritable_requests(state, request, requests.len(), index);
            }
            let reply = match (format.as_str(), language) {
                ("JSON", _) => json_array(&requests.iter().map(|r| crate::recorded::flat(r)).collect::<Vec<_>>()),
                // `RequestDefinitionSerializer.serialize`: JSON, whatever the format says.
                ("JAVA", _) => {
                    let items: Vec<Value> = requests.iter().map(|r| crate::recorded::ordered(r)).collect();
                    let body = if items.is_empty() { "[]".to_string() } else { json::pretty(&items) };
                    Reply::api_body(200, "application/java", body)
                }
                ("LOG_ENTRIES", _) => {
                    let entries = state.log.received_log_entries(matcher.as_ref(), &state.config);
                    let body = if entries.is_empty() { "[]".to_string() } else { json::pretty_multiline(&Value::Array(entries)) };
                    Reply::api_body(200, "application/json", body)
                }
                ("CURL", _) => curl_commands(requests.iter().map(|r| r.as_ref())),
                ("OPENAPI", _) => openapi(requests.iter().map(|r| crate::export::Expectation::synthetic(crate::recorded::input_request(r), None)).collect()),
                ("POSTMAN", _) => postman(requests.iter().map(|r| crate::export::Expectation::synthetic(crate::recorded::input_request(r), None)).collect()),
                ("BRUNO", _) => bruno(requests.iter().map(|r| crate::export::Expectation::synthetic(crate::recorded::input_request(r), None)).collect(), "requests"),
                ("HAR", _) => har(requests.iter().map(|r| crate::export::Pair { request: Some(crate::export::Request::received(r)), response: None, timestamp: None }).collect()),
                (_, Some(_)) => retrieved_text(200, format!("{format} not supported for REQUESTS (use RECORDED_EXPECTATIONS)")),
                _ => return unsupported(raw_kind, raw_format),
            };
            log_retrieved(format!("retrieved requests in {fmt} that match:{{}}"));
            reply
        }
        "REQUEST_RESPONSES" => {
            // `MockServerEventLog.retrieveRequestResponses`'s redacted pair list — shared by every format below,
            // as for `REQUESTS` above.
            let mut exchanges = crate::recorded::redact_exchanges(state.log.matching(matcher.as_ref()), &state.config);
            // `retrieveRequestResponsesPossiblyFanIn` (not for `LOG_ENTRIES`, nor the unsupported formats).
            if matches!(format.as_str(), "JSON" | "CURL" | "HAR" | "OPENAPI" | "POSTMAN" | "BRUNO") && let Some(fan_in) = fan_in_for(state, request) {
                match fan_in_request_responses(state, &fan_in, filter.matcher_json()) {
                    Ok(remote) => exchanges.extend(remote),
                    Err(peers) => return fan_in_failed(state, peers),
                }
            }
            if format == "JSON" && let Some(index) = exchanges.iter().position(|x| x.shown_request.is_none() && crate::recorded::unwritable_request(&x.request)) {
                return unwritable_request_responses(state, request, exchanges.len(), index);
            }
            let reply = match (format.as_str(), language) {
                ("JSON", _) => json_array(&exchanges.iter().map(|x| crate::recorded::exchange_json(x)).collect::<Vec<_>>()),
                ("LOG_ENTRIES", _) => log_entries(crate::recorded::EntryScope::RequestResponses),
                ("CURL", _) => curl_commands(exchanges.iter().map(|x| &*x.request)),
                ("HAR", _) => har(exchanges.iter().map(|x| exchange_pair(state, x)).collect()),
                ("OPENAPI", _) => openapi(exchanges.iter().map(|x| exchange_expectation(x)).collect()),
                ("POSTMAN", _) => postman(exchanges.iter().map(|x| exchange_expectation(x)).collect()),
                ("BRUNO", _) => bruno(exchanges.iter().map(|x| exchange_expectation(x)).collect(), "traffic"),
                ("JAVA", _) | (_, Some(_)) => retrieved_text(200, format!("{format} not supported for REQUEST_RESPONSES")),
                _ => return unsupported(raw_kind, raw_format),
            };
            log_retrieved(format!("retrieved requests and responses in {fmt} that match:{{}}"));
            reply
        }
        "RECORDED_EXPECTATIONS" => {
            // (Only the forwarded exchanges meet the filter: an OpenAPI one logs its differences at TRACE.)
            let recorded: Vec<_> = state
                .log
                .exchanges()
                .into_iter()
                .filter(|x| x.recorded.is_some() && matcher.as_ref().is_none_or(|f| f.matches(&x.request, Mode::ControlPlane)))
                .map(|x| crate::transport_headers::recorded_view(x, false))
                .collect();
            // `postProcessRecordedExpectations`: consolidation or deduplication, for the model-based formats only.
            let post_processed = language.is_some() || matches!(format.as_str(), "JSON" | "JAVA" | "HAR" | "OPENAPI" | "POSTMAN" | "BRUNO");
            // `recordedBodyFileExtractor` is built (and refuses a bad `extractBodiesLargerThan`) before any step.
            let extractor = if post_processed {
                match crate::import::body_files::extractor(state, request) {
                    Ok(extractor) => extractor,
                    Err(message) => return retrieve_client_error(state, request, &message),
                }
            } else {
                None
            };
            let recorded = if post_processed { crate::import::post_process_recorded(state, request, recorded) } else { recorded };
            // `postProcessRecordedExpectations`'s `redactSecretsInRecordedExpectations` step — every
            // format below but `LOG_ENTRIES`/`CURL` shares this redacted view.
            let recorded = crate::recorded::redact_recorded_expectations(recorded, &state.config);
            // Paged after post-processing and redaction, before the body files are extracted (`postProcessRecordedExpectations`).
            let recorded = expectation_filter.page(recorded);
            // Its last step, `?extractBodiesLargerThan`.
            let recorded = match &extractor {
                Some(extractor) => extractor.extract(state, recorded),
                None => recorded,
            };
            let canonical: Vec<Value> = recorded.iter().filter_map(|x| x.recorded.clone()).collect();
            let reply = match (format.as_str(), language) {
                ("JSON", _) => json_array(&canonical),
                ("JAVA", _) => {
                    let sources: Vec<_> = recorded
                        .iter()
                        .filter_map(|x| {
                            let input = x.recorded_input.as_ref()?;
                            Some(codegen::java::Source { input, id: None, times: &input["times"], time_to_live: &input["timeToLive"] })
                        })
                        .collect();
                    match codegen::java::expectations(&sources) {
                        Ok(code) => Reply::api_typed(200, "application/java", code),
                        Err(message) => return java_codegen_failure(state, request, message),
                    }
                }
                (_, Some(language)) => code_reply(language, &canonical),
                ("LOG_ENTRIES", _) => log_entries(crate::recorded::EntryScope::RecordedExpectations),
                ("CURL", _) => retrieved_text(200, "CURL not supported for RECORDED_EXPECTATIONS"),
                ("HAR", _) => har(recorded.iter().filter_map(|x| expectation_pair(x.recorded_input.as_ref()?, x.recorded.as_ref()?)).collect()),
                ("OPENAPI", _) => openapi(recorded_expectations(&recorded)),
                ("POSTMAN", _) => postman(recorded_expectations(&recorded)),
                ("BRUNO", _) => bruno(recorded_expectations(&recorded), "recorded"),
                _ => return unsupported(raw_kind, raw_format),
            };
            log_retrieved(format!("retrieved recorded expectations in {fmt} that match:{{}}"));
            reply
        }
        // `HttpState.retrieve`: a non-blank `correlationId` replaces the request filter with every entry of that id.
        "LOGS" if correlation.is_some() => {
            let id = correlation.unwrap_or_default();
            if format == "LOG_ENTRIES" {
                let entries = state.log.log_entries_correlated(id, port, &state.config);
                if let Some(failure) = unwritable_log_entries(state, request, &entries) {
                    return failure;
                }
                let body = if entries.is_empty() { "[]".to_string() } else { json::pretty_multiline(&Value::Array(entries)) };
                log_retrieved("retrieved log entries in log_entries format that match:{}".to_string());
                Reply::api_body(200, "application/json", body)
            } else {
                let lines: Vec<String> = state
                    .log
                    .messages_correlated(id)
                    .into_iter()
                    .map(|(ts, message)| format!("{} - {message}", ts.format("%Y-%m-%d %H:%M:%S%.3f")))
                    .collect();
                log_retrieved("retrieved logs that match:{}".to_string());
                retrieved_text(200, lines.join("\n------------------------------------\n") + "\n")
            }
        }
        "LOGS" if format == "LOG_ENTRIES" => {
            let reply = log_entries(crate::recorded::EntryScope::Messages);
            // a log Jackson cannot write fails before `retrieved log entries` is logged
            if reply.status == 500 {
                return reply;
            }
            log_retrieved("retrieved log entries in log_entries format that match:{}".to_string());
            reply
        }
        "LOGS" => {
            let filter = matcher.as_ref().unwrap_or(&any);
            let lines: Vec<String> = state
                .log
                .messages(|r| filter.matches(r, Mode::ControlPlane), |d| admits_definition(d, filter))
                .into_iter()
                .map(|(ts, message)| format!("{} - {message}", ts.format("%Y-%m-%d %H:%M:%S%.3f")))
                .collect();
            log_retrieved("retrieved logs that match:{}".to_string());
            retrieved_text(200, lines.join("\n------------------------------------\n") + "\n")
        }
        "METRICS" => {
            let reply = Reply::api_body(200, "application/json", crate::metrics::retrieve(state));
            // `HttpState` at the pinned commit: an INFO `RETRIEVED` entry with the filter and no arguments,
            // whether or not metrics are enabled.
            crate::dataplane::flush_regex_timeouts(state);
            if state.info_enabled() {
                let entry = crate::recorded::LogEntry::new(crate::recorded::Kind::Retrieved, "retrieved metrics".to_string())
                    .correlation(uuid::Uuid::new_v4().to_string())
                    .request_json(filter_json.clone());
                state.log.message_about(entry, Subject::Definition(filter_json.clone()));
            }
            reply
        }
        _ => unsupported(raw_kind, raw_format),
    }
}

/// `request.getLogCorrelationId()`: the request's own, else a fresh one (a control-plane request gets its own).
fn correlation_of(request: &HttpRequest) -> String {
    crate::breakpoint::correlation(request)
}

/// `serializeAsBrunoCollection`: a ZIP download named after what it holds.
fn bruno(expectations: Vec<crate::export::Expectation>, what: &str) -> Reply {
    let mut reply = Reply::api(200);
    reply.headers.push(("content-type".into(), "application/zip".into()));
    reply.headers.push(("content-disposition".into(), format!("attachment; filename=\"mockserver-{what}.bruno.zip\"")));
    reply.body = crate::export::bruno::serialize(&expectations).into();
    reply
}

/// `serializeAsPostmanCollection`.
fn postman(expectations: Vec<crate::export::Expectation>) -> Reply {
    Reply::api_body(200, "application/json", crate::export::postman::serialize(&expectations))
}

/// `serializeAsOpenApi`.
fn openapi(expectations: Vec<crate::export::Expectation>) -> Reply {
    Reply::api_body(200, "application/json", crate::export::openapi::serialize(&expectations))
}

/// An expectation for the export formats: its request and response as given (their order), bodies as the model
/// holds them; `None` for a request that is not an HTTP request definition.
fn export_expectation(id: &str, input: &Value, canonical: &Value) -> crate::export::Expectation {
    let merged = |key: &str| -> Option<Value> {
        let model = canonical.get(key)?;
        let mut v = input.get(key).cloned().unwrap_or_else(|| model.clone());
        if let (Some(o), Some(body)) = (v.as_object_mut(), model.get("body")) {
            o.insert("body".into(), body.clone());
        }
        Some(v)
    };
    let http = canonical.get("httpRequest").is_some_and(|d| d.get("specUrlOrPayload").is_none() && !canonical::is_dns_request(d) && !canonical::is_conditional_request(d));
    crate::export::Expectation { id: id.to_string(), request: merged("httpRequest").filter(|_| http), response: merged("httpResponse") }
}

fn recorded_expectations(recorded: &[std::sync::Arc<crate::recorded::Exchange>]) -> Vec<crate::export::Expectation> {
    recorded
        .iter()
        .filter_map(|x| {
            let canonical = x.recorded.as_ref()?;
            let id = canonical.get("id").and_then(Value::as_str).unwrap_or_default();
            let input = x.recorded_input.as_ref().unwrap_or(canonical);
            let mut e = export_expectation(id, input, canonical);
            // A JSON body keeps its original text in the model (a consolidated or templatized one).
            for (message, key) in [(&mut e.request, "httpRequest"), (&mut e.response, "httpResponse")] {
                let raw = input.get(key).and_then(|m| m.get("body")).filter(|b| b.get("type").and_then(Value::as_str) == Some("JSON") && b.get("json").is_some_and(Value::is_string));
                if let (Some(Value::Object(m)), Some(raw)) = (message.as_mut(), raw) {
                    m.insert("body".into(), raw.clone());
                }
                // A JSON body without a content type (a modifier's bare `JsonBody`) keeps none, as in the HAR export.
                let untyped = input.get(key).and_then(|m| m.get("body")).is_some_and(|b| b.get("type").and_then(Value::as_str) == Some("JSON") && b.get("contentType").is_some_and(Value::is_null));
                if let (true, Some(Value::Object(body))) = (untyped, message.as_mut().and_then(|m| m.get_mut("body"))) && body.get("type").and_then(Value::as_str) == Some("JSON") {
                    body.insert("contentType".into(), Value::Null);
                }
            }
            Some(e)
        })
        .collect()
}

/// `toExpectationsFromPairs`: a recorded exchange as a synthetic expectation.
fn exchange_expectation(x: &crate::recorded::Exchange) -> crate::export::Expectation {
    let request = x.shown_request.clone().unwrap_or_else(|| crate::recorded::input_request(&x.request));
    crate::export::Expectation::synthetic(request, (!x.response.is_null()).then(|| Value::clone(&x.response)))
}

/// `HarConverter.serialize`.
fn har(pairs: Vec<crate::export::Pair>) -> Reply {
    Reply::api_body(200, "application/json", crate::export::har::serialize(&pairs))
}

/// `expectationsToLogEvents`: an expectation of an HTTP request as its request (in the order it was given, bodies as
/// the model holds them) and its `httpResponse`, if it has one.
fn expectation_pair(input: &Value, canonical: &Value) -> Option<crate::export::Pair> {
    let definition = canonical.get("httpRequest")?;
    if definition.get("specUrlOrPayload").is_some() || canonical::is_dns_request(definition) || canonical::is_conditional_request(definition) {
        return None;
    }
    let mut request = crate::export::Request::definition(input.get("httpRequest").unwrap_or(definition));
    let model = crate::export::Request::definition(definition);
    // A JSON body prints as the text it was given, as upstream's JsonBody keeps it.
    request.body = model.body.map(|b| b.with_raw_json(input.pointer("/httpRequest/body")));
    request.remote_address = request.remote_address.or(model.remote_address);
    let response = canonical.get("httpResponse").map(|r| {
        let mut response = crate::export::Response::json(input.get("httpResponse").unwrap_or(r));
        // An empty string body is still a body in the model (the canonical form drops it).
        response.body = crate::export::Response::json(r).body.map(|b| b.with_raw_json(input.pointer("/httpResponse/body"))).or(response.body.take().filter(|b| b.text.is_empty()));
        response
    });
    Some(crate::export::Pair { request: Some(request), response, timestamp: None })
}

/// A recorded exchange (`LogEventRequestAndResponse`) with its log timestamp.
fn exchange_pair(state: &State, x: &crate::recorded::Exchange) -> crate::export::Pair {
    let request = match &x.shown_request {
        Some(shown) => crate::export::Request::definition(shown),
        None => crate::export::Request::received(&x.request),
    };
    crate::export::Pair {
        request: Some(request),
        response: (!x.response.is_null()).then(|| {
            let mut response = crate::export::Response::json(&x.response);
            response.body = response.body.take().map(|b| b.with_raw_json(x.recorded_input.as_ref().and_then(|i| i.pointer("/httpResponse/body"))));
            // The response model keeps its headers in the order they were given: the recorded response's as it
            // arrived, a mocked one's as its expectation gave them.
            let mut recorded = x.recorded_input.as_ref().and_then(|i| i.get("httpResponse")).map(crate::export::Response::json);
            // An empty string body is still a body in the model (the log drops it).
            if response.body.is_none() {
                response.body = recorded.as_mut().and_then(|r| r.body.take()).filter(|b| b.text.is_empty() && !b.binary);
            }
            let input = recorded.or_else(|| x.expectation_id.as_deref().and_then(|id| state.store.get(id)).and_then(|e| e.input.get("httpResponse").map(crate::export::Response::json)));
            if let Some(input) = input {
                response.headers.sort_by_key(|(k, _)| input.headers.iter().position(|(n, _)| n == k).unwrap_or(usize::MAX));
            }
            response
        }),
        timestamp: Some(x.timestamp.format("%Y-%m-%d %H:%M:%S%.3f").to_string()),
    }
}

/// `HttpState.toCurlCommands`: each request as its cURL command, a blank line between them, a newline at the end.
fn curl_commands<'a>(requests: impl Iterator<Item = &'a HttpRequest>) -> Reply {
    // `writeCurlCommands`: a separator only follows text (a first command that renders empty gets none), and a
    // newline always ends the body, even when nothing matched.
    let mut body = String::new();
    let mut written = false;
    for request in requests {
        let curl = crate::curl::to_curl(request, None);
        if written {
            body.push_str("\n\n");
        }
        body.push_str(&curl);
        written = written || !curl.is_empty();
    }
    body.push('\n');
    Reply::api_typed(200, "text/plain", body)
}

fn unsupported(kind: &str, format: &str) -> Reply {
    text(400, format!("\"{kind}\" with format \"{format}\" is not supported yet by mock-server"))
}

/// `ExpectationToJavaSerializer` failing on a field it reads without a null check: the `NullPointerException` is a
/// fault, answered 500 by `HttpRequestHandler` (`ControlPlaneFailureResponse`).
fn java_codegen_failure(state: &State, request: &HttpRequest, message: String) -> Reply {
    unexpected_failure(state, request, &crate::recorded::Failure::of("java.lang.NullPointerException", message, Vec::new(), &[]))
}

/// A non-Java code format, given each expectation with default values written out (`ExpectationTo<X>Serializer`).
fn code_reply(language: codegen::Language, expectations: &[Value]) -> Reply {
    let jsons: Vec<String> = expectations.iter().map(json::pretty_expectations).collect();
    Reply::api_body(200, language.content_type(), language.serialize(&jsons))
}

/// A filter as its log entries print it: an OpenAPI one as upstream deserialised it (`OpenAPIDefinition`: the spec
/// as JSON, the operation first), any other as given.
fn logged_definition(filter: &Value) -> Value {
    if filter.get("specUrlOrPayload").is_some() { canonical::request_definition(filter) } else { filter.clone() }
}

/// A log line's filter `definition`, as its `httpRequest` and its one argument. A binary definition is written as it
/// prints (`LogEntry.updateBody` passes it through since upstream #102), and the argument is its `toString`, compacted
///.
fn attached_definition(entry: crate::recorded::LogEntry, definition: &Value) -> crate::recorded::LogEntry {
    if !canonical::is_binary_request(definition) {
        return entry.request_json(definition.clone()).args([definition]);
    }
    let shown = canonical::shown_definition(definition.clone());
    entry.request_json(shown.clone()).args([shown]).own_argument(0)
}

/// `PUT /mockserver/clear?type=all|log|expectations` with an optional matcher or `{"id": …}` (§1.2).
fn clear(state: &State, request: &HttpRequest) -> Reply {
    let dropped = undecodable_query(state, request);
    let request = dropped.as_ref().unwrap_or(request);
    let correlation = uuid::Uuid::new_v4().to_string();
    // `ExpectationFilter.fromControlPlaneRequest(request).requireComplete(true)`, before the body is read.
    let expectation_filter = match crate::expectation_filter::ExpectationFilter::from_request(request).and_then(|f| f.require_complete(true)) {
        Ok(f) => f,
        Err(message) => return filter_failure(state, request, &message),
    };
    // `HttpState.clear` reads the filter before its `try`, then `ClearType.valueOf` of the upper-cased `type`
    // (`defaultIfEmpty` "ALL") inside it: a bad filter is logged by `HttpRequestHandler` only.
    let filter = match filter_or_message(state, request) {
        Ok(f) => f,
        Err(message) => return filter_failure(state, request, &message),
    };
    if expectation_filter.is_filtered() {
        return clear_filtered(state, request, &filter, &expectation_filter, &correlation);
    }
    let kind = query_param(request, "type").filter(|v| !v.is_empty()).unwrap_or("all");
    let lower = kind.to_ascii_lowercase();
    if !["log", "expectations", "all"].contains(&lower.as_str()) {
        return clear_failed(state, request, &correlation, &format!("No enum constant org.mockserver.model.ClearType.{}", kind.to_uppercase()));
    }
    let (clear_log, clear_expectations) = (lower != "expectations", lower != "log");
    let matcher = matcher::string::with_remote_refs_policy(state.json_schema_allow_remote_refs(), || filter.matcher_json().map(RequestMatcher::compile));
    // `HttpState.clear` builds the filter's matcher first: a `JSON_SCHEMA` body networknt cannot build throws
    if let Some(error) = matcher.as_ref().filter(|m| m.body_schema_unbuilt()).and_then(RequestMatcher::body_error) {
        return unexpected_failure(state, request, &schema_unbuilt_failure(&error));
    }
    // `?namespace=` (or the namespace header) clears only that tenant's expectations, and never the event log,
    // which is not namespaced; `type=log` ignores it.
    if let Some(tenant) = crate::namespace::filter(state, request).filter(|_| clear_expectations) {
        clear_namespace(state, &tenant);
        crate::persistence::changed(state, None);
        return Reply::api(200);
    }
    // An OpenAPI filter whose spec cannot be loaded: building its matcher (for the log or the expectations, whichever
    // comes first) throws the `IllegalArgumentException` `HttpState.clear` reports as a bad `type`.
    if let Some(error) = matcher.as_ref().and_then(RequestMatcher::load_error) {
        return clear_failed(state, request, &correlation, error);
    }
    // `HttpState.clear`: the log first, then the expectations, each removal logged after the log was cleared.
    // `RequestMatchers.isUnfiltered`: `{}` clears everything, as no filter does, without reverse matching
    // (which a `not(...)`, conditional, DNS or binary definition would fail).
    let unfiltered = filter.unfiltered();
    if clear_log {
        match &matcher {
            Some(_) if unfiltered => state.log.clear(None),
            Some(m) => {
                // (No body is upstream's `clear(null)`: everything goes, and no matcher is built.)
                let _scan = OpenApiScan::begin(state, false, filter.matcher_json().cloned().unwrap_or_else(|| json!({})));
                state.log.clear(Some((&|r: &HttpRequest| m.matches(r, Mode::ControlPlane), &|d: &Value| definition_matches_filter(d, m))));
            }
            None => state.log.clear(None),
        }
        crate::dataplane::flush_regex_timeouts(state);
        if state.info_enabled() {
            let definition = filter.matcher_json().map(logged_definition);
            let definition = definition.as_ref();
            // `setArguments(requestDefinition == null ? "{}" : requestDefinition)`.
            let argument = definition.map_or_else(|| crate::recorded::Arg::from("{}"), crate::recorded::Arg::from);
            let entry = crate::recorded::LogEntry::new(crate::recorded::Kind::Cleared, "cleared logs that match:{}").without_port()
                .correlation(correlation.clone())
                .request_json(definition.cloned().unwrap_or_else(|| json!({})))
                .args([argument]);
            // Unfiltered, the entry's request is upstream's default `request()`: an empty request, which the next
            // unfiltered clear removes and a filter shows (or clears) only when it matches an empty request.
            let subject = match definition {
                Some(d) => crate::recorded::Subject::Definitions(vec![d.clone()]),
                None => crate::recorded::Subject::Request(std::sync::Arc::new(HttpRequest::default())),
            };
            state.log.message_about(entry, subject);
        }
    }
    if clear_expectations {
        match (&filter, &matcher) {
            // `RequestMatchers.clear(ExpectationId)`: logged whether or not the expectation was still there.
            (Filter::Expectation(id, _), _) => {
                let candidates: Vec<_> = state.store.get(id).into_iter().collect();
                if let Some(error) = clear_walk(state, &candidates, &correlation) {
                    return clear_failed(state, request, &correlation, error);
                }
                if state.info_enabled() {
                    let entry = crate::recorded::LogEntry::new(crate::recorded::Kind::Cleared, "cleared expectations that have id:{}").correlation(correlation.clone()).args([id]);
                    state.log.message(entry);
                }
            }
            (_, Some(m)) => {
                let scan = OpenApiScan::begin(state, true, filter.matcher_json().cloned().unwrap_or_else(|| json!({})));
                let candidates: Vec<_> = state.store.all().into_iter().filter(|e| unfiltered || expectation_matches_filter(e, m)).collect();
                drop(scan);
                crate::dataplane::flush_regex_timeouts(state);
                if let Some(error) = clear_walk(state, &candidates, &correlation) {
                    if candidates.len() > 1 {
                        crate::persistence::changed(state, None);
                    }
                    return clear_failed(state, request, &correlation, error);
                }
                if state.info_enabled() {
                    let definition = filter.matcher_json().map(logged_definition).unwrap_or_else(|| json!({}));
                    let entry = attached_definition(
                        crate::recorded::LogEntry::new(crate::recorded::Kind::Cleared, "cleared expectations that match:{}").correlation(correlation.clone()),
                        &definition,
                    );
                    state.log.message_about(entry, Subject::Definition(definition));
                }
            }
            // `RequestMatchers.reset`: every expectation removed (and logged), ids forgotten, scenarios reset.
            _ => {
                if let Some(error) = reset_aborted(state) {
                    return clear_failed(state, request, &correlation, error);
                }
                let removed = state.store.all();
                state.store.clear();
                log_removals(state, &removed, &correlation);
            }
        }
    }
    crate::persistence::changed(state, None);
    Reply::api(200)
}

/// `HttpState.clear` for a request naming a metadata or `unmatched` filter: only expectations go (the event log carries
/// neither), those the namespace, the body (a request matcher or an id) and the filter all accept.
fn clear_filtered(state: &State, request: &HttpRequest, filter: &Filter, expectation_filter: &crate::expectation_filter::ExpectationFilter, correlation: &str) -> Reply {
    if let Some(kind) = query_param(request, "type").filter(|t| !t.trim().is_empty())
        && !kind.eq_ignore_ascii_case("expectations")
        && !kind.eq_ignore_ascii_case("all")
    {
        return filter_failure(state, request, &format!("metadata and unmatched filters only apply to type=expectations or type=all, not type={kind}"));
    }
    let tenant = crate::namespace::filter(state, request);
    let admitted = |e: &Expectation| tenant.as_deref().is_none_or(|t| e.namespace.as_deref() == Some(t)) && expectation_filter.matches(e);
    let matcher = matcher::string::with_remote_refs_policy(state.json_schema_allow_remote_refs(), || filter.matcher_json().map(RequestMatcher::compile));
    if let Some(error) = matcher.as_ref().filter(|m| m.body_schema_unbuilt()).and_then(RequestMatcher::body_error) {
        return unexpected_failure(state, request, &schema_unbuilt_failure(&error));
    }
    if let Some(error) = matcher.as_ref().and_then(RequestMatcher::load_error) {
        return clear_failed(state, request, correlation, error);
    }
    let unfiltered = filter.unfiltered();
    let scan = OpenApiScan::begin(state, true, filter.matcher_json().cloned().unwrap_or_else(|| json!({})));
    let candidates: Vec<_> = match (filter, &matcher) {
        (Filter::Expectation(id, _), _) => state.store.get(id).into_iter().filter(|e| admitted(e)).collect(),
        (_, Some(m)) => state.store.all().into_iter().filter(|e| admitted(e) && (unfiltered || expectation_matches_filter(e, m))).collect(),
        _ => state.store.all().into_iter().filter(|e| admitted(e)).collect(),
    };
    drop(scan);
    crate::dataplane::flush_regex_timeouts(state);
    let error = clear_walk(state, &candidates, correlation);
    if !candidates.is_empty() && state.info_enabled() {
        let definition = filter.matcher_json().map(logged_definition);
        let entry = crate::recorded::LogEntry::new(crate::recorded::Kind::Cleared, "cleared{}expectations that match filter:{}")
            .correlation(correlation.to_string())
            .request_json(definition.clone().unwrap_or_else(|| json!({})))
            .args([crate::recorded::Arg::from(json!(candidates.len())), crate::recorded::Arg::from(expectation_filter.to_json())]);
        let subject = match definition {
            Some(d) => crate::recorded::Subject::Definitions(vec![d]),
            None => crate::recorded::Subject::Request(std::sync::Arc::new(HttpRequest::default())),
        };
        state.log.message_about(entry, subject);
    }
    if let Some(error) = error {
        crate::persistence::changed(state, None);
        return clear_failed(state, request, correlation, error);
    }
    crate::persistence::changed(state, None);
    Reply::api(200)
}

/// `RequestMatchers.clearByNamespace`: each removed expectation is logged, then (only when there was one) the clear.
fn clear_namespace(state: &State, namespace: &str) {
    let removed = state.store.take_where(|e| e.namespace.as_deref() == Some(namespace));
    if removed.is_empty() {
        return;
    }
    let correlation = uuid::Uuid::new_v4().to_string();
    log_removals(state, &removed, &correlation);
    if state.info_enabled() {
        let entry = crate::recorded::LogEntry::new(crate::recorded::Kind::Cleared, "cleared expectations in namespace:{}").correlation(correlation).args([namespace]);
        state.log.message(entry);
    }
}

/// `retrieveActiveExpectations`: what it drops as used up or expired is logged as removed.
pub(crate) fn retrievable_logged(state: &State) -> Vec<std::sync::Arc<Expectation>> {
    let listed = state.store.retrievable();
    log_lazy_removals(state, None);
    listed
}

/// The `removed expectation` entries of expectations a scan or a listing dropped as used up or expired (`only`: one id).
pub(crate) fn log_lazy_removals(state: &State, only: Option<&str>) {
    let removed = state.store.take_lazy_removed(only);
    if !removed.is_empty() {
        log_removals(state, &removed, &uuid::Uuid::new_v4().to_string());
    }
}

/// `removeHttpRequestMatcher` for each of `removed`: the `removed expectation` line, and a scenario no remaining
/// expectation names is forgotten (`clearOrphanedScenarioState`).
pub(crate) fn log_removals(state: &State, removed: &[std::sync::Arc<Expectation>], correlation: &str) {
    if state.info_enabled() {
        for e in removed {
            log_removed(state, e, correlation);
        }
    }
    let remaining = state.store.all();
    for name in removed.iter().filter_map(|e| e.input.get("scenarioName").and_then(Value::as_str)).filter(|n| !n.trim().is_empty()) {
        if !remaining.iter().any(|e| e.input.get("scenarioName").and_then(Value::as_str) == Some(name)) {
            state.scenarios().clear(name);
        }
    }
}

/// An expectation's request definition as the `httpRequest` of its creating, updated and removed entries: a binary one
/// as it prints, a DNS or binary one without its `not` (the oracle leaves it out there, though the expectation shows it).
fn logged_request_definition(subject: &Value) -> Value {
    let mut out = subject.clone();
    if canonical::is_binary_request(subject) {
        out = canonical::shown_definition(out);
    }
    let drops_not = canonical::is_dns_request(subject) || canonical::is_binary_request(subject);
    if drops_not
        && let Some(o) = out.as_object_mut()
    {
        o.shift_remove("not");
    }
    out
}

/// `REMOVED_EXPECTATION_MESSAGE_FORMAT`, a log line about the expectation's request matcher.
fn log_removed(state: &State, e: &Expectation, correlation: &str) {
    let shown = canonical::logged_expectation_ending(&e.current(), e.end_date_millis());
    let subject = e.request_definition();
    // A binary definition is written as it prints (upstream #102; `null` before).
    let attached = logged_request_definition(&subject);
    let mut entry = crate::recorded::LogEntry::new(crate::recorded::Kind::RemovedExpectation, "removed expectation:{}with id:{}")
        .request_json(attached)
        .args([crate::recorded::Arg::from(shown.clone()), (&e.id).into()]);
    if !correlation.is_empty() {
        entry = entry.correlation(correlation);
    }
    crate::log::entry(state, &entry);
    state.log.message_about(entry, Subject::Definition(subject));
}

/// MockServer writes an empty result as `[]` and anything else pretty-printed.
fn json_array(items: &[Value]) -> Reply {
    let body = if items.is_empty() { "[]".to_string() } else { json::pretty_expectations(&Value::Array(items.to_vec())) };
    Reply::api_body(200, "application/json", body)
}

#[cfg(test)]
mod operation_route_tests {
    use super::operation_route;

    /// `http_route` is the operation path under `/mockserver`, a name in it a placeholder, else `_OTHER`.
    #[test]
    fn operation_routes_are_a_fixed_set() {
        assert_eq!(operation_route("/mockserver/expectation"), "/mockserver/expectation");
        assert_eq!(operation_route("/expectation"), "/mockserver/expectation", "a legacy alias");
        assert_eq!(operation_route("/mockserver/openapi.yaml"), "/mockserver/openapi.yaml");
        assert_eq!(operation_route("/mockserver/dashboard/static/js/main.js"), "/mockserver/dashboard");
        assert_eq!(operation_route("/mockserver/chaosExperiment/profiles/slow-db"), "/mockserver/chaosExperiment/profiles/{name}");
        assert_eq!(operation_route("/mockserver/chaosExperiment/profiles"), "/mockserver/chaosExperiment/profiles");
        assert_eq!(operation_route("/mockserver/loadScenario/checkout"), "/mockserver/loadScenario/{name}");
        assert_eq!(operation_route("/mockserver/loadScenario/checkout/report"), "/mockserver/loadScenario/{name}/report");
        assert_eq!(operation_route("/mockserver/loadScenario/start"), "/mockserver/loadScenario/start");
        assert_eq!(operation_route("/scenario/login"), "/mockserver/scenario/{name}");
        assert_eq!(operation_route("/mockserver/wasm/unknown"), "_OTHER");
        assert_eq!(operation_route("/mockserverx/status"), "_OTHER");
        assert!(super::OPERATIONS.windows(2).all(|w| w[0] < w[1]), "sorted, no duplicates");
    }
}

#[cfg(test)]
mod dashboard_tests {
    //! `DashboardHandlerTest`: the asset's `Content-Length` is its UTF-8 byte count, an SVG is
    //! `image/svg+xml`, and an unmapped extension falls back to `application/octet-stream`.
    use super::*;

    fn serve(name: &str, content: &[u8]) -> Reply {
        let dir = std::env::temp_dir().join(format!("dashboard-handler-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(name), content).unwrap();
        let request = HttpRequest { method: "GET".into(), path: format!("/mockserver/dashboard/{name}"), keep_alive: false, ..Default::default() };
        let reply = dashboard_in(&request, dir.to_str().unwrap());
        std::fs::remove_dir_all(&dir).unwrap();
        reply
    }

    fn header<'a>(reply: &'a Reply, name: &str) -> Option<&'a str> {
        reply.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    #[test]
    fn content_length_matches_utf8_body_length_for_multi_byte_asset() {
        let body = "console.log('h\u{e9}llo \u{4e16}\u{754c} \u{20ac}');";
        let reply = serve("multibyte-test.js", body.as_bytes());
        assert_eq!(reply.body.len(), body.len());
        assert!(body.len() > body.chars().count(), "fixture has multi-byte characters");
        assert_eq!(header(&reply, "content-length"), Some(body.len().to_string().as_str()));
        assert_ne!(header(&reply, "content-length"), Some(body.chars().count().to_string().as_str()));
    }

    #[test]
    fn serves_svg_with_svg_content_type() {
        let reply = serve("favicon-fixture.svg", b"<svg xmlns=\"http://www.w3.org/2000/svg\"/>");
        assert_eq!(header(&reply, "content-type"), Some("image/svg+xml"));
    }

    #[test]
    fn serves_unmapped_extension_as_octet_stream() {
        let reply = serve("unmapped-fixture.webp", b"RIFFxxxxWEBP");
        assert_ne!(reply.status, 404);
        assert_eq!(header(&reply, "content-type"), Some("application/octet-stream"));
    }
}
