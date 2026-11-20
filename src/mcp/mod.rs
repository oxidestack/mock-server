//! The MCP control endpoint, `/mockserver/mcp` (`McpStreamableHttpHandler`, `McpRequestProcessor`): JSON-RPC 2.0
//! over streamable HTTP with sessions (`Mcp-Session-Id`), answered before the control plane and never logged. It
//! serves `initialize`, `ping`, `tools/*` (the catalogue in `tools.json` is `McpToolRegistry`'s definitions as the
//! oracle lists them; [`tools`] runs them), `resources/*`, `prompts/*` and `sampling/createMessage`.

mod llm_tools;
pub(crate) use llm_tools::PROVIDERS;
pub(crate) mod spec_tools;
pub mod tools;

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;
use serde_json::{Map, Value, json};

use crate::reply::Reply;
use crate::request::HttpRequest;
use crate::state::State;

const LATEST_PROTOCOL_VERSION: &str = "2025-06-18";
const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];
const MAX_SESSIONS: usize = 100;
const SESSION_TTL_MILLIS: i64 = 60 * 60 * 1000;

const INSTRUCTIONS: &str = "MockServer is an HTTP(S) mock server and proxy for testing. Use these tools to mock APIs, debug failing requests, and verify implementations:\n\
- Mock APIs: 'create_expectation', 'create_expectation_from_openapi', and 'create_expectations_from_recorded_traffic' (turn traffic already recorded via the proxy into mocks).\n\
- Debug a request that did not match: call 'explain_unmatched_requests' after a failed test run to see, for each request that hit the server, the closest expectations ranked by similarity with field-level diffs and a remediation hint — no need to reconstruct the request. 'debug_request_mismatch' does the same for a request you supply. 'explain_request' takes one received request's correlation id (from 'retrieve_logs') and says which expectation serves it now and why each one ahead of it lost; 'diagnose_config' shows which settings are in effect and where they came from. 'suggest_expectation_fix' proposes a guarded JSON patch for each close expectation; 'lint_expectations' finds expectations that can never match; 'explain_forward_failure' says why a forward or proxied request got a 502; 'test_template' dry-runs a response or forward template.\n\
- Verify an implementation: 'verify_request' / 'verify_request_sequence' check requests were made; 'verify_traffic_against_openapi' checks recorded traffic conforms to an OpenAPI contract; 'run_contract_test' sends spec-derived example requests to a running service and checks the responses; 'run_resiliency_test' sends malformed and boundary-case requests and reports which inputs the service failed to handle gracefully.\n\
- Deterministic LLM testing: 'record_llm_fixtures' snapshots LLM/MCP traffic recorded through the proxy into a committable, secret-free fixture file; 'load_expectations_from_file' replays it.\n\
Readable resources expose live state: mockserver://expectations, mockserver://requests, mockserver://logs, mockserver://unmatched, mockserver://configuration.";

const PARSE_ERROR: i64 = -32700;
const INVALID_REQUEST: i64 = -32600;
const METHOD_NOT_FOUND: i64 = -32601;
const INVALID_PARAMS: i64 = -32602;

struct Session {
    initialized: bool,
    last_accessed: i64,
    protocol_version: String,
}

/// `McpSessionManager`: at most 100 sessions (the least recently used is evicted), each idle for at most an hour.
#[derive(Default)]
pub struct Sessions {
    sessions: Mutex<HashMap<String, Session>>,
}

impl Sessions {
    fn create(&self, state: &State, protocol_version: String) -> String {
        let mut sessions = self.sessions.lock();
        if sessions.len() >= MAX_SESSIONS && let Some(oldest) = sessions.iter().min_by_key(|(_, s)| s.last_accessed).map(|(k, _)| k.clone()) {
            sessions.remove(&oldest);
            let entry = crate::recorded::LogEntry::at(crate::recorded::Level::Warn, "MCP session limit reached ({}), evicted least recently used session {}");
            crate::log::entry(state, &entry.args([crate::recorded::Arg::from(serde_json::json!(MAX_SESSIONS)), crate::recorded::Arg::from(oldest.as_str())]));
        }
        let id = uuid::Uuid::new_v4().to_string();
        sessions.insert(id.clone(), Session { initialized: false, last_accessed: now(), protocol_version });
        id
    }

    /// `getSession`: touches a live session; an expired one is dropped.
    fn with<T>(&self, id: Option<&str>, f: impl FnOnce(&mut Session) -> T) -> Option<T> {
        let id = id?;
        let mut sessions = self.sessions.lock();
        let expired = sessions.get(id).is_some_and(|s| now() - s.last_accessed > SESSION_TTL_MILLIS);
        if expired {
            sessions.remove(id);
            return None;
        }
        let session = sessions.get_mut(id)?;
        session.last_accessed = now();
        Some(f(session))
    }

    fn remove(&self, id: &str) -> bool {
        self.sessions.lock().remove(id).is_some()
    }
}

fn now() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// Whether the HTTP/1.1 and HTTP/2 pipelines answer `path` as MCP: `McpStreamableHttpHandler` is only added under
/// `mcpEnabled` (`PortUnificationHandler`, `Http2MultiplexChildInitializer`); HTTP/3 answers MCP regardless.
pub fn serves(state: &State, path: &str) -> bool {
    is_mcp_path(path) && state.config.bool_property("mcpEnabled", true)
}

/// `McpRequestProcessor.isMcpPath` (the query is not part of `path`).
pub fn is_mcp_path(path: &str) -> bool {
    path == "/mockserver/mcp" || path.starts_with("/mockserver/mcp/")
}

/// A JSON-RPC response (`JsonRpcResponse`): properties alphabetical, `id` always written.
fn response(id: &Value, result: Value) -> Value {
    // Built by hand: `json!` would re-serialise the result's numbers (`2.0E-4` → `2.0e-4`).
    let mut o = Map::new();
    o.insert("id".into(), id.clone());
    o.insert("jsonrpc".into(), json!("2.0"));
    o.insert("result".into(), result);
    Value::Object(o)
}

fn error(id: &Value, code: i64, message: &str) -> Value {
    json!({"error": {"code": code, "message": message}, "id": id, "jsonrpc": "2.0"})
}

/// `McpResult`: status, body (none for an empty one) and the session id to send.
struct Outcome {
    status: u32,
    body: Option<Value>,
    session: Option<String>,
}

fn with_body(status: u32, body: Value) -> Outcome {
    Outcome { status, body: Some(body), session: None }
}

fn empty(status: u32) -> Outcome {
    Outcome { status, body: None, session: None }
}

/// `McpStreamableHttpHandler.handleMcpRequest`: the reply, written without MockServer's usual decoration.
pub async fn handle(state: &Arc<State>, request: &HttpRequest) -> Reply {
    let origin = request.first_header("origin").filter(|o| !o.is_empty()).map(str::to_string);
    let outcome = result(state, request).await;
    let mut reply = Reply::status(outcome.status);
    let body = outcome.body.map(|b| b.to_string()).unwrap_or_default();
    if !body.is_empty() {
        reply.headers.push(("content-type".into(), "application/json".into()));
    }
    reply.headers.push(("content-length".into(), body.len().to_string()));
    if let Some(session) = outcome.session {
        reply.headers.push(("Mcp-Session-Id".into(), session));
    }
    if let Some(origin) = origin {
        reply.headers.extend(cors(state, request, origin));
    }
    reply.body = body.into();
    reply.close = !request.keep_alive;
    reply
}

/// `McpStreamableHttpHandler.addCorsHeaders` for a request with an `Origin`: none unless the control-plane origin
/// policy allows it (`CORSOriginPolicy`).
pub fn cors(state: &State, request: &HttpRequest, origin: String) -> Vec<(String, String)> {
    if !crate::cors_origin::allowed_by_config(&state.config, Some(&origin), crate::cors_origin::request_host(request).as_deref()) {
        return Vec::new();
    }
    let requested = request.first_header("access-control-request-headers").filter(|h| !h.is_empty());
    vec![
        ("access-control-allow-origin".into(), origin),
        ("access-control-allow-methods".into(), crate::reply::DEFAULT_CORS_METHODS.into()),
        ("access-control-allow-headers".into(), requested.unwrap_or(crate::reply::DEFAULT_CORS_HEADERS).into()),
        ("access-control-expose-headers".into(), format!("Mcp-Session-Id, {}", crate::reply::DEFAULT_CORS_HEADERS)),
        ("access-control-max-age".into(), "300".into()),
    ]
}

/// What an MCP request is answered with (`McpRequestProcessor.McpResult`): status, JSON body, new session id.
pub struct McpResult {
    pub status: u32,
    pub body: Option<String>,
    pub session: Option<String>,
}

/// The MCP exchange without its transport framing, as the HTTP/3 handler writes it.
pub async fn result(state: &Arc<State>, request: &HttpRequest) -> McpResult {
    let origin = request.first_header("origin").filter(|o| !o.is_empty());
    // `authenticateRequest`: authentication only; tools are authorized one by one.
    let authenticated = || crate::auth::authenticate(state, request).ok();
    let outcome = match request.method.as_str() {
        // `isControlPlaneOriginRefused`: a browser origin the control plane does not allow, built by hand
        _ if crate::cors_origin::is_refused(request, &state.config) => with_body(
            403,
            json!({"jsonrpc": "2.0", "error": {"code": INVALID_REQUEST, "message": crate::cors_origin::REFUSED_MESSAGE}, "id": null}),
        ),
        "OPTIONS" if origin.is_some() => empty(200),
        "POST" | "GET" | "DELETE" => match authenticated() {
            // `authenticateRequest` builds this body by hand: `jsonrpc` first, unlike `JsonRpcMessage`'s alphabetical order.
            None => with_body(401, json!({"jsonrpc": "2.0", "error": {"code": INVALID_REQUEST, "message": "Unauthorized for control plane"}, "id": null})),
            Some(scopes) if request.method == "POST" => post(state, request, &scopes).await,
            Some(_) if request.method == "GET" => empty(405),
            Some(_) => match request.first_header("mcp-session-id") {
                Some(id) if state.mcp.remove(id) => empty(200),
                _ => empty(404),
            },
        },
        _ => with_body(405, error(&Value::Null, INVALID_REQUEST, "Method not allowed")),
    };
    McpResult { status: outcome.status, body: outcome.body.map(|b| b.to_string()).filter(|b| !b.is_empty()), session: outcome.session }
}

/// A parsed JSON-RPC request (`parseJsonRpcRequest`); `None` when it is not a valid one.
struct Rpc {
    method: String,
    params: Option<Value>,
    id: Value,
    notification: bool,
}

fn parse_rpc(node: &Value) -> Option<Rpc> {
    let o = node.as_object()?;
    if o.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return None;
    }
    let method = o.get("method").and_then(Value::as_str).filter(|m| !m.is_empty())?.to_string();
    let id = o.get("id").cloned().unwrap_or(Value::Null);
    match &id {
        Value::Null | Value::String(_) => {}
        Value::Number(n) if n.as_i64().is_some() => {}
        _ => return None,
    }
    Some(Rpc { method, params: o.get("params").filter(|p| !p.is_null()).cloned(), id, notification: !o.contains_key("id") })
}

/// `sessionRejectionStatus`.
fn session_rejection(state: &State, session: Option<&str>) -> Option<(u32, &'static str)> {
    match session.map(str::trim).filter(|s| !s.is_empty()) {
        None => Some((400, "Missing Mcp-Session-Id header. Call 'initialize' first.")),
        Some(id) if state.mcp.with(Some(id), |_| ()).is_none() => Some((404, "Unknown or terminated Mcp-Session-Id. Start a new session by calling 'initialize'.")),
        Some(_) => None,
    }
}

fn initialized(state: &State, session: Option<&str>) -> bool {
    state.mcp.with(session, |s| s.initialized).unwrap_or(false)
}

const NOT_INITIALIZED: &str = "MCP session has not completed initialization. Send the 'notifications/initialized' notification first.";

/// `handlePost`.
async fn post(state: &Arc<State>, request: &HttpRequest, scopes: &[String]) -> Outcome {
    // The Netty handler reads the content as UTF-8, whatever its type.
    let body = String::from_utf8_lossy(&request.body);
    if body.is_empty() {
        return with_body(400, error(&Value::Null, PARSE_ERROR, "Empty request body"));
    }
    let node: Value = match crate::json::parse_lenient(body.as_bytes()) {
        Ok(v) => v,
        Err(_) => return with_body(400, error(&Value::Null, PARSE_ERROR, "Parse error")),
    };
    let session = request.first_header("mcp-session-id");
    match &node {
        Value::Array(items) => batch(state, items, session, scopes).await,
        Value::Object(_) => single(state, &node, session, scopes).await,
        _ => with_body(400, error(&Value::Null, PARSE_ERROR, "Invalid JSON-RPC message")),
    }
}

async fn single(state: &Arc<State>, node: &Value, session: Option<&str>, scopes: &[String]) -> Outcome {
    let Some(rpc) = parse_rpc(node) else { return with_body(400, error(&Value::Null, INVALID_REQUEST, "Invalid JSON-RPC request")) };
    if rpc.notification {
        if let Some((status, _)) = session_rejection(state, session) {
            return empty(status);
        }
        if rpc.method != "notifications/initialized" && !initialized(state, session) {
            return empty(400);
        }
        notification(state, &rpc, session);
        return empty(202);
    }
    if rpc.method == "initialize" {
        let (result, id) = initialize(state, &rpc);
        return Outcome { status: 200, body: Some(result), session: Some(id) };
    }
    if let Some((status, message)) = session_rejection(state, session) {
        return with_body(status, error(&rpc.id, INVALID_REQUEST, message));
    }
    if rpc.method != "ping" && !initialized(state, session) {
        return with_body(400, error(&rpc.id, INVALID_REQUEST, NOT_INITIALIZED));
    }
    with_body(200, process(state, &rpc, session, scopes).await)
}

async fn batch(state: &Arc<State>, items: &[Value], session: Option<&str>, scopes: &[String]) -> Outcome {
    if items.is_empty() {
        return with_body(400, error(&Value::Null, INVALID_REQUEST, "Invalid Request: batch must not be empty"));
    }
    if let Some((status, message)) = session_rejection(state, session) {
        return with_body(status, error(&Value::Null, INVALID_REQUEST, message));
    }
    let mut responses = Vec::new();
    let mut all_notifications = true;
    for item in items {
        let Some(rpc) = parse_rpc(item) else {
            responses.push(error(&Value::Null, INVALID_REQUEST, "Invalid JSON-RPC request"));
            all_notifications = false;
            continue;
        };
        if rpc.method == "initialize" {
            responses.push(error(&rpc.id, INVALID_REQUEST, "The 'initialize' method must be sent as a single request, not inside a batch."));
            all_notifications = false;
            continue;
        }
        if rpc.notification {
            if rpc.method == "notifications/initialized" || initialized(state, session) {
                notification(state, &rpc, session);
            }
            continue;
        }
        all_notifications = false;
        if rpc.method != "ping" && !initialized(state, session) {
            responses.push(error(&rpc.id, INVALID_REQUEST, NOT_INITIALIZED));
            continue;
        }
        responses.push(process(state, &rpc, session, scopes).await);
    }
    if all_notifications { empty(202) } else { with_body(200, Value::Array(responses)) }
}

fn notification(state: &State, rpc: &Rpc, session: Option<&str>) {
    if rpc.method == "notifications/initialized" {
        state.mcp.with(session, |s| s.initialized = true);
    }
}

/// `handleInitialize`: a new session, the negotiated protocol version, the capabilities and server info.
fn initialize(state: &State, rpc: &Rpc) -> (Value, String) {
    let requested = rpc.params.as_ref().and_then(|p| p.get("protocolVersion")).and_then(|v| match v {
        Value::String(s) => Some(s.clone()),
        Value::Null => None,
        other => Some(other.to_string()),
    });
    let version = requested.filter(|v| SUPPORTED_PROTOCOL_VERSIONS.contains(&v.as_str())).unwrap_or_else(|| LATEST_PROTOCOL_VERSION.into());
    let id = state.mcp.create(state, version.clone());
    let result = json!({
        "protocolVersion": version,
        "capabilities": {
            "tools": {"listChanged": false},
            "resources": {"subscribe": false, "listChanged": false},
            "prompts": {"listChanged": false},
            "sampling": {},
        },
        "serverInfo": {"name": "MockServer", "version": crate::control::VERSION},
        "instructions": INSTRUCTIONS,
    });
    (response(&rpc.id, result), id)
}

/// `processRequest`.
async fn process(state: &Arc<State>, rpc: &Rpc, session: Option<&str>, scopes: &[String]) -> Value {
    let id = &rpc.id;
    let params = rpc.params.as_ref();
    let text = |p: Option<&Value>, k: &str| p.and_then(|p| p.get(k)).filter(|v| !v.is_null()).map(|v| v.as_str().map_or_else(|| v.to_string(), str::to_string));
    match rpc.method.as_str() {
        "initialize" => initialize(state, rpc).0,
        "ping" => response(id, json!({})),
        "tools/list" => response(id, json!({"tools": tools::catalogue()})),
        "tools/call" => {
            let Some(p) = params else { return error(id, INVALID_PARAMS, "Missing params") };
            let Some(name) = text(Some(p), "name") else { return error(id, INVALID_PARAMS, "Missing tool name") };
            if !tools::exists(&name) {
                return error(id, METHOD_NOT_FOUND, &format!("Unknown tool: {name}"));
            }
            // `controlPlaneToolAuthorized`: a mutating tool needs MUTATE, a reading one READ.
            let read = !tools::is_mutating(&name);
            if state.config.bool_property("controlPlaneAuthorizationEnabled", false) && !crate::auth::authorized(&state.config, scopes, read) {
                if state.info_enabled() {
                    let granted: Vec<&str> = crate::auth::granted_roles(&state.config, scopes).into_iter().map(|r| crate::auth::ROLES[r]).collect();
                    let reason = format!("principal granted roles [{}] do not satisfy required role {} for tool {name}", granted.join(", "), if read { "READ" } else { "MUTATE" });
                    state.log.message(crate::recorded::LogEntry::new(crate::recorded::Kind::Info, "control plane tool call forbidden:{}").args([&reason]));
                }
                return error(id, INVALID_REQUEST, "Forbidden for control plane");
            }
            let arguments = p.get("arguments").cloned().unwrap_or_else(|| json!({}));
            let result = tools::call(state, &name, &arguments).await;
            if crate::metrics::enabled(&state.config) {
                state.config.metrics.mcp_tool_call(&name);
            }
            let text = crate::json::pretty(&result);
            let mut o = Map::new();
            o.insert("content".into(), json!([{"type": "text", "text": text}]));
            let structured = state.mcp.with(session, |s| s.protocol_version.as_str() >= "2025-06-18").unwrap_or(false);
            if structured && result.is_object() {
                o.insert("structuredContent".into(), result.clone());
            }
            let is_error = matches!(result.get("error"), Some(Value::Bool(true))) || result.get("error").and_then(Value::as_str) == Some("true");
            o.insert("isError".into(), json!(is_error));
            response(id, Value::Object(o))
        }
        "resources/list" => response(id, json!({"resources": RESOURCES.iter().map(|(uri, name, description, mime)| json!({"uri": uri, "name": name, "description": description, "mimeType": mime})).collect::<Vec<_>>()})),
        "resources/read" => {
            let Some(p) = params else { return error(id, INVALID_PARAMS, "Missing params") };
            let Some(uri) = text(Some(p), "uri") else { return error(id, INVALID_PARAMS, "Missing resource URI") };
            let Some((_, _, _, mime)) = RESOURCES.iter().find(|(u, ..)| *u == uri) else {
                return error(id, INVALID_PARAMS, &format!("Unknown resource: {uri}"));
            };
            let content = read_resource(state, &uri).await;
            response(id, json!({"contents": [{"uri": uri, "mimeType": mime, "text": crate::json::pretty(&content)}]}))
        }
        "prompts/list" => response(
            id,
            json!({"prompts": PROMPTS.iter().map(|p| json!({
                "name": p.name,
                "description": p.description,
                "arguments": p.arguments.iter().map(|(n, d)| json!({"name": n, "description": d, "required": true})).collect::<Vec<_>>(),
            })).collect::<Vec<_>>()}),
        ),
        "prompts/get" => {
            let Some(p) = params else { return error(id, INVALID_PARAMS, "Missing params") };
            let Some(name) = text(Some(p), "name") else { return error(id, INVALID_PARAMS, "Missing prompt name") };
            let Some(prompt) = PROMPTS.iter().find(|pr| pr.name == name) else { return error(id, INVALID_PARAMS, &format!("Unknown prompt: {name}")) };
            let missing = missing_arguments(prompt, p.get("arguments"));
            if !missing.is_empty() {
                // `MissingPromptArgumentsException`, answered with `data.missingArguments`
                let message = format!("Missing required argument{} for prompt '{name}': {}", if missing.len() == 1 { "" } else { "s" }, missing.join(", "));
                return json!({"error": {"code": INVALID_PARAMS, "data": {"missingArguments": missing}, "message": message}, "id": id, "jsonrpc": "2.0"});
            }
            let text = substitute(prompt.template, p.get("arguments"));
            response(id, json!({"description": prompt.description, "messages": [{"role": "user", "content": {"type": "text", "text": text}}]}))
        }
        "sampling/createMessage" => {
            let Some(p) = params else { return error(id, INVALID_PARAMS, "Missing params") };
            if !p.get("messages").and_then(Value::as_array).is_some_and(|m| !m.is_empty()) {
                return error(id, INVALID_PARAMS, "'messages' must be a non-empty array");
            }
            let text = text(Some(p), "mockResponse").unwrap_or_else(|| "This is a mocked completion from MockServer's sampling/createMessage handler.".into());
            let model = p.pointer("/modelPreferences/hints/0/name").and_then(Value::as_str).filter(|n| !n.is_empty()).unwrap_or("mock-llm");
            response(id, json!({"role": "assistant", "content": {"type": "text", "text": text}, "model": model, "stopReason": "endTurn"}))
        }
        other => error(id, METHOD_NOT_FOUND, &format!("Method not found: {other}")),
    }
}

/// `McpResourceRegistry`: uri, name, description, MIME type.
const RESOURCES: &[(&str, &str, &str, &str)] = &[
    ("mockserver://expectations", "Active Expectations", "All currently active expectations configured in MockServer", "application/json"),
    ("mockserver://requests", "Recorded Requests", "Recent recorded requests received by MockServer (last 50)", "application/json"),
    ("mockserver://logs", "Server Logs", "Recent MockServer log entries", "text/plain"),
    ("mockserver://configuration", "Server Configuration", "Current MockServer configuration properties", "application/json"),
    ("mockserver://unmatched", "Unmatched Requests", "Recent requests that matched no expectation, with ranked closest-expectation diagnostics and remediation hints", "application/json"),
];

/// A control-plane call made on the server's behalf (`httpState.retrieve`, …): the reply's body as text.
pub async fn internal(state: &Arc<State>, method: &str, path: &str, body: &str) -> (u32, String) {
    internal_now(state, method, path, body)
}

/// `httpState.retrieve(...)` as a tool calls it, as JSON with `filter` as the body: logged like any retrieve. The
/// tools read the answer from the event log themselves.
pub(crate) fn logged_retrieve(state: &Arc<State>, kind: &str, filter: Option<&Value>) {
    internal_now(state, "PUT", &format!("/mockserver/retrieve?type={kind}&format=JSON"), &filter.map(Value::to_string).unwrap_or_default());
}

/// [`internal`] for synchronous callers.
pub fn internal_now(state: &Arc<State>, method: &str, path: &str, body: &str) -> (u32, String) {
    let (path, query) = path.split_once('?').map_or((path, None), |(p, q)| (p, Some(q)));
    let request = HttpRequest {
        method: method.into(),
        path: path.into(),
        query: query.map(crate::request::parse_query).unwrap_or_default(),
        raw_query: query.map(str::to_string),
        body: body.as_bytes().to_vec().into(),
        keep_alive: true,
        trusted: true,
        ..HttpRequest::default()
    };
    match crate::control::route(state, &request) {
        Some(reply) => (reply.status, String::from_utf8_lossy(&reply.body).into_owned()),
        None => (404, String::new()),
    }
}

/// `McpResourceRegistry.readResource`.
async fn read_resource(state: &Arc<State>, uri: &str) -> Value {
    let parsed = |body: &str, empty: Value| if body.is_empty() { empty } else { serde_json::from_str(body).unwrap_or(Value::Null) };
    match uri {
        "mockserver://expectations" => parsed(&internal(state, "PUT", "/mockserver/retrieve?type=ACTIVE_EXPECTATIONS&format=JSON", "").await.1, json!([])),
        "mockserver://requests" => {
            let mut v = parsed(&internal(state, "PUT", "/mockserver/retrieve?type=REQUESTS&format=JSON", "").await.1, json!([]));
            if let Value::Array(items) = &mut v && items.len() > 50 {
                let skip = items.len() - 50;
                items.drain(..skip);
            }
            v
        }
        "mockserver://logs" => json!({"logs": internal(state, "PUT", "/mockserver/retrieve?type=LOGS&format=JSON", "").await.1}),
        // `McpResourceRegistry.readConfiguration`: `HttpState`'s configuration, which a `PUT /mockserver/configuration`
        // now reaches (upstream 0e8566814; the 8.0.0 process kept its startup values).
        "mockserver://configuration" => {
            let effective = crate::config::effective_json(&state.config);
            json!({"maxExpectations": effective["maxExpectations"], "maxLogEntries": effective["maxLogEntries"]})
        }
        _ => {
            let (status, body) = internal(state, "PUT", "/mockserver/explainUnmatched", r#"{"limit":20}"#).await;
            if status == 200 && !body.is_empty() {
                serde_json::from_str(&body).unwrap_or(Value::Null)
            } else if status == 404 {
                json!({"error": "Failed to read unmatched requests"})
            } else {
                json!({"unmatchedRequestCount": 0, "unmatchedRequests": []})
            }
        }
    }
}

struct Prompt {
    name: &'static str,
    description: &'static str,
    arguments: &'static [(&'static str, &'static str)],
    template: &'static str,
}

/// `McpPromptRegistry.FACTS_THEN_INTERPRETATION`: appended to every diagnosis prompt.
macro_rules! facts_then_interpretation {
    () => {
        "\n\nAnswer in two separate sections. Under the heading \"Facts from MockServer\", list only values copied from the tool results (status codes, counts, field names, differences and error text), each with the name of the tool that returned it, without rewording them. If a tool returned an error or nothing, say so there instead of guessing. Under the heading \"Interpretation\", give your explanation and the change you suggest, and present nothing in that section as MockServer output."
    };
}

/// `McpPromptRegistry`: every argument is required.
const PROMPTS: &[Prompt] = &[
    Prompt {
        name: "debug_unmatched_request",
        description: "Guides debugging of a request that matched no MockServer expectation",
        arguments: &[("method", "HTTP method of the request that did not match"), ("path", "Path of the request that did not match")],
        template: concat!(
            "A {{method}} request to {{path}} did not match any MockServer expectation. Call the 'explain_unmatched_requests' tool, then summarise the closest expectation and the field-level differences, and suggest a fix.",
            facts_then_interpretation!()
        ),
    },
    Prompt {
        name: "why_did_verify_fail",
        description: "Explains why a MockServer request verification failed, from the verification result and the requests MockServer received",
        arguments: &[("method", "HTTP method of the request that was verified"), ("path", "Path of the request that was verified")],
        template: concat!(
            "A MockServer verification of {{method}} {{path}} failed. Work through these steps in order.\n",
            "1. Call 'verify_request' with method \"{{method}}\" and path \"{{path}}\", and with the atLeast and atMost counts the failing check used if you know them. Its \"message\" states how many matching requests were expected and found, then the requests MockServer received (or how many there were) and, when any were received, a \"closest match diff\" naming each field of the closest request that differed. It is evaluated against the requests recorded now, so it also counts any that arrived after the original check ran. If the failing verification also matched headers, query parameters or a body, call 'raw_verify' with the full verification JSON instead.\n",
            "2. Call 'retrieve_recorded_requests' with method \"{{method}}\" to see every {{method}} request MockServer received, and compare their paths, headers and bodies with what was verified.\n",
            "3. If no request reached MockServer at all, call 'get_status' to confirm it is running and which ports it listens on, then call 'retrieve_logs' to look for errors.\n",
            "Then say whether the code under test sent a different request, sent it a different number of times, or the verification itself expects the wrong thing, and suggest the change.",
            facts_then_interpretation!()
        ),
    },
    Prompt {
        name: "fix_my_expectation",
        description: "Finds the smallest change that makes an existing MockServer expectation match a request, starting from the fix MockServer suggests, and applies it only once the user agrees",
        arguments: &[("method", "HTTP method of the request the expectation should match"), ("path", "Path of the request the expectation should match")],
        template: concat!(
            "A {{method}} request to {{path}} is not getting the response the user expects from MockServer. Work through these steps in order.\n",
            "1. Call 'suggest_expectation_fix' with limit 20, adding \"expectationId\" if the user named the expectation they meant. It covers only requests that reached MockServer and matched nothing. Use only the entries in \"unmatchedRequests\" whose \"method\" and \"path\" are {{method}} and {{path}}; each lists close expectations by \"expectationId\", each with a \"suggestedFix\": a \"patch\" (an RFC 6902 JSON patch of the expectation as 'list_expectations' returns it, each change preceded by a \"test\" of the current value), the \"unpatchedFields\" it could not patch with the reason for each, and \"matchesAfterPatch\". Nothing is applied.\n",
            "2. Call 'list_expectations' and take the full JSON of the expectation the user meant (normally the first one with a suggested fix) by its id.\n",
            "3. If there is no suggested fix for that expectation (a \"suggestedFixCount\" of 0 with a \"note\" means the request may not have been sent or may have matched another expectation; a fix is suggested only for the five closest expectations), or its \"matchesAfterPatch\" is false, or \"unpatchedFields\" lists fields, call 'debug_request_mismatch' with method \"{{method}}\" and path \"{{path}}\", adding the request's headers and body if the user gave them. It returns one result per active expectation, closest first, each with its \"expectationId\", whether it \"matches\", the \"differences\" per field and a \"remediation\" hint. If an expectation the user did not mean also matches, it may be the one answering the request: say so.\n",
            "Propose the change: the suggested patch applied to the expectation's JSON when there is one, plus the smallest hand-made change to any field it left unpatched, or only a hand-made change when no fix was suggested. Show each changed field with its old and new value and say which changes MockServer suggested. Do not apply it until the user agrees. Then call 'raw_expectation' with the corrected expectation, keeping its \"id\" so it replaces the original rather than adding a second one, and call 'debug_request_mismatch' again to confirm that it now matches.",
            facts_then_interpretation!()
        ),
    },
    Prompt {
        name: "why_forward_failed",
        description: "Explains why MockServer could not forward or proxy a request, from the failed forwards MockServer recorded and the forward expectation",
        arguments: &[("method", "HTTP method of the request that failed to forward"), ("path", "Path of the request that failed to forward")],
        template: concat!(
            "A {{method}} request to {{path}} that MockServer should have forwarded or proxied failed. Work through these steps in order.\n",
            "1. Call 'explain_forward_failure' with limit 20. It returns \"forwardFailures\", most recent first, each with its \"correlationId\", \"method\", \"path\", \"statusCode\" (502) and \"reason\"; use the ones whose method and path are {{method}} and {{path}}. When \"causeNamed\" is true, the reason is the cause MockServer named and what to change (for example a TLS failure, an HTTP/2 error, a connection it could not set up, an upstream response it could not decode, an unresolvable host, or a refused or timed-out connection), and it is also the 502 body. When \"forwardLoopSuspected\" is true, the forward went back to MockServer itself. When \"causeNamed\" is false, the reason is the raw error: call 'retrieve_logs' with that \"correlationId\" to see the request's whole lifecycle, including any exception logged for it.\n",
            "2. Call 'list_expectations' with path \"{{path}}\" to find the expectation that forwarded it and note its target host, port and scheme. If none matches, MockServer was acting as a proxy and sent the request to the host the request itself named.\n",
            "3. If \"forwardFailureCount\" is 0, or no failure has this method and path, call 'retrieve_request_responses' with method \"{{method}}\" and path \"{{path}}\" to see what MockServer sent back: a response other than a 502 means the forward did not fail inside MockServer. MockServer records failed forwards only when its logLevel is INFO or more detailed (the default is INFO), and drops the oldest log entries beyond maxLogEntries, so if neither tool shows the request, report that instead of guessing a cause.\n",
            "Then name the most likely cause and the change to make: to the forward target, the upstream service, MockServer's TLS or proxy settings, or the network between them.",
            facts_then_interpretation!()
        ),
    },
    Prompt {
        name: "create_mock_from_description",
        description: "Turns a natural-language description of an endpoint into a MockServer expectation",
        arguments: &[("description", "Plain-language description of the endpoint to mock")],
        template: concat!(
            "Create a MockServer expectation for this endpoint: {{description}}\n\n",
            "Use 'create_expectation' when the description needs only a method, a path, a status code, a response body, response headers, a match count (times), a time to live or a chaos (fault injection) profile; it accepts no other parameters. When the request must also match on headers, query parameters, cookies or a body, or the response needs a delay or a template, use 'raw_expectation' with the full expectation JSON (an object with \"httpRequest\" and \"httpResponse\").\n",
            "If the tool returns an error, read its \"message\" and, when present, its \"unknownParameters\" or \"validationErrors\": each names the exact field to fix. Correct only those fields and call the tool again; do not drop details from the description to make the error go away.\n",
            "Then call 'list_expectations' with the same method and path to confirm the expectation is active. Report the expectation id the tool returned, then list separately every detail you assumed because the description did not state it (for example the status code or the content type)."
        ),
    },
];

/// `missingRequiredArguments`: each argument absent or null (all are required), when `arguments` is not an object
/// every one of them.
fn missing_arguments(prompt: &Prompt, arguments: Option<&Value>) -> Vec<&'static str> {
    let args = arguments.and_then(Value::as_object);
    prompt.arguments.iter().map(|(n, _)| *n).filter(|n| args.and_then(|a| a.get(*n)).is_none_or(Value::is_null)).collect()
}

/// `applySubstitutions`: `{{name}}` becomes the argument's text (a non-string as its JSON); unknown names stay.
fn substitute(template: &str, arguments: Option<&Value>) -> String {
    let Some(Value::Object(args)) = arguments else { return template.to_string() };
    let placeholder = regex::Regex::new(r"\{\{([A-Za-z0-9_]+)}}").expect("placeholder pattern");
    placeholder
        .replace_all(template, |c: &regex::Captures| match args.get(&c[1]) {
            Some(Value::String(s)) => s.clone(),
            Some(v) => v.to_string(),
            None => c[0].to_string(),
        })
        .into_owned()
}
