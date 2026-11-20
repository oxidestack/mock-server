//! `PUT /mockserver/contractTest` (`HttpState.handleContractTest` over `OpenApiContractTest.runContractTests`): each
//! operation of an OpenAPI spec gets an example request, sent to `baseUrl` through the forwarding client (the
//! `replayHandler`, i.e. `NettyHttpClient.sendRequest`), and its response is validated against the operation.
//!
//! The example requests are the MCP `run_contract_test` tool's (`mcp::spec_tools::example_request`), plus the
//! cookies that tool never sends; the transport differs (the tool uses `HttpURLConnection`).

use crate::reply::Reply;
use crate::request::HttpRequest;
use crate::state::State;
use serde_json::{json, Map, Value};
use std::sync::Arc;

/// Answers `PUT /mockserver/contractTest` (and its bare alias); `None` for any other request.
pub async fn route(state: &Arc<State>, request: &HttpRequest) -> Option<Reply> {
    if request.method != "PUT" || !matches!(request.path.as_str(), "/mockserver/contractTest" | "/contractTest") {
        return None;
    }
    if let Some(reply) = crate::auth::control_plane_refusal(state, request) {
        return Some(reply);
    }
    Some(handle(state, request).await)
}

fn error(status: u32, message: &str) -> Reply {
    Reply::api_body(status, "application/json", format!("{{\"error\":{}}}", Value::String(message.into())))
}

/// `JsonNode.asText()` of a field, `None` for a missing or `null` one: an object or array reads as `""`.
fn text_or_null(root: &Value, key: &str) -> Option<String> {
    match root.get(key)? {
        Value::Null => None,
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Array(_) | Value::Object(_) => Some(String::new()),
    }
}

fn blank(s: &Option<String>) -> bool {
    s.as_deref().is_none_or(|s| s.trim().is_empty())
}

async fn handle(state: &Arc<State>, request: &HttpRequest) -> Reply {
    let body = request.body_json_or_xml_str();
    if body.trim().is_empty() {
        return error(400, "request body is required — must be a JSON document with a \"spec\" (URL or inline spec) and a \"baseUrl\"");
    }
    let root = match crate::json::parse_lenient(body.as_bytes()) {
        Ok(v) => v,
        Err(e) => {
            // `readTree`'s exception message: Jackson's text where it is known, else the parser's own.
            let message = crate::jackson_syntax::syntax_error(&body)
                .and_then(|t| t.split_once(": ").map(|(_, m)| m.to_string()))
                .unwrap_or_else(|| e.to_string());
            return failed(state, request, &message);
        }
    };
    let mut spec = text_or_null(&root, "spec");
    if blank(&spec) {
        spec = text_or_null(&root, "specUrlOrPayload");
    }
    let base_url = text_or_null(&root, "baseUrl");
    let filter = text_or_null(&root, "operationId");
    let Some(spec) = spec.filter(|s| !s.trim().is_empty()) else {
        return error(400, "request body must contain a \"spec\" — a URL, file path, or inline OpenAPI spec");
    };
    let Some(base_url) = base_url.filter(|s| !s.trim().is_empty()) else {
        return error(400, "request body must contain a \"baseUrl\" — the base URL of the service under test");
    };
    let target = match crate::java_uri::parse(base_url.trim()) {
        Ok(t) => t,
        Err(e) => return error(400, &format!("invalid baseUrl: {e}")),
    };
    let Some(host) = target.host.clone().filter(|h| !h.trim().is_empty()) else {
        return error(400, "baseUrl must include a host e.g. http://localhost:8080");
    };
    // SSRF protection: the policy of the forward and replay paths.
    if let Some(reason) = crate::ws_relay::blocked(state, &host).await {
        let entry = crate::recorded::LogEntry::new(crate::recorded::Kind::Warn, "contract test blocked by SSRF policy:{}").args([reason.clone()]);
        crate::log::warn_event(state, entry);
        return error(403, &format!("contract test blocked by SSRF policy: {reason}"));
    }
    let https = target.scheme.as_deref().is_some_and(|s| s.eq_ignore_ascii_case("https"));
    let port = if target.port != -1 { target.port } else if https { 443 } else { 80 };
    let context_path = match target.raw_path.as_deref() {
        Some(p) if p != "/" => p.strip_suffix('/').unwrap_or(p).to_string(),
        _ => String::new(),
    };
    let sender = Sender { host, port, https, context_path };
    // `runOffTheEventLoop` refused by a shut-down scheduler (fe354ebd5)
    if state.scheduler_is_shut_down() {
        return error(503, "unable to schedule contract test: MockServer is stopping");
    }

    let openapi = match crate::openapi::checking_spec_fetches(&state.config, || crate::mcp::spec_tools::model(&spec)) {
        Ok(m) => m,
        Err(e) => return failed(state, request, &e),
    };
    let definitions = openapi.get_components().and_then(|c| c.get_schemas());
    let mut results = Vec::new();
    for (template, item) in openapi.get_paths().map(|p| p.entries()).unwrap_or_default() {
        for (method, operation) in crate::openapi_expectations::map_operations(&item) {
            let operation_id = operation.get_operation_id();
            if filter.as_deref().is_some_and(|f| !f.trim().is_empty() && operation_id.as_deref() != Some(f)) {
                continue;
            }
            let example = crate::mcp::spec_tools::example_request(
                definitions.as_ref(),
                method,
                &template,
                &operation,
                state.config.bool_property("generateRealisticExampleValues", false),
            );
            let id = operation_id.clone().unwrap_or_default();
            let (status, errors) = match sender.send(state, &example).await {
                Ok((status, headers, body)) => {
                    let response = crate::openapi_validation::Response { status, headers: &headers, body: &body };
                    (status, crate::openapi::checking_spec_fetches(&state.config, || crate::openapi_validation::validate_response(&spec, &id, &response)))
                }
                Err(cause) => {
                    // `OpenAPIValidationErrors.unexpectedError` over the sender's `RuntimeException`.
                    let context = format!("contract test for operation {id} ({} {template})", method.to_ascii_uppercase());
                    crate::log::warn(state, &format!("exception while {context}"));
                    let message = format!("failed to send contract-test request to {base_url}: {cause}");
                    (0, vec![format!("{context} failed: RuntimeException: {}", bounded_single_line(&message))])
                }
            };
            results.push(json!({
                "operationId": operation_id,
                "method": method,
                "path": template,
                "statusCodeReceived": status,
                "passed": errors.is_empty(),
                "validationErrors": errors,
            }));
        }
    }
    let passed = results.iter().filter(|r| r["passed"] == Value::Bool(true)).count();
    let mut report = Map::new();
    report.insert("baseUrl".into(), json!(base_url));
    report.insert("totalOperations".into(), json!(results.len()));
    report.insert("passed".into(), json!(passed));
    report.insert("failed".into(), json!(results.len() - passed));
    // A run that exercised no operation has verified nothing.
    report.insert("allPassed".into(), json!(!results.is_empty() && passed == results.len()));
    if results.is_empty() {
        let message = match filter.filter(|f| !f.trim().is_empty()) {
            Some(f) => format!("no operation matched operationId \"{f}\" - nothing was verified"),
            None => "the specification declares no operations to test - nothing was verified".to_string(),
        };
        report.insert("error".into(), json!(message));
    }
    report.insert("results".into(), Value::Array(results));
    Reply::api_body(200, "application/json", crate::json::pretty(&Value::Object(report)))
}

/// The handler's catch: logged at ERROR, answered `400 {"error": message}`.
fn failed(state: &State, request: &HttpRequest, message: &str) -> Reply {
    let entry = crate::recorded::LogEntry::at(crate::recorded::Level::Error, "exception handling contract test request:{}error:{}");
    crate::log::entry(state, &entry.args([crate::recorded::Arg::from(crate::recorded::logged(request)), message.into()]));
    error(400, message)
}

/// `OpenAPIValidationErrors.boundedSingleLine`: whitespace and control runs collapsed, at most 280 characters.
fn bounded_single_line(text: &str) -> String {
    let mut collapsed = String::new();
    let mut gap = false;
    for c in text.chars() {
        if c.is_whitespace() || c.is_control() {
            gap = true;
        } else {
            if gap && !collapsed.is_empty() {
                collapsed.push(' ');
            }
            gap = false;
            collapsed.push(c);
        }
    }
    if collapsed.chars().count() > 280 {
        let cut: String = collapsed.chars().take(280).collect();
        format!("{cut}...")
    } else {
        collapsed
    }
}

/// The handler's `httpSender`: the example request aimed at the service under test (socket address, `secure`,
/// `Host`, the base URL's path in front), sent through the forwarding client within `maxSocketTimeoutInMillis`.
struct Sender {
    host: String,
    port: i32,
    https: bool,
    context_path: String,
}

impl Sender {
    /// The response's status, headers and (decoded) body, or the message of the exception the send throws.
    async fn send(&self, state: &State, example: &crate::mcp::spec_tools::ExampleRequest) -> Result<(u32, crate::request::MultiMap, String), String> {
        let Ok(port) = u16::try_from(self.port) else { return Err(format!("port out of range:{}", self.port)) };
        let default_port = if self.https { 443 } else { 80 };
        let host_header = if self.port == default_port { self.host.clone() } else { format!("{}:{}", self.host, self.port) };
        let mut headers = Map::new();
        for (name, values) in &example.headers {
            if !name.eq_ignore_ascii_case("host") {
                headers.insert(name.clone(), json!(values));
            }
        }
        headers.insert("host".into(), json!([host_header]));
        let mut query: Map<String, Value> = Map::new();
        for (name, value) in &example.query {
            match query.get_mut(name).and_then(Value::as_array_mut) {
                Some(values) => values.push(json!(value)),
                None => {
                    query.insert(name.clone(), json!([value]));
                }
            }
        }
        let path = if self.context_path.is_empty() { example.path.clone() } else { format!("{}{}", self.context_path, example.path) };
        let mut out = Map::new();
        out.insert("method".into(), json!(example.method));
        out.insert("path".into(), json!(path));
        if !query.is_empty() {
            out.insert("queryStringParameters".into(), Value::Object(query));
        }
        out.insert("headers".into(), Value::Object(headers));
        if !example.cookies.is_empty() {
            out.insert("cookies".into(), Value::Object(example.cookies.iter().map(|(k, v)| (k.clone(), json!(v))).collect()));
        }
        if let Some(body) = &example.body {
            out.insert("body".into(), json!(body));
        }
        out.insert("secure".into(), json!(self.https));
        out.insert("socketAddress".into(), json!({"host": self.host, "port": port, "scheme": if self.https { "HTTPS" } else { "HTTP" }}));
        let timeout = std::time::Duration::from_millis(state.config.int_property("maxSocketTimeoutInMillis", 20_000).max(1) as u64);
        // The future's own `get(timeout)` races the client's read timeout; the client's normally answers first.
        let sent = tokio::time::timeout(timeout + std::time::Duration::from_millis(500), crate::forward::send_json(state, &Value::Object(out))).await;
        match sent {
            Err(_) => Err("TimeoutException".into()),
            // `ExecutionException.getMessage()`: the cause's `toString()`.
            Ok(Err(e)) => Err(e.exception_string()),
            Ok(Ok(response)) => {
                let encoding = response.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("content-encoding")).map(|(_, v)| v.as_str());
                let body = crate::request::decompress(encoding, &response.body).unwrap_or_else(|| response.body.clone());
                let mut headers = crate::request::MultiMap::new();
                for (k, v) in &response.headers {
                    match headers.iter_mut().find(|(n, _)| n == k) {
                        Some((_, values)) => values.push(v.clone()),
                        None => headers.push((k.clone(), vec![v.clone()])),
                    }
                }
                Ok((response.status, headers, String::from_utf8_lossy(&body).into_owned()))
            }
        }
    }
}
