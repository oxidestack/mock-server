//! `McpToolRegistry`'s tools over the expectations and a spec: `list_mock_tools` (`McpToolSchemaGenerator`),
//! `verify_traffic_against_openapi`, `run_contract_test`, `run_resiliency_test` and `run_mcp_contract_test`.

use std::sync::Arc;

use serde_json::{Map, Value, json};

use super::tools::{as_text, error};
use crate::state::State;

// ------------------------------------------------------------------ list_mock_tools

/// A `NottableString` in its canonical form: `!value` when negated.
fn notted(v: Option<&Value>) -> bool {
    match v {
        Some(Value::String(s)) => s.starts_with('!'),
        Some(Value::Object(o)) => o.get("not").and_then(Value::as_bool).unwrap_or(false),
        _ => false,
    }
}

fn nottable_text(v: Option<&Value>, default: &str) -> String {
    match v {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Object(o)) => o.get("value").and_then(Value::as_str).unwrap_or_default().to_string(),
        _ => default.to_string(),
    }
}

/// `McpToolSchemaGenerator.toolName`.
fn mock_tool_name(method: &str, path: &str) -> String {
    let mut name = String::new();
    for c in format!("{method}_{path}").to_lowercase().chars() {
        if c.is_ascii_lowercase() || c.is_ascii_digit() {
            name.push(c);
        } else if !name.ends_with('_') {
            name.push('_');
        }
    }
    let name = name.trim_start_matches('_');
    let name = name.strip_suffix('_').unwrap_or(name);
    let mut name = if name.is_empty() { "tool".to_string() } else { name.to_string() };
    name.truncate(64);
    name
}

/// `handleListMockTools` over `McpToolSchemaGenerator`: one tool per active expectation that answers with a response.
pub async fn list_mock_tools(state: &Arc<State>) -> Value {
    let expectations = crate::control::active_expectations_quiet(state);
    let mut used: Vec<String> = Vec::new();
    let mut tools = Vec::new();
    for e in &expectations {
        let Some(request) = e.get("httpRequest").filter(|r| r.is_object() && r.get("specUrlOrPayload").is_none()) else { continue };
        if notted(request.get("method")) || notted(request.get("path")) {
            continue;
        }
        let responds = e.get("httpResponse").is_some_and(|r| !r.is_null()) || e.get("httpResponses").and_then(Value::as_array).is_some_and(|r| !r.is_empty());
        if !responds {
            continue;
        }
        // An absent method or path is the empty `NottableString`, not null, so the defaults never apply.
        let method = nottable_text(request.get("method"), "");
        let path = nottable_text(request.get("path"), "");
        let base = mock_tool_name(&method, &path);
        let mut candidate = base.clone();
        let mut suffix = 2;
        while used.contains(&candidate) {
            let s = format!("_{suffix}");
            suffix += 1;
            let trimmed = if base.len() + s.len() > 64 { &base[..64 - s.len()] } else { base.as_str() };
            candidate = format!("{trimmed}{s}");
        }
        used.push(candidate.clone());
        let mut properties = Map::new();
        let names: Vec<String> = match request.get("queryStringParameters") {
            Some(Value::Object(o)) => o.keys().cloned().collect(),
            Some(Value::Array(items)) => items.iter().filter_map(|p| p.get("name")).map(|n| nottable_text(Some(n), "")).collect(),
            _ => Vec::new(),
        };
        for name in names.into_iter().filter(|n| !n.starts_with('!')) {
            properties.insert(name, json!({"type": "string", "description": "query parameter"}));
        }
        if request.get("body").is_some_and(|b| !b.is_null()) {
            properties.insert("body".into(), json!({"description": "request body", "anyOf": [{"type": "string"}, {"type": "object"}]}));
        }
        let mut meta = Map::new();
        meta.insert("method".into(), json!(method));
        meta.insert("path".into(), json!(path));
        if let Some(id) = e.get("id") {
            meta.insert("expectationId".into(), id.clone());
        }
        tools.push(json!({
            "name": candidate,
            "description": format!("Mock for {method} {path}"),
            "inputSchema": {"type": "object", "properties": properties},
            "_mockserver": meta,
        }));
    }
    let count = tools.len();
    json!({"tools": tools, "count": count})
}

// ------------------------------------------------------------------ verify_traffic_against_openapi

/// A non-blank `specUrlOrPayload` argument, `asText(null)` (an object spec reads as `""`, so is blank).
fn spec_argument(args: &Value) -> Result<String, Value> {
    as_text(args, "specUrlOrPayload")
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| error("'specUrlOrPayload' is required and must not be blank"))
}

/// `handleVerifyTrafficAgainstOpenApi`: the recorded request-response pairs (filtered by `method`/`path`) validated
/// against the spec.
pub fn verify_traffic_against_openapi(state: &Arc<State>, args: &Value) -> Value {
    let spec = match spec_argument(args) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let mut filter = Map::new();
    for key in ["method", "path"] {
        if let Some(v) = args.get(key).filter(|v| !v.is_null()) {
            filter.insert(key.into(), json!(as_text(args, key).unwrap_or_else(|| v.to_string())));
        }
    }
    let filter = Value::Object(filter);
    super::logged_retrieve(state, "REQUEST_RESPONSES", Some(&filter));
    let matcher = crate::matcher::RequestMatcher::compile(&filter);
    let exchanges: Vec<_> = state.log.matching(Some(&matcher));
    let rendered = crate::control::validation_pairs(&exchanges);
    if rendered.is_empty() {
        return json!({"status": "no_traffic", "message": "No recorded request-response pairs found matching the filter.", "totalPairs": 0, "passed": 0, "failed": 0});
    }
    let pairs: Vec<(crate::request::HttpRequest, crate::openapi_validation::Response)> =
        rendered.iter().map(|(r, h, s, b)| (r.clone(), crate::openapi_validation::Response { status: *s, headers: h, body: b })).collect();
    let report = match crate::openapi::checking_spec_fetches(&state.config, || crate::openapi_validation::traffic_report(&spec, &pairs)) {
        Ok(r) => r,
        Err(_) => return super::llm_tools::failure(state, "Failed to verify traffic against OpenAPI"),
    };
    let mut results = Vec::new();
    let (mut passed, mut failed) = (0, 0);
    for r in report["results"].as_array().cloned().unwrap_or_default() {
        let mut o = Map::new();
        o.insert("method".into(), r["method"].clone());
        o.insert("path".into(), r["path"].clone());
        o.insert("matchedOperation".into(), r["matchedOperation"].clone());
        o.insert("passed".into(), r["passed"].clone());
        for key in ["requestErrors", "responseErrors"] {
            if r[key].as_array().is_some_and(|a| !a.is_empty()) {
                o.insert(key.into(), r[key].clone());
            }
        }
        if r["passed"] == json!(true) {
            passed += 1;
        } else {
            failed += 1;
        }
        results.push(Value::Object(o));
    }
    json!({
        "status": if failed == 0 { "conformant" } else { "non_conformant" },
        "totalPairs": results.len(),
        "passed": passed,
        "failed": failed,
        "results": results,
    })
}

// ------------------------------------------------------------------ run_contract_test / run_resiliency_test

use crate::openapi_examples::{self as examples, Direction};
use jackson::JavaObject;
use swagger_parser::models::{OpenAPI, Operation, Parameter, Schema};

/// A request built from a spec's examples (`OpenApiContractTest.buildExampleRequest`).
#[derive(Clone)]
pub(crate) struct ExampleRequest {
    pub method: String,
    pub path: String,
    pub query: Vec<(String, String)>,
    pub headers: Vec<(String, Vec<String>)>,
    /// `withCookie`: a cookie named again takes the new value. The MCP tools never send them.
    pub cookies: Vec<(String, String)>,
    pub body: Option<String>,
}

/// `OpenApiParameterExamples.getParameterExampleValue`; `realistic` is the static store's
/// `generateRealisticExampleValues` (`OpenApiContractTest` passes no configuration).
fn parameter_example(param: &Parameter, definitions: Option<&swagger_parser::java::JMap<Schema>>, realistic: bool) -> Option<String> {
    if let Some(example) = param.get_example().filter(|e| !matches!(e, JavaObject::Null)) {
        return Some(example.to_java_string());
    }
    if let Some(value) = param.get_examples().and_then(|e| e.values().into_iter().next()).and_then(|e| e.get_value()) {
        return Some(value.to_java_string());
    }
    if let Some(schema) = param.get_schema() {
        if let Some(default) = schema.get_default().filter(|d| !matches!(d, JavaObject::Null)) {
            return Some(default.to_java_string());
        }
        if let Some(first) = schema.get_enum().and_then(|e| e.get(0)) {
            return Some(first.to_java_string());
        }
        if let Some(generated) = examples::from_schema_with(&schema, definitions, None, Direction::Request, realistic) {
            return Some(match &generated.value {
                examples::Value::String(s) => s.clone(),
                _ => examples::to_json(&generated),
            });
        }
    }
    (param.get_required() == Some(true)).then(|| "example".to_string())
}

fn parameters(operation: &Operation) -> Vec<Parameter> {
    operation.get_parameters().map(|p| p.to_vec()).unwrap_or_default()
}

/// The request body's media type: `application/json` when declared, else the first.
fn request_media(operation: &Operation) -> Option<(String, swagger_parser::models::MediaType)> {
    let content = operation.get_request_body()?.get_content()?;
    let map = content.0.read().map.clone();
    if let Some(m) = map.get("application/json") {
        return Some(("application/json".into(), m.clone()));
    }
    map.into_iter().next()
}

/// `generateExampleBody`: the media type's example, else its first named example, else the schema's example, else a
/// generated one, each written by Jackson's pretty printer.
fn example_body(media: &swagger_parser::models::MediaType, definitions: Option<&swagger_parser::java::JMap<Schema>>, realistic: bool) -> Option<String> {
    if let Some(e) = media.get_example().filter(|e| !matches!(e, JavaObject::Null)) {
        return Some(examples::java_object_to_json(&e));
    }
    if let Some(examples_map) = media.get_examples().filter(|e| !e.is_empty()) && let Some(value) = examples_map.values().into_iter().next().and_then(|e| e.get_value()) {
        return Some(examples::java_object_to_json(&value));
    }
    let schema = media.get_schema()?;
    if let Some(e) = schema.get_example().filter(|e| !matches!(e, JavaObject::Null)) {
        return Some(examples::java_object_to_json(&e));
    }
    examples::from_schema_with(&schema, definitions, None, Direction::Request, realistic).map(|g| examples::to_json(&g))
}

/// `buildExampleRequest`: the path with example path parameters, example query and header parameters, and the
/// request body's content type and example; `realistic` as in [`parameter_example`].
pub(crate) fn example_request(
    definitions: Option<&swagger_parser::java::JMap<Schema>>,
    method: &str,
    template: &str,
    operation: &Operation,
    realistic: bool,
) -> ExampleRequest {
    let mut path = template.to_string();
    for p in parameters(operation).iter().filter(|p| p.get_in().as_deref() == Some("path")) {
        let value = parameter_example(p, definitions, realistic).unwrap_or_else(|| "example".into());
        path = path.replace(&format!("{{{}}}", p.get_name().unwrap_or_default()), &value);
    }
    static PLACEHOLDER: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| regex::Regex::new(r"\{[^}]+}").unwrap());
    let path = PLACEHOLDER.replace_all(&path, "example").into_owned();
    let mut request = ExampleRequest { method: method.into(), path, query: Vec::new(), headers: Vec::new(), cookies: Vec::new(), body: None };
    for p in parameters(operation) {
        let name = p.get_name().unwrap_or_default();
        match p.get_in().as_deref() {
            Some("query") => {
                if let Some(v) = parameter_example(&p, definitions, realistic) {
                    request.query.push((name, v));
                }
            }
            Some("header") => {
                if let Some(v) = parameter_example(&p, definitions, realistic) {
                    add_header(&mut request.headers, &name, v);
                }
            }
            // Cookies are set on the request; the MCP tools never send them (`sendHttpRequest` writes only headers).
            Some("cookie") => {
                if let Some(v) = parameter_example(&p, definitions, realistic) {
                    match request.cookies.iter_mut().find(|(n, _)| *n == name) {
                        Some(existing) => existing.1 = v,
                        None => request.cookies.push((name, v)),
                    }
                }
            }
            _ => {}
        }
    }
    if let Some((content_type, media)) = request_media(operation) {
        add_header(&mut request.headers, "content-type", content_type);
        if media.get_schema().is_some() {
            request.body = example_body(&media, definitions, realistic);
        }
    }
    request
}

/// `HttpRequest.withHeader`: a header named again (case-insensitively) takes the new value.
fn add_header(headers: &mut Vec<(String, Vec<String>)>, name: &str, value: String) {
    match headers.iter_mut().find(|(n, _)| n.eq_ignore_ascii_case(name)) {
        Some((_, values)) => *values = vec![value],
        None => headers.push((name.to_string(), vec![value])),
    }
}

/// The target of a `baseUrl`: host, port, scheme and path prefix (without a trailing `/`), or the tool's error.
struct Target {
    host: String,
    port: u16,
    secure: bool,
    base_path: String,
}

/// `new java.net.URI(url)` and the tools' checks on it: `Err(Some(error))` for the tools' own errors, `Err(None)`
/// where upstream throws later (a port `InetSocketAddress` rejects), which fails the tool.
fn target(url: &str, arg: &str) -> Result<Target, Option<Value>> {
    let Some(parts) = crate::import::url_parts(url) else { return Err(Some(error(&format!("'{arg}' is not a valid URL: {url}")))) };
    let Some(host) = parts.host.filter(|h| !h.is_empty()) else {
        return Err(Some(error(&format!("'{arg}' must be an absolute HTTP/HTTPS URL with a hostname: {url}"))));
    };
    let scheme = parts.scheme.unwrap_or_default();
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return Err(Some(error(&format!("'{arg}' must use the http or https scheme: {url}"))));
    }
    let secure = scheme.eq_ignore_ascii_case("https");
    let port = if parts.port == -1 { if secure { 443 } else { 80 } } else { u16::try_from(parts.port).map_err(|_| None)? };
    // `run_mcp_contract_test` posts to the raw path (`/` when empty); the OpenAPI tools prefix the decoded path,
    // less one trailing `/`.
    let base_path = if arg == "targetUrl" {
        parts.raw_path.filter(|p| !p.is_empty()).unwrap_or_else(|| "/".into())
    } else {
        let path = parts.path.unwrap_or_default();
        path.strip_suffix('/').map(str::to_string).unwrap_or(path)
    };
    Ok(Target { host, port, secure, base_path })
}

/// A sent request's answer: status (0 when it could not be sent), headers and body.
struct Answer {
    status: u32,
    headers: crate::request::MultiMap,
    body: String,
}

/// `McpToolRegistry.sendHttpRequest`'s default timeout (connect and read), used by `run_contract_test` and each
/// `run_mcp_contract_test` exchange.
const SEND_TIMEOUT_MILLIS: u64 = 10_000;
/// `handleRunResiliencyTest`'s timeout: malformed input should be answered promptly.
const RESILIENCY_TIMEOUT_MILLIS: u64 = 5_000;
/// `MAX_RESPONSE_BODY_SIZE`: a longer body is cut here and marked.
const MAX_RESPONSE_BODY_SIZE: usize = 10 * 1024 * 1024;

/// `URLEncoder.encode(s, "UTF-8")`: form encoding.
fn form_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'-' | b'*' | b'_' => out.push(b as char),
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// `HttpURLConnection`'s restricted headers: with `sun.net.http.allowRestrictedHeaders` unset (MockServer leaves it
/// so), `setRequestProperty` drops them.
const RESTRICTED_HEADERS: [&str; 12] = [
    "Access-Control-Request-Headers",
    "Access-Control-Request-Method",
    "Connection",
    "Content-Length",
    "Content-Transfer-Encoding",
    "Host",
    "Keep-Alive",
    "Origin",
    "Trailer",
    "Transfer-Encoding",
    "Upgrade",
    "Via",
];

/// `User-Agent: Java/<java.version>` of the oracle image's JDK (26.0.2.1 at b765b8271), as its `HttpURLConnection` sends it.
const JAVA_USER_AGENT: &str = "Java/26.0.2.1";

/// `InetAddress.getHostName()` of a literal address: the reverse-lookup name, kept only when that name resolves back
/// to the address; `None` (the literal stays) otherwise.
fn reverse_lookup(ip: std::net::IpAddr) -> Option<String> {
    use std::net::ToSocketAddrs;
    let address = socket2::SockAddr::from(std::net::SocketAddr::new(ip, 0));
    let mut name = [0 as libc::c_char; 1025];
    // SAFETY: `address` is a valid socket address of `address.len()` bytes; `name` is a writable buffer of the given
    // length, which `getnameinfo` NUL-terminates on success.
    let code = unsafe {
        libc::getnameinfo(address.as_ptr() as *const libc::sockaddr, address.len(), name.as_mut_ptr(), name.len() as libc::socklen_t, std::ptr::null_mut(), 0, libc::NI_NAMEREQD)
    };
    if code != 0 {
        return None;
    }
    // SAFETY: NUL-terminated by a successful `getnameinfo`.
    let name = unsafe { std::ffi::CStr::from_ptr(name.as_ptr()) }.to_string_lossy().into_owned();
    (name.as_str(), 0).to_socket_addrs().ok()?.any(|a| a.ip() == ip).then_some(name)
}

/// `new InetSocketAddress(host, port).getHostName()` (the host of the tools' URL, a TLS forward's upstream): a name as
/// given, a literal address's name by reverse lookup (`127.0.0.1` is `localhost`), else the literal.
pub(crate) async fn url_host(host: &str) -> String {
    let Ok(ip) = host.trim_start_matches('[').trim_end_matches(']').parse::<std::net::IpAddr>() else { return host.to_string() };
    tokio::task::spawn_blocking(move || reverse_lookup(ip)).await.ok().flatten().unwrap_or_else(|| host.to_string())
}

/// `sendHttpRequest` over `java.net.HttpURLConnection`: the request to the target (the base path prepended) on a
/// direct connection, the query form-encoded, the body as UTF-8, and the headers in the order the JDK writes them:
/// each header's first value as set (a name set again keeps its place; the restricted ones dropped), then whichever
/// of `User-Agent`, `Host` (the URL's host, see [`url_host`]), `Accept: */*` and `Connection: keep-alive` is not
/// set, then `Content-Length` for a body. The JDK's form `Content-Type` for a body without one is unreachable (every
/// example body has a content type). The JDK's method rules apply: `setRequestMethod` refuses a method outside
/// [`JDK_METHODS`], and `getOutputStream` sends a `GET` with a body as `POST` and refuses one for `TRACE`; a failure is
/// `connection error: ` and the JDK exception's message ([`jdk_failure`]).
/// `sendToCheckedTarget`: [`send_unchecked`] once the target's host passes the forward target checks again; a
/// refusal is the send's connection error. Redirects are followed unless a forward target check is on
/// (`setInstanceFollowRedirects(!InetAddressValidator.isActive)`): see [`redirect_target`].
async fn send(state: &State, t: &Target, request: &ExampleRequest, timeout_millis: u64) -> Answer {
    if let Some(reason) = crate::ws_relay::blocked(state, &t.host).await {
        return Answer { status: 0, headers: Vec::new(), body: format!("connection error: {reason}") };
    }
    send_unchecked(t, request, timeout_millis, !crate::ws_relay::checks_active(state)).await
}

/// `HttpURLConnection`'s `getRedirectedFrom`/`followRedirect0` on a 301, 302, 303 or 307 with a `Location`: the
/// next request's `(secure, host, port, target)`, `None` when the answer is final (another status, no `Location`, a
/// `Location` that is not an absolute or relative `http`/`https` URL, or one that changes the protocol).
fn redirect_target(secure: bool, host: &str, port: u16, target: &str, status: u32, location: Option<&str>) -> Option<(bool, String, u16, String)> {
    if !matches!(status, 301 | 302 | 303 | 307) {
        return None;
    }
    let location = location?.trim();
    let path_of = |parts: &crate::import::UrlParts| {
        let path = parts.raw_path.clone().filter(|p| !p.is_empty()).unwrap_or_else(|| "/".into());
        match &parts.raw_query {
            Some(q) => format!("{path}?{q}"),
            None => path,
        }
    };
    let default_port = |secure: bool| if secure { 443 } else { 80 };
    if let Some(parts) = crate::import::url_parts(location).filter(|p| p.scheme.is_some() || location.starts_with("//")) {
        let to_secure = match parts.scheme.as_deref() {
            Some(s) if s.eq_ignore_ascii_case("https") => true,
            Some(s) if s.eq_ignore_ascii_case("http") => false,
            Some(_) => return None,
            None => secure,
        };
        if to_secure != secure {
            return None;
        }
        let to_host = parts.host.clone().filter(|h| !h.is_empty())?;
        let to_port = if parts.port == -1 { default_port(secure) } else { u16::try_from(parts.port).ok()? };
        return Some((secure, to_host, to_port, path_of(&parts)));
    }
    let next = if location.starts_with('/') {
        location.to_string()
    } else {
        let current = target.split('?').next().unwrap_or("/");
        let dir = &current[..current.rfind('/').map_or(0, |i| i + 1)];
        format!("{}{location}", if dir.is_empty() { "/" } else { dir })
    };
    Some((secure, host.to_string(), port, next))
}

/// The answer's `Location` header.
fn location_of(headers: &[(String, String)]) -> Option<&str> {
    headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("location")).map(|(_, v)| v.as_str())
}

async fn send_unchecked(t: &Target, request: &ExampleRequest, timeout_millis: u64, follow_redirects: bool) -> Answer {
    let failed = |message: String| Answer { status: 0, headers: Vec::new(), body: format!("connection error: {message}") };
    if !JDK_METHODS.contains(&request.method.as_str()) {
        return failed(format!("Invalid HTTP method: {}", request.method));
    }
    let body = request.body.clone().filter(|b| !b.is_empty()).unwrap_or_default();
    let method = match request.method.as_str() {
        "GET" if !body.is_empty() => "POST".to_string(),
        "TRACE" if !body.is_empty() => return failed("HTTP method TRACE doesn't support output".into()),
        method => method.to_string(),
    };
    let path = if !t.base_path.is_empty() && !request.path.starts_with(&t.base_path) { format!("{}{}", t.base_path, request.path) } else { request.path.clone() };
    let query: Vec<String> = request.query.iter().map(|(k, v)| format!("{}={}", form_encode(k), form_encode(v))).collect();
    let target = if query.is_empty() { path } else { format!("{path}?{}", query.join("&")) };
    let mut headers: Vec<(String, String)> = Vec::new();
    for (name, values) in &request.headers {
        if RESTRICTED_HEADERS.iter().any(|r| r.eq_ignore_ascii_case(name)) {
            continue;
        }
        if let Some(first) = values.first() {
            match headers.iter_mut().find(|(n, _)| n.eq_ignore_ascii_case(name)) {
                Some((_, value)) => *value = first.clone(),
                None => headers.push((name.clone(), first.clone())),
            }
        }
    }
    let (mut secure, mut host, mut port) = (t.secure, t.host.clone(), t.port);
    let (mut method, mut target, mut headers, mut body) = (method, target, headers, body);
    let wait = std::time::Duration::from_millis(timeout_millis);
    let mut redirects = 0;
    loop {
        let name = url_host(&host).await;
        let mut sent = headers.clone();
        let defaults = [
            ("User-Agent", JAVA_USER_AGENT.to_string()),
            ("Host", crate::forward::host_header(&name, port, secure)),
            ("Accept", "*/*".to_string()),
            ("Connection", "keep-alive".to_string()),
        ];
        for (name, value) in defaults {
            if !sent.iter().any(|(n, _)| n.eq_ignore_ascii_case(name)) {
                sent.push((name.into(), value));
            }
        }
        if !body.is_empty() {
            sent.push(("Content-Length".into(), body.len().to_string()));
        }
        let outbound = crate::client::Outbound { method: method.clone(), target: target.clone(), headers: sent, body: body.clone().into_bytes().into(), http2: false, may_stream: false, decoded_body: None };
        match crate::client::send_with_timeout(crate::client::Route::Direct, &host, port, secure, &outbound, wait).await {
            Some(Ok(u)) => {
                if follow_redirects && let Some((next_secure, next_host, next_port, next_target)) = redirect_target(secure, &host, port, &target, u.status, location_of(&u.headers)) {
                    redirects += 1;
                    if redirects >= MAX_REDIRECTS {
                        return failed(format!("Server redirected too many times ({MAX_REDIRECTS})"));
                    }
                    // a POST answered 301, 302 or 303 is repeated as a GET with none of the request's own headers or body
                    if method == "POST" && u.status != 307 {
                        method = "GET".into();
                        body = String::new();
                        headers.clear();
                    }
                    (secure, host, port, target) = (next_secure, next_host, next_port, next_target);
                    continue;
                }
                let mut headers = crate::request::MultiMap::new();
                for (k, v) in u.headers {
                    match headers.iter_mut().find(|(n, _)| *n == k) {
                        Some((_, values)) => values.push(v),
                        None => headers.push((k, vec![v])),
                    }
                }
                let mut body = String::from_utf8_lossy(&u.body[..u.body.len().min(MAX_RESPONSE_BODY_SIZE)]).into_owned();
                if u.body.len() > MAX_RESPONSE_BODY_SIZE {
                    body.push_str(&format!("\n[TRUNCATED: response body exceeded {MAX_RESPONSE_BODY_SIZE} bytes]"));
                }
                return Answer { status: u.status, headers, body };
            }
            Some(Err(e)) => return failed(jdk_failure(&e)),
            None => return failed("Read timed out".into()),
        }
    }
}

/// `HttpURLConnection`'s limit on followed redirects.
const MAX_REDIRECTS: u32 = 20;

/// `HttpURLConnection.setRequestMethod`'s methods; any other throws `ProtocolException`.
const JDK_METHODS: [&str; 7] = ["GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE", "TRACE"];

/// The message of the exception `HttpURLConnection` throws for a failed send: `ConnectException`'s
/// `Connection refused`, `SocketTimeoutException`'s `Connect timed out`/`Read timed out`, `UnknownHostException`'s
/// host; the client's own text for any other.
fn jdk_failure(e: &crate::client::Error) -> String {
    use crate::client::Error;
    match e {
        Error::Refused(_) => "Connection refused".into(),
        Error::Resolve { host, .. } => host.clone(),
        Error::ConnectTimeout(_) => "Connect timed out".into(),
        Error::ReadTimeout | Error::FutureTimeout => "Read timed out".into(),
        other => other.exception_message().unwrap_or_else(|| "Read timed out".into()),
    }
}

/// The spec's model with operation ids filled in, and its component schemas.
pub(crate) fn model(spec: &str) -> Result<OpenAPI, String> {
    let model = crate::openapi::load_model(spec)?;
    crate::openapi_expectations::add_missing_operation_ids(&model);
    Ok(model)
}

/// The tools' `specUrlOrPayload` and `baseUrl`; `Err(None)` where upstream fails the tool.
async fn spec_and_target(state: &State, args: &Value, tool: &str) -> Result<(String, Target), Option<Value>> {
    let spec = spec_argument(args).map_err(Some)?;
    let Some(base_url) = as_text(args, "baseUrl").filter(|b| !b.trim().is_empty()) else { return Err(Some(error("'baseUrl' is required and must not be blank"))) };
    crate::log::info_event(state, crate::recorded::LogEntry::at(crate::recorded::Level::Info, format!("MCP {tool} sending requests to external target:{{}}")).args([&base_url]));
    Ok((spec, checked_target(state, &base_url, "baseUrl", tool).await?))
}

/// [`target`], its host first checked under the forward target checks (`blockedTargetResult`), between the scheme
/// check and the port.
async fn checked_target(state: &State, url: &str, arg: &str, tool: &str) -> Result<Target, Option<Value>> {
    if let Some(host) = target_host(url) && let Some(refused) = blocked_target_result(state, tool, &host).await {
        return Err(Some(refused));
    }
    target(url, arg)
}

/// The host of a URL [`target`] gets past its host and scheme checks.
fn target_host(url: &str) -> Option<String> {
    let parts = crate::import::url_parts(url)?;
    let scheme = parts.scheme.unwrap_or_default();
    let http = scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https");
    parts.host.filter(|h| !h.is_empty() && http)
}

/// `McpToolRegistry.blockedTargetResult`: `None` when the tool may send to `host` under
/// `forwardProxyBlockPrivateNetworks` and the `forwardProxyAllowedHosts`/`DeniedHosts` lists, otherwise the error
/// result the tool returns, the refusal logged (WARN) once.
async fn blocked_target_result(state: &State, tool: &str, host: &str) -> Option<Value> {
    let reason = crate::ws_relay::blocked(state, host).await?;
    crate::log::warn_event(state, crate::recorded::LogEntry::at(crate::recorded::Level::Warn, "MCP {} blocked by SSRF policy:{}").args([tool, reason.as_str()]));
    Some(error(&format!("{tool} blocked by SSRF policy: {reason}")))
}

/// `handleRunContractTest` over `OpenApiContractTest`: each operation's example request sent to `baseUrl`, the
/// response validated against the operation.
pub async fn run_contract_test(state: &Arc<State>, args: &Value) -> Value {
    let (spec, target) = match spec_and_target(state, args, "run_contract_test").await {
        Ok(v) => v,
        Err(e) => return e.unwrap_or_else(|| super::llm_tools::failure(state, "Failed to run contract test")),
    };
    let filter = as_text(args, "operationId").filter(|f| !f.trim().is_empty());
    let openapi = match crate::openapi::checking_spec_fetches(&state.config, || model(&spec)) {
        Ok(m) => m,
        Err(_) => return super::llm_tools::failure(state, "Failed to run contract test"),
    };
    let definitions = openapi.get_components().and_then(|c| c.get_schemas());
    let realistic = state.config.bool_property("generateRealisticExampleValues", false);
    let mut results = Vec::new();
    let (mut passed, mut failed) = (0, 0);
    for (template, item) in openapi.get_paths().map(|p| p.entries()).unwrap_or_default() {
        for (method, operation) in crate::openapi_expectations::map_operations(&item) {
            let operation_id = operation.get_operation_id();
            if filter.as_ref().is_some_and(|f| operation_id.as_ref() != Some(f)) {
                continue;
            }
            let request = example_request(definitions.as_ref(), method, &template, &operation, realistic);
            let answer = send(state, &target, &request, SEND_TIMEOUT_MILLIS).await;
            let response = crate::openapi_validation::Response { status: answer.status, headers: &answer.headers, body: &answer.body };
            let errors = crate::openapi::checking_spec_fetches(&state.config, || crate::openapi_validation::validate_response(&spec, operation_id.as_deref().unwrap_or_default(), &response));
            let ok = errors.is_empty();
            let mut o = Map::new();
            o.insert("operationId".into(), json!(operation_id));
            o.insert("method".into(), json!(method));
            o.insert("path".into(), json!(template));
            o.insert("statusCode".into(), json!(answer.status));
            o.insert("passed".into(), json!(ok));
            if !ok {
                o.insert("validationErrors".into(), json!(errors));
                failed += 1;
            } else {
                passed += 1;
            }
            results.push(Value::Object(o));
        }
    }
    json!({
        "status": if failed == 0 { "all_passed" } else { "failures_detected" },
        "totalOperations": results.len(),
        "passed": passed,
        "failed": failed,
        "results": results,
    })
}

/// `BigDecimal.add`/`subtract(BigDecimal.ONE)`.
fn plus_one(v: &jackson::bigdecimal::BigDecimal, delta: i64) -> jackson::bigdecimal::BigDecimal {
    use num_bigint::BigInt;
    if v.scale >= 0 {
        let one = BigInt::from(10).pow(v.scale as u32) * BigInt::from(delta);
        jackson::bigdecimal::BigDecimal::new(&v.unscaled + one, v.scale)
    } else {
        let whole = &v.unscaled * BigInt::from(10).pow((-v.scale) as u32);
        jackson::bigdecimal::BigDecimal::new(whole + BigInt::from(delta), 0)
    }
}

/// A mutated request: its type, description and the request.
struct Mutation {
    kind: &'static str,
    description: String,
    request: ExampleRequest,
}

/// `cloneRequest`: method, path, query, headers and body (cookies are dropped).
fn with_body(valid: &ExampleRequest, body: &Value) -> ExampleRequest {
    ExampleRequest { body: Some(crate::json::pretty(body)), ..valid.clone() }
}

/// `generateMutations`.
fn mutations(definitions: Option<&swagger_parser::java::JMap<Schema>>, template: &str, operation: &Operation, valid: &ExampleRequest) -> Vec<Mutation> {
    let _ = definitions;
    let mut out = Vec::new();
    for p in parameters(operation).iter().filter(|p| p.get_in().as_deref() == Some("path") && p.get_required() == Some(true)) {
        let name = p.get_name().unwrap_or_default();
        let mut path = template.replace(&format!("{{{name}}}"), "");
        while path.contains("//") {
            path = path.replace("//", "/");
        }
        if path.ends_with('/') && path.len() > 1 {
            path.pop();
        }
        out.push(Mutation { kind: "OMIT_REQUIRED_PATH_PARAM", description: format!("omit required path parameter '{name}'"), request: ExampleRequest { path, ..valid.clone() } });
    }
    for p in parameters(operation).iter().filter(|p| p.get_in().as_deref() == Some("query") && p.get_required() == Some(true)) {
        let name = p.get_name().unwrap_or_default();
        let query = valid.query.iter().filter(|(k, _)| *k != name).cloned().collect();
        out.push(Mutation { kind: "OMIT_REQUIRED_QUERY_PARAM", description: format!("omit required query parameter '{name}'"), request: ExampleRequest { query, ..valid.clone() } });
    }
    let Some((_, media)) = request_media(operation) else { return out };
    let Some(schema) = media.get_schema() else { return out };
    let body = valid.body.as_deref().filter(|b| !b.is_empty()).and_then(|b| crate::json::parse_lenient(b.as_bytes()).ok()).filter(Value::is_object);
    let properties = schema.get_properties().map(|p| p.entries()).unwrap_or_default();
    let modified = |f: &dyn Fn(&mut Map<String, Value>)| -> Option<Value> {
        let mut o = body.clone()?.as_object()?.clone();
        f(&mut o);
        Some(Value::Object(o))
    };
    if let (Some(required), true) = (schema.get_required(), schema.get_properties().is_some()) {
        for field in required.to_vec() {
            if let Some(b) = modified(&|o| {
                o.shift_remove(&field);
            }) {
                out.push(Mutation { kind: "OMIT_REQUIRED_BODY_FIELD", description: format!("omit required body field '{field}'"), request: with_body(valid, &b) });
            }
        }
    }
    for (field, s) in &properties {
        let Some(kind) = s.get_type() else { continue };
        let value = match kind.as_str() {
            "integer" | "number" => json!("not_a_number"),
            "boolean" => json!("not_a_boolean"),
            "string" => json!(99999),
            "array" => json!("not_an_array"),
            "object" => json!("not_an_object"),
            _ => continue,
        };
        if let Some(b) = modified(&|o| {
            o.insert(field.clone(), value.clone());
        }) {
            out.push(Mutation { kind: "TYPE_VIOLATION", description: format!("type violation on field '{field}' (expected {kind})"), request: with_body(valid, &b) });
        }
    }
    for (field, s) in &properties {
        let kind = s.get_type().unwrap_or_default();
        if kind != "integer" && kind != "number" || body.is_none() {
            continue;
        }
        for (bound, delta, label) in [(s.get_minimum(), -1, "minimum-1"), (s.get_maximum(), 1, "maximum+1")] {
            let Some(bound) = bound else { continue };
            let beyond = plus_one(&bound, delta);
            let value = if kind == "integer" { json!(beyond.to_i64_wrapping()) } else { crate::model::number(&java_compat::double_to_string(beyond.to_f64())) };
            if let Some(b) = modified(&|o| {
                o.insert(field.clone(), value.clone());
            }) {
                out.push(Mutation {
                    kind: "NUMERIC_BOUNDARY_VIOLATION",
                    description: format!("numeric boundary violation on field '{field}' ({label} = {})", beyond.to_java_string()),
                    request: with_body(valid, &b),
                });
            }
        }
    }
    for (field, s) in &properties {
        if s.get_type().as_deref() != Some("string") || body.is_none() {
            continue;
        }
        if let Some(min) = s.get_min_length().filter(|m| *m > 0) && let Some(b) = modified(&|o| {
            o.insert(field.clone(), json!("x".repeat((min - 1).max(0) as usize)));
        }) {
            out.push(Mutation { kind: "STRING_LENGTH_BOUNDARY_VIOLATION", description: format!("string length violation on field '{field}' (minLength-1 = {})", min - 1), request: with_body(valid, &b) });
        }
        if let Some(max) = s.get_max_length() && let Some(b) = modified(&|o| {
            o.insert(field.clone(), json!("x".repeat((max as i64 + 1).max(0) as usize)));
        }) {
            out.push(Mutation { kind: "STRING_LENGTH_BOUNDARY_VIOLATION", description: format!("string length violation on field '{field}' (maxLength+1 = {})", max as i64 + 1), request: with_body(valid, &b) });
        }
    }
    for (field, s) in &properties {
        if s.get_type().as_deref() != Some("string") || s.get_max_length().is_some() {
            continue;
        }
        if let Some(b) = modified(&|o| {
            o.insert(field.clone(), json!("A".repeat(10_000)));
        }) {
            out.push(Mutation { kind: "OVERSIZED_STRING_FIELD", description: format!("oversized string for field '{field}' (10000 chars)"), request: with_body(valid, &b) });
        }
    }
    out.push(Mutation { kind: "MALFORMED_JSON_BODY", description: "malformed/unparseable JSON body".into(), request: ExampleRequest { body: Some("{this is: not valid json!!! [}".into()), ..valid.clone() } });
    out
}

/// `handleRunResiliencyTest` over `OpenApiResiliencyTest`: malformed and boundary-case variants of each operation's
/// example request, classified HANDLED when the service answers 4xx.
pub async fn run_resiliency_test(state: &Arc<State>, args: &Value) -> Value {
    let (spec, target) = match spec_and_target(state, args, "run_resiliency_test").await {
        Ok(v) => v,
        Err(e) => return e.unwrap_or_else(|| super::llm_tools::failure(state, "Failed to run resiliency test")),
    };
    let filter = as_text(args, "operationId").filter(|f| !f.trim().is_empty());
    let openapi = match crate::openapi::checking_spec_fetches(&state.config, || model(&spec)) {
        Ok(m) => m,
        Err(_) => return super::llm_tools::failure(state, "Failed to run resiliency test"),
    };
    let Some(paths) = openapi.get_paths() else { return super::llm_tools::failure(state, "Failed to run resiliency test") };
    let definitions = openapi.get_components().and_then(|c| c.get_schemas());
    let realistic = state.config.bool_property("generateRealisticExampleValues", false);
    let mut results = Vec::new();
    // operation key → (operationId, method, path, handled, unexpected)
    let mut summaries: Vec<(String, Option<String>, String, String, usize, usize)> = Vec::new();
    for (template, item) in paths.entries() {
        for (method, operation) in crate::openapi_expectations::map_operations(&item) {
            let operation_id = operation.get_operation_id();
            if filter.as_ref().is_some_and(|f| operation_id.as_ref() != Some(f)) {
                continue;
            }
            let valid = example_request(definitions.as_ref(), method, &template, &operation, realistic);
            for m in mutations(definitions.as_ref(), &template, &operation, &valid) {
                let answer = send(state, &target, &m.request, RESILIENCY_TIMEOUT_MILLIS).await;
                let handled = (400..500).contains(&answer.status);
                results.push(json!({
                    "operationId": operation_id,
                    "method": method,
                    "path": template,
                    "mutationType": m.kind,
                    "mutationDescription": m.description,
                    "statusCode": answer.status,
                    "classification": if handled { "HANDLED" } else { "UNEXPECTED" },
                }));
                let key = operation_id.clone().unwrap_or_else(|| format!("{method} {template}"));
                let entry = match summaries.iter_mut().position(|s| s.0 == key) {
                    Some(i) => &mut summaries[i],
                    None => {
                        summaries.push((key, operation_id.clone(), method.to_string(), template.clone(), 0, 0));
                        summaries.last_mut().unwrap()
                    }
                };
                if handled {
                    entry.4 += 1;
                } else {
                    entry.5 += 1;
                }
            }
        }
    }
    let handled = results.iter().filter(|r| r["classification"] == "HANDLED").count();
    let unexpected = results.len() - handled;
    let operation_summaries: Vec<Value> =
        summaries.into_iter().map(|(_, id, method, path, h, u)| json!({"operationId": id, "method": method, "path": path, "handled": h, "unexpected": u})).collect();
    json!({
        "status": if unexpected == 0 { "all_handled" } else { "failures_detected" },
        "totalMutations": results.len(),
        "handled": handled,
        "unexpected": unexpected,
        "operationSummaries": operation_summaries,
        "results": results,
    })
}

// ------------------------------------------------------------------ run_mcp_contract_test

/// `ExchangeResult`: status, session id, the parsed JSON-RPC body, or the transport error.
struct Exchanged {
    status: u32,
    session: Option<String>,
    body: Option<Value>,
    transport_error: Option<String>,
}

/// `parseJsonRpcBody`: JSON, or the first SSE event's `data:` lines.
fn json_rpc_body(headers: &crate::request::MultiMap, body: &str) -> Option<Value> {
    if body.trim().is_empty() {
        return None;
    }
    let content_type = crate::request::first(headers, "content-type").map(str::to_lowercase);
    let lead = body.trim_start();
    let mut json_text = body.to_string();
    if content_type.is_some_and(|c| c.contains("text/event-stream")) || lead.starts_with("event:") || lead.starts_with("data:") {
        let mut data = String::new();
        let mut collecting = false;
        for line in body.split('\n') {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("data:") {
                if !data.is_empty() {
                    data.push('\n');
                }
                data.push_str(rest.trim());
                collecting = true;
            } else if trimmed.is_empty() && collecting {
                break;
            }
        }
        if !data.is_empty() {
            json_text = data;
        }
    }
    crate::json::parse_lenient(json_text.as_bytes()).ok()
}

async fn exchange(state: &State, t: &Target, message: &Value, session: Option<&str>) -> Exchanged {
    // `sendToCheckedTarget` throws the refusal, which the exchange reports as its transport error.
    if let Some(reason) = crate::ws_relay::blocked(state, &t.host).await {
        return Exchanged { status: 0, session: None, body: None, transport_error: Some(reason) };
    }
    let mut headers = vec![("Content-Type".to_string(), vec!["application/json".to_string()]), ("Accept".into(), vec!["application/json, text/event-stream".into()])];
    if let Some(s) = session.filter(|s| !s.is_empty()) {
        headers.push(("Mcp-Session-Id".into(), vec![s.to_string()]));
    }
    let path = if t.base_path.is_empty() { "/".to_string() } else { t.base_path.clone() };
    let request = ExampleRequest { method: "POST".into(), path, query: Vec::new(), headers, cookies: Vec::new(), body: Some(message.to_string()) };
    let target = Target { base_path: String::new(), host: t.host.clone(), port: t.port, secure: t.secure };
    let answer = send_unchecked(&target, &request, SEND_TIMEOUT_MILLIS, !crate::ws_relay::checks_active(state)).await;
    if answer.status == 0 {
        return Exchanged { status: 0, session: None, body: None, transport_error: Some(answer.body) };
    }
    let session = answer.headers.iter().find(|(k, v)| k.eq_ignore_ascii_case("mcp-session-id") && !v.is_empty()).map(|(_, v)| v[0].clone());
    Exchanged { status: answer.status, session, body: json_rpc_body(&answer.headers, &answer.body), transport_error: None }
}

/// `textOrNull`: a non-blank value node's text.
fn text_or_null(node: Option<&Value>, field: &str) -> Option<String> {
    let v = node?.get(field)?;
    let text = match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        _ => return None,
    };
    (!text.trim().is_empty()).then_some(text)
}

struct Check {
    name: String,
    passed: bool,
    status: Option<u32>,
    detail: Option<String>,
    errors: Vec<String>,
}

impl Check {
    fn new(name: &str) -> Check {
        Check { name: name.into(), passed: false, status: None, detail: None, errors: Vec::new() }
    }

    /// `validateJsonRpcResult`.
    fn json_rpc_result(&mut self, status: u32, body: Option<&Value>) {
        if status != 200 {
            self.errors.push(format!("expected HTTP 200, got {status}"));
        }
        let Some(body) = body else {
            self.errors.push("response body was empty or not valid JSON".into());
            return;
        };
        if text_or_null(Some(body), "jsonrpc").as_deref() != Some("2.0") {
            self.errors.push("missing or invalid 'jsonrpc' version (expected \"2.0\")".into());
        }
        if let Some(e) = body.get("error") {
            let message = match e.get("message") {
                Some(Value::String(s)) => s.clone(),
                Some(Value::Null) | None => String::new(),
                Some(Value::Object(_) | Value::Array(_)) => String::new(),
                Some(other) => other.to_string(),
            };
            self.errors.push(format!("server returned a JSON-RPC error: {message}"));
        } else if body.get("result").is_none() {
            self.errors.push("response has neither 'result' nor 'error'".into());
        }
    }
}

fn rpc(id: i64, method: &str, params: Value) -> Value {
    let mut o = Map::new();
    o.insert("jsonrpc".into(), json!("2.0"));
    o.insert("id".into(), json!(id));
    o.insert("method".into(), json!(method));
    o.insert("params".into(), params);
    Value::Object(o)
}

/// `handleRunMcpContractTest` over `McpContractTest`: initialize, the initialized notification, ping, tools/list,
/// an unknown method and optionally one tools/call against the target MCP server, each checked against the spec.
pub async fn run_mcp_contract_test(state: &Arc<State>, args: &Value) -> Value {
    let Some(url) = as_text(args, "targetUrl").filter(|u| !u.trim().is_empty()) else { return error("'targetUrl' is required and must not be blank") };
    let version_arg = as_text(args, "protocolVersion");
    let tool = as_text(args, "toolName");
    crate::log::info_event(state, crate::recorded::LogEntry::at(crate::recorded::Level::Info, "MCP run_mcp_contract_test connecting to external MCP server:{}").args([&url]));
    let t = match checked_target(state, &url, "targetUrl", "run_mcp_contract_test").await {
        Ok(t) => t,
        Err(e) => return e.unwrap_or_else(|| super::llm_tools::failure(state, "Failed to run MCP contract test")),
    };
    let version = version_arg.map(|v| v.trim().to_string()).filter(|v| !v.is_empty()).unwrap_or_else(|| "2025-06-18".into());
    let mut protocol = version.clone();
    let (mut server_name, mut server_version) = (None, None);
    let mut checks: Vec<Check> = Vec::new();
    let init = exchange(state, &t, &rpc(1, "initialize", json!({"protocolVersion": version, "capabilities": {}, "clientInfo": {"name": "MockServer-contract-test", "version": version}})), None).await;
    let mut check = Check::new("initialize");
    let mut session: Option<String>;
    if let Some(e) = &init.transport_error {
        check.errors.push(format!("could not connect to target: {e}"));
        checks.push(check);
    } else {
        check.status = Some(init.status);
        check.json_rpc_result(init.status, init.body.as_ref());
        if let Some(result) = init.body.as_ref().and_then(|b| b.get("result")) {
            match text_or_null(Some(result), "protocolVersion") {
                None => check.errors.push("result.protocolVersion is missing".into()),
                Some(v) => protocol = v,
            }
            if !result.get("capabilities").is_some_and(Value::is_object) {
                check.errors.push("result.capabilities object is missing".into());
            }
            match text_or_null(result.get("serverInfo"), "name") {
                None => check.errors.push("result.serverInfo.name is missing".into()),
                Some(n) => {
                    server_name = Some(n);
                    server_version = text_or_null(result.get("serverInfo"), "version");
                }
            }
        }
        check.passed = check.errors.is_empty();
        session = init.session.clone();
        check.detail = Some(if check.passed { if session.is_some() { "session established" } else { "no session id returned" } } else { "initialize failed" }.into());
        checks.push(check);
        let notified = exchange(state, &t, &json!({"jsonrpc": "2.0", "method": "notifications/initialized"}), session.as_deref()).await;
        let mut check = Check::new("notifications/initialized");
        if let Some(e) = &notified.transport_error {
            check.errors.push(format!("transport error: {e}"));
        } else {
            check.status = Some(notified.status);
            if notified.status != 202 {
                check.errors.push(format!(
                    "expected HTTP 202 Accepted for a notification, got {} (MCP 2025-06-18 basic/transports: the server MUST return 202 Accepted with no body)",
                    notified.status
                ));
            }
            if notified.status == 202 && notified.body.is_some() {
                check.errors.push("expected no body for a notification, got a JSON-RPC body (MCP 2025-06-18 basic/transports: the server MUST return 202 Accepted with no body)".into());
            }
            if notified.session.is_some() {
                session = notified.session.clone();
            }
        }
        check.passed = check.errors.is_empty();
        checks.push(check);
        let ping = exchange(state, &t, &rpc(2, "ping", json!({})), session.as_deref()).await;
        let mut check = Check::new("ping");
        match &ping.transport_error {
            Some(e) => check.errors.push(format!("transport error: {e}")),
            None => {
                check.status = Some(ping.status);
                check.json_rpc_result(ping.status, ping.body.as_ref());
            }
        }
        check.passed = check.errors.is_empty();
        checks.push(check);
        let list = exchange(state, &t, &rpc(3, "tools/list", json!({})), session.as_deref()).await;
        let mut check = Check::new("tools/list");
        match &list.transport_error {
            Some(e) => check.errors.push(format!("transport error: {e}")),
            None => {
                check.status = Some(list.status);
                check.json_rpc_result(list.status, list.body.as_ref());
                if let Some(result) = list.body.as_ref().and_then(|b| b.get("result")) {
                    match result.get("tools").and_then(Value::as_array) {
                        None => check.errors.push("result.tools is not an array".into()),
                        Some(tools) => {
                            let malformed = tools
                                .iter()
                                .filter(|tool| {
                                    let schema = tool.get("inputSchema");
                                    let bad = !schema.is_some_and(Value::is_object) || (schema.and_then(|s| s.get("type")).is_some() && text_or_null(schema, "type").as_deref() != Some("object"));
                                    text_or_null(Some(tool), "name").is_none() || bad
                                })
                                .count();
                            if malformed > 0 {
                                check.errors.push(format!("{malformed} of {} tools are missing a name or a valid object inputSchema", tools.len()));
                            }
                            check.detail = Some(format!("{} tools advertised", tools.len()));
                        }
                    }
                }
            }
        }
        check.passed = check.errors.is_empty();
        checks.push(check);
        let unknown = exchange(state, &t, &rpc(4, "mockserver/contract-test/does-not-exist", json!({})), session.as_deref()).await;
        let mut check = Check::new("rejects unknown method");
        match &unknown.transport_error {
            Some(e) => check.errors.push(format!("transport error: {e}")),
            None => {
                check.status = Some(unknown.status);
                match unknown.body.as_ref().and_then(|b| b.get("error")).filter(|e| e.is_object()) {
                    None => check.errors.push("expected a JSON-RPC error object for an unknown method".into()),
                    Some(e) => match e.get("code").filter(|c| c.is_i64() || c.is_u64()) {
                        None => check.errors.push("JSON-RPC error is missing an integer 'code'".into()),
                        Some(code) if code.as_i64() != Some(-32601) => {
                            check.errors.push(format!("expected error code -32601 (Method not found), got {}", code.as_i64().unwrap_or_default() as i32))
                        }
                        Some(_) => check.detail = Some("responded with code -32601".into()),
                    },
                }
            }
        }
        check.passed = check.errors.is_empty();
        checks.push(check);
        if let Some(tool) = tool.as_deref().map(str::trim).filter(|t| !t.is_empty()) {
            let called = exchange(state, &t, &rpc(5, "tools/call", json!({"name": tool, "arguments": {}})), session.as_deref()).await;
            let mut check = Check::new(&format!("tools/call ({tool})"));
            match &called.transport_error {
                Some(e) => check.errors.push(format!("transport error: {e}")),
                None => {
                    check.status = Some(called.status);
                    check.json_rpc_result(called.status, called.body.as_ref());
                    if let Some(result) = called.body.as_ref().and_then(|b| b.get("result")) {
                        match result.get("content").and_then(Value::as_array) {
                            None => check.errors.push("result.content is not an array".into()),
                            Some(items) => {
                                for item in items {
                                    let kind = text_or_null(Some(item), "type");
                                    if kind.is_none() {
                                        check.errors.push("a content item is missing 'type'".into());
                                        break;
                                    }
                                    if kind.as_deref() == Some("resource_link") && text_or_null(Some(item), "uri").is_none() {
                                        check.errors.push("a resource_link content item is missing 'uri'".into());
                                        break;
                                    }
                                }
                            }
                        }
                        if result.get("structuredContent").is_some_and(|s| !s.is_object()) {
                            check.errors.push("result.structuredContent is present but not a JSON object".into());
                        }
                        if result.get("isError").is_some_and(|s| !s.is_boolean()) {
                            check.errors.push("result.isError is present but not a boolean".into());
                        }
                        let is_error = match result.get("isError") {
                            Some(Value::Bool(b)) => *b,
                            Some(Value::String(s)) => s.trim() == "true",
                            Some(Value::Number(n)) => n.as_i64().is_some_and(|i| i != 0),
                            _ => false,
                        };
                        check.detail = Some(format!("isError={is_error}"));
                    }
                }
            }
            check.passed = check.errors.is_empty();
            checks.push(check);
        }
    }
    let passed = checks.iter().filter(|c| c.passed).count();
    let failed = checks.len() - passed;
    let mut o = Map::new();
    o.insert("status".into(), json!(if failed == 0 { "all_passed" } else { "failures_detected" }));
    o.insert("protocolVersion".into(), json!(protocol));
    if let Some(name) = server_name {
        let mut info = Map::new();
        info.insert("name".into(), json!(name));
        if let Some(v) = server_version {
            info.insert("version".into(), json!(v));
        }
        o.insert("serverInfo".into(), Value::Object(info));
    }
    o.insert("totalChecks".into(), json!(checks.len()));
    o.insert("passed".into(), json!(passed));
    o.insert("failed".into(), json!(failed));
    let results: Vec<Value> = checks
        .into_iter()
        .map(|c| {
            let mut n = Map::new();
            n.insert("check".into(), json!(c.name));
            n.insert("passed".into(), json!(c.passed));
            if let Some(s) = c.status {
                n.insert("statusCode".into(), json!(s));
            }
            if let Some(d) = c.detail {
                n.insert("detail".into(), json!(d));
            }
            if !c.errors.is_empty() {
                n.insert("validationErrors".into(), json!(c.errors));
            }
            Value::Object(n)
        })
        .collect();
    o.insert("results".into(), Value::Array(results));
    Value::Object(o)
}
