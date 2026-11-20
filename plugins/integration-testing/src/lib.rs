//! Rust counterparts of the callback classes that MockServer 8.0.0's own tests name:
//! - `org.mockserver.testing.integration.callback.*` from `mockserver-integration-testing`;
//! - the nested callback classes of `mockserver-netty`'s test classes.
//!
//! [`classes`] lists them under their Java names. Oracle scenarios and Rust ports register them in-process, and
//! built as a plugin (`cdylib`, or `wasm32-unknown-unknown`), they serve the unmodified upstream suites run
//! against a mock-server process.

use std::sync::Mutex;

use mock_server_callback_sdk::{CallbackClass, CallbackError, ExpectationInitializer, ForwardAndResponseCallback, ForwardCallback, Value, json};

pub const PACKAGE: &str = "org.mockserver.testing.integration.callback";

/// `HttpRequest.getFirstHeader`: case-insensitive, `""` when absent.
pub fn first_header(model: &Value, name: &str) -> String {
    let Some(Value::Object(headers)) = model.get("headers") else { return String::new() };
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .and_then(|(_, v)| v.as_array().and_then(|a| a.first()).or(Some(v)))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn path(model: &Value) -> &str {
    model.get("path").and_then(Value::as_str).unwrap_or_default()
}

/// `HttpRequest.getBodyAsString`: the body's text in any of the model's body forms.
pub fn body_text(model: &Value) -> String {
    match model.get("body") {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Object(o)) => o
            .get("string")
            .or_else(|| o.get("json"))
            .or_else(|| o.get("xml"))
            .map(|v| v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string()))
            .unwrap_or_default(),
        Some(other) if !other.is_null() => other.to_string(),
        _ => String::new(),
    }
}

/// `PrecannedTestExpectationResponseCallback`: 202 with a body for paths ending `/callback`, else 404.
pub fn precanned_response(request: &Value) -> Result<Value, CallbackError> {
    if path(request).ends_with("/callback") {
        Ok(json!({
            "statusCode": 202,
            "headers": {"x-callback": ["test_callback_header"], "Content-Length": ["19"], "Connection": ["keep-alive"]},
            "body": "a_callback_response"
        }))
    } else {
        Ok(json!({"statusCode": 404, "reasonPhrase": "Not Found"}))
    }
}

/// `StaticTestExpectationResponseCallback`: records each request and answers `httpResponse` (empty by default).
/// Its state lives in the loading process, as the Java class's statics do in the server's JVM.
pub static STATIC_REQUESTS: Mutex<Vec<Value>> = Mutex::new(Vec::new());
pub static STATIC_RESPONSE: Mutex<Option<Value>> = Mutex::new(None);

pub fn static_response(request: &Value) -> Result<Value, CallbackError> {
    STATIC_REQUESTS.lock().unwrap().push(request.clone());
    Ok(STATIC_RESPONSE.lock().unwrap().clone().unwrap_or_else(|| json!({})))
}

/// `TestClasspathTestExpectationResponseCallback` (mockserver-netty's tests): the same, with state of its own.
pub static CLASSPATH_REQUESTS: Mutex<Vec<Value>> = Mutex::new(Vec::new());
pub static CLASSPATH_RESPONSE: Mutex<Option<Value>> = Mutex::new(None);

pub fn classpath_response(request: &Value) -> Result<Value, CallbackError> {
    CLASSPATH_REQUESTS.lock().unwrap().push(request.clone());
    Ok(CLASSPATH_RESPONSE.lock().unwrap().clone().unwrap_or_else(|| json!({})))
}

/// The request both precanned forward callbacks send: to `localhost:<x-echo-server-port>`, with `x-test` kept.
fn overridden_request(request: &Value, keep_protocol: bool) -> Value {
    let mut out = json!({
        "headers": {"Host": [format!("localhost:{}", first_header(request, "x-echo-server-port"))], "x-test": [first_header(request, "x-test")]},
        "body": "some_overridden_body",
    });
    if keep_protocol && let Some(p) = request.get("protocol") {
        out["protocol"] = p.clone();
    }
    out["secure"] = request.get("secure").cloned().unwrap_or(json!(false));
    out
}

/// `PrecannedTestExpectationForwardCallbackRequest`.
pub struct ForwardRequest;

impl ForwardCallback for ForwardRequest {
    fn handle(&self, request: &Value) -> Result<Value, CallbackError> {
        Ok(overridden_request(request, true))
    }
}

/// `PrecannedTestExpectationForwardCallbackRequestAndResponse`.
pub struct ForwardRequestAndResponse;

impl ForwardAndResponseCallback for ForwardRequestAndResponse {
    fn handle(&self, request: &Value) -> Result<Value, CallbackError> {
        Ok(overridden_request(request, false))
    }

    fn handle_response(&self, _request: &Value, response: &Value) -> Result<Value, CallbackError> {
        let mut headers = mock_server_callback_sdk::serde_json::Map::new();
        headers.insert("x-response-test".into(), json!(["x-response-test"]));
        if let Some(Value::Object(upstream)) = response.get("headers") {
            for (k, v) in upstream {
                if !k.eq_ignore_ascii_case("content-length") {
                    headers.insert(k.clone(), v.clone());
                }
            }
        }
        Ok(json!({"headers": headers, "body": "some_overidden_response_body"}))
    }
}

/// `EchoBodyCallback` (the h2c and HTTP/3 matrix tests): the request body back.
pub fn echo_body(request: &Value) -> Result<Value, CallbackError> {
    Ok(json!({"body": body_text(request)}))
}

/// `ConcurrencyBasicResponseMockingIntegrationTest.ClassCallback`: the request body back, with its length.
pub fn echo_with_length(request: &Value) -> Result<Value, CallbackError> {
    let body = body_text(request);
    Ok(json!({"headers": {"content-length": [body.len().to_string()]}, "body": body}))
}

/// `FileBodyVerbatimNonStaticActionsIntegrationTest.FileBodyCallback` / `BinaryFileBodyCallback`: a FILE body with
/// no template type, read from the class path.
pub fn file_body(request: &Value) -> Result<Value, CallbackError> {
    let _ = request;
    Ok(json!({"statusCode": 200, "body": {"type": "FILE", "filePath": "org/mockserver/netty/filebody/verbatim_file_body.xml", "contentType": "application/xml"}}))
}

pub fn binary_file_body(request: &Value) -> Result<Value, CallbackError> {
    let _ = request;
    Ok(json!({"statusCode": 200, "body": {"type": "FILE", "filePath": "org/mockserver/netty/filebody/verbatim_binary_body.png", "contentType": "image/png"}}))
}

/// `Http1PipeliningClosingAndStopIntegrationTest$StuckCallback`: sleeps 4 s, then answers `stuck`, an exchange that
/// makes no progress past `inboundConnectionIdleTimeoutMillis`. Native only: `wasm32-unknown-unknown` cannot sleep (its
/// `std::thread::sleep` panics), so the WASM module leaves the class out.
#[cfg(not(target_arch = "wasm32"))]
pub fn stuck_response(request: &Value) -> Result<Value, CallbackError> {
    let _ = request;
    std::thread::sleep(std::time::Duration::from_secs(4));
    Ok(json!({"body": "stuck"}))
}

/// `ExpectationInitializerIntegrationExample` (`mockserver.initializationClass`).
pub struct InitializerExample;

impl ExpectationInitializer for InitializerExample {
    fn initialize_expectations(&self) -> Result<Value, CallbackError> {
        Ok(json!([
            {"httpRequest": {"path": "/simpleFirst"}, "httpResponse": {"body": "some first response"}},
            {"httpRequest": {"path": "/simpleSecond"}, "httpResponse": {"body": "some second response"}}
        ]))
    }
}

/// `org.mockserver.test.LibsTestInitializer`, the initializer upstream's docker_compose_libs_classpath container case
/// compiles into a jar on `/libs` (conformance/containers/cases/docker_compose_libs_plugin loads this one from there).
pub struct LibsTestInitializer;

impl ExpectationInitializer for LibsTestInitializer {
    fn initialize_expectations(&self) -> Result<Value, CallbackError> {
        Ok(json!([{"httpRequest": {"path": "/libs-test-path"}, "httpResponse": {"body": "libs_classpath_response"}}]))
    }
}

/// `RelayRawBytesErrorIntegrationTest$EmptyRawBytes`: answers `/raw` with an `error()` of no bytes, which upstream loads
/// in the server's JVM because an empty array is left out of an expectation's JSON; here it is an empty base64 string.
pub struct EmptyRawBytes;

impl ExpectationInitializer for EmptyRawBytes {
    fn initialize_expectations(&self) -> Result<Value, CallbackError> {
        Ok(json!([{"httpRequest": {"path": "/raw"}, "httpError": {"responseBytes": ""}}]))
    }
}

/// Every class under its Java name (`Class.getName`: nested classes joined with `$`).
pub fn classes() -> Vec<(String, CallbackClass)> {
    let netty = "org.mockserver.netty";
    #[allow(unused_mut)]
    let mut classes = vec![
        (format!("{PACKAGE}.PrecannedTestExpectationResponseCallback"), CallbackClass::new().with_response(precanned_response)),
        (format!("{PACKAGE}.StaticTestExpectationResponseCallback"), CallbackClass::new().with_response(static_response)),
        (format!("{PACKAGE}.PrecannedTestExpectationForwardCallbackRequest"), CallbackClass::new().with_forward(ForwardRequest)),
        (format!("{PACKAGE}.PrecannedTestExpectationForwardCallbackRequestAndResponse"), CallbackClass::new().with_forward_and_response(ForwardRequestAndResponse)),
        (format!("{netty}.integration.mock.TestClasspathTestExpectationResponseCallback"), CallbackClass::new().with_response(classpath_response)),
        (format!("{netty}.integration.mock.H2cMockingMatrixIntegrationTest$EchoBodyCallback"), CallbackClass::new().with_response(echo_body)),
        (format!("{netty}.http3.Http3MockingMatrixIntegrationTest$EchoBodyCallback"), CallbackClass::new().with_response(echo_body)),
        (format!("{netty}.integration.mock.initializer.ExpectationInitializerIntegrationExample"), CallbackClass::new().with_initializer(InitializerExample)),
        ("org.mockserver.test.LibsTestInitializer".to_string(), CallbackClass::new().with_initializer(LibsTestInitializer)),
        (format!("{netty}.integration.proxy.http.RelayRawBytesErrorIntegrationTest$EmptyRawBytes"), CallbackClass::new().with_initializer(EmptyRawBytes)),
        (format!("{netty}.integration.mock.ConcurrencyBasicResponseMockingIntegrationTest$ClassCallback"), CallbackClass::new().with_response(echo_with_length)),
        (format!("{netty}.integration.mock.FileBodyVerbatimNonStaticActionsIntegrationTest$FileBodyCallback"), CallbackClass::new().with_response(file_body)),
        (format!("{netty}.integration.mock.FileBodyVerbatimNonStaticActionsIntegrationTest$BinaryFileBodyCallback"), CallbackClass::new().with_response(binary_file_body)),
    ];
    #[cfg(not(target_arch = "wasm32"))]
    classes.push((format!("{netty}.integration.mock.Http1PipeliningClosingAndStopIntegrationTest$StuckCallback"), CallbackClass::new().with_response(stuck_response)));
    classes
}

mock_server_callback_sdk::export_callback_classes!(classes());
