//! Class callbacks whose upstream tests read the callback class's static state from the test JVM, which a separate
//! server process never shares:
//! - `TestClasspathTestExpectationResponseCallback` (`shouldCallbackToSpecifiedClassInTestClasspath*`);
//! - `StaticTestExpectationResponseCallback` (`shouldCallbackToSpecifiedClassWithDynamicResponse`).
//!
//! Here the classes are registered in-process, so the test reads their state as upstream does. Each upstream class
//! is its transport: `ExtendedNettyMockingIntegrationTest` (HTTP, then HTTPS), `HTTP2ExtendedMockingIntegrationTest`
//! (HTTP, then HTTP/2 over TLS), `SecureClientMockingIntegrationTest` (a TLS control plane as well).

use std::sync::Mutex;

use mock_server_integration_testing_callbacks as callbacks;
use serde_json::{Value, json};

use crate::common::{self, Transport};

/// The callback classes' state is process-wide, as a Java class's statics are.
static STATE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const CLASSPATH_CLASS: &str = "org.mockserver.netty.integration.mock.TestClasspathTestExpectationResponseCallback";
const STATIC_CLASS: &str = "org.mockserver.testing.integration.callback.StaticTestExpectationResponseCallback";

fn accepted() -> Value {
    json!({"statusCode": 202, "reasonPhrase": "Accepted", "headers": {"x-callback": ["test_callback_header"]}, "body": "a_callback_response"})
}

fn reset(requests: &Mutex<Vec<Value>>, response: &Mutex<Option<Value>>) {
    requests.lock().unwrap().clear();
    *response.lock().unwrap() = Some(accepted());
}

/// `makeRequest` of a `POST /callback` with a body, checked against the precanned `202`.
async fn callback_request(port: u16, transport: Transport, body: &str) {
    let r = common::exchange(port, transport, "POST", "/callback", &[("X-Test", "test_headers_and_body")], body).await;
    assert_eq!(r.status, 202, "{transport:?}");
    if transport != Transport::Http2 {
        assert_eq!(r.reason.as_deref(), Some("Accepted"), "{transport:?}");
    }
    assert_eq!(r.header("x-callback"), Some("test_callback_header"), "{transport:?}");
    assert_eq!(r.text(), "a_callback_response", "{transport:?}");
}

fn recorded(requests: &Mutex<Vec<Value>>, index: usize) -> (String, String) {
    let requests = requests.lock().unwrap();
    let request = requests.get(index).unwrap_or_else(|| panic!("the callback saw {} requests", requests.len()));
    (callbacks::body_text(request), request.get("path").and_then(Value::as_str).unwrap_or_default().to_string())
}

/// Registers the class callback (through the TLS control plane when `secure_control_plane`), then sends one request
/// per transport and checks what the callback class recorded.
async fn run(class: &str, requests: &Mutex<Vec<Value>>, response: &Mutex<Option<Value>>, transports: &[Transport], secure_control_plane: bool) {
    let _guard = STATE.lock().await;
    reset(requests, response);
    let server = common::start_with_callback_classes(&[]).await;
    let expectation = json!({"httpRequest": {"path": "/callback"}, "httpResponseClassCallback": {"callbackClass": class}});
    let control = if secure_control_plane { Transport::Https } else { Transport::Http };
    let created = common::exchange(server.port, control, "PUT", "/mockserver/expectation", &[], &expectation.to_string()).await;
    assert_eq!(created.status, 201, "{}", created.text());
    for (i, transport) in transports.iter().enumerate() {
        let body = if *transport == Transport::Http { "an_example_body_http" } else { "an_example_body_https" };
        callback_request(server.port, *transport, body).await;
        assert_eq!(recorded(requests, i), (body.to_string(), "/callback".to_string()), "{transport:?}");
    }
    server.server.shutdown().await;
}

async fn classpath(transports: &[Transport]) {
    run(CLASSPATH_CLASS, &callbacks::CLASSPATH_REQUESTS, &callbacks::CLASSPATH_RESPONSE, transports, false).await;
}

async fn dynamic(transports: &[Transport], secure_control_plane: bool) {
    run(STATIC_CLASS, &callbacks::STATIC_REQUESTS, &callbacks::STATIC_RESPONSE, transports, secure_control_plane).await;
}

// `ExtendedNettyMockingIntegrationTest`

#[tokio::test(flavor = "multi_thread")]
async fn extended_netty_should_callback_to_specified_class_in_test_classpath_as_class() {
    classpath(&[Transport::Http, Transport::Https]).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn extended_netty_should_callback_to_specified_class_in_test_classpath_as_string() {
    classpath(&[Transport::Http, Transport::Https]).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn extended_netty_should_callback_to_specified_class_with_dynamic_response() {
    dynamic(&[Transport::Http, Transport::Https], false).await;
}

// `HTTP2ExtendedMockingIntegrationTest`

#[tokio::test(flavor = "multi_thread")]
async fn http2_extended_should_callback_to_specified_class_in_test_classpath_as_class() {
    classpath(&[Transport::Http, Transport::Http2]).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn http2_extended_should_callback_to_specified_class_in_test_classpath_as_string() {
    classpath(&[Transport::Http, Transport::Http2]).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn http2_extended_should_callback_to_specified_class_with_dynamic_response() {
    dynamic(&[Transport::Http, Transport::Http2], false).await;
}

// `SecureClientMockingIntegrationTest`

#[tokio::test(flavor = "multi_thread")]
async fn secure_client_should_callback_to_specified_class_with_dynamic_response() {
    dynamic(&[Transport::Http, Transport::Https], true).await;
}
