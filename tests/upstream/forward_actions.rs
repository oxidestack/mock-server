//! `HttpForwardWithFallbackActionHandlerTest` and `HttpForwardValidateActionHandlerTest` (mockserver-core). Upstream
//! drives each handler with a mocked `NettyHttpClient`; here the upstream is a second expectation on the same
//! in-process server, answering the forwarded request once the forwarding expectation (served `once`) is used up.

use serde_json::{Value, json};

use crate::common;

/// The pet store spec the validate handler tests use (`openapi_petstore_example.json`).
const PETSTORE: &str = include_str!("../files/openapi/openapi_petstore_example.json");

/// A forward-with-fallback expectation for `/api` whose upstream (this server, once the forward is used up) answers
/// `upstream`; the answer the client gets.
async fn fallback_exchange(upstream: Value, action: Value) -> common::Response {
    let server = common::start(&[]).await;
    common::expect(server.port, &json!({"httpRequest": {"path": "/api"}, "httpResponse": upstream})).await;
    let mut action = action;
    action["httpForward"] = json!({"host": "localhost", "port": server.port});
    common::expect(server.port, &json!({"httpRequest": {"path": "/api"}, "priority": 10, "times": {"remainingTimes": 1}, "httpForwardWithFallback": action})).await;
    let response = common::send(server.port, "GET", "/api", "").await;
    server.server.shutdown().await;
    response
}

fn fallback(body: &str) -> Value {
    json!({"fallbackResponse": {"statusCode": 200, "body": body}})
}

#[tokio::test(flavor = "multi_thread")]
async fn should_return_upstream_response_when_2xx() {
    let r = fallback_exchange(json!({"statusCode": 200, "body": "upstream OK"}), fallback("fallback")).await;
    assert_eq!((r.status, r.body.as_str()), (200, "upstream OK"));
}

#[tokio::test(flavor = "multi_thread")]
async fn should_return_fallback_when_upstream_returns_5xx() {
    for status in [500, 503, 599] {
        let r = fallback_exchange(json!({"statusCode": status, "body": "Service Unavailable"}), fallback("fallback response")).await;
        assert_eq!((r.status, r.body.as_str()), (200, "fallback response"), "upstream {status}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn should_not_fallback_on_4xx() {
    for status in [404, 499] {
        let r = fallback_exchange(json!({"statusCode": status, "body": "upstream"}), fallback("fallback")).await;
        assert_eq!((r.status, r.body.as_str()), (status, "upstream"), "upstream {status}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn should_fallback_on_custom_status_codes() {
    let mut action = fallback("rate-limited fallback");
    action["fallbackOnStatusCodes"] = json!([429, 503]);
    let r = fallback_exchange(json!({"statusCode": 429, "body": "Too Many Requests"}), action).await;
    assert_eq!((r.status, r.body.as_str()), (200, "rate-limited fallback"));
}

#[tokio::test(flavor = "multi_thread")]
async fn should_not_fallback_on_status_code_not_in_custom_list() {
    let mut action = fallback("fallback");
    action["fallbackOnStatusCodes"] = json!([429, 503]);
    let r = fallback_exchange(json!({"statusCode": 500, "body": "Server Error"}), action).await;
    assert_eq!((r.status, r.body.as_str()), (500, "Server Error"));
}

/// Upstream's client future fails ("Connection timed out"); here the upstream refuses the connection.
#[tokio::test(flavor = "multi_thread")]
async fn should_fallback_on_timeout() {
    for (on_timeout, status, body) in [(None, 200, "timeout fallback"), (Some(false), 502, "")] {
        let server = common::start(&[]).await;
        let mut action = json!({"httpForward": {"host": "localhost", "port": 1}, "fallbackResponse": {"statusCode": 200, "body": "timeout fallback"}});
        if let Some(on) = on_timeout {
            action["fallbackOnTimeout"] = json!(on);
        }
        common::expect(server.port, &json!({"httpRequest": {"path": "/api"}, "httpForwardWithFallback": action})).await;
        let r = common::send(server.port, "GET", "/api", "").await;
        assert_eq!((r.status, r.body.as_str()), (status, body), "fallbackOnTimeout {on_timeout:?}");
        server.server.shutdown().await;
    }
}

/// A validate action for the pet store served once, forwarding to this server, whose own expectation answers
/// `upstream` (if any); the answer and whether the upstream was reached.
async fn validate_exchange(action: Value, method: &str, body: &str, upstream: Option<Value>, properties: &[(&str, &str)]) -> (common::Response, bool) {
    let server = common::start(properties).await;
    if let Some(upstream) = upstream {
        common::expect(server.port, &json!({"id": "upstream", "httpRequest": {"path": "/pets"}, "httpResponse": upstream})).await;
    }
    let mut action = action;
    action["specUrlOrPayload"] = json!(PETSTORE);
    if action.get("host").is_none() {
        action["host"] = json!("localhost");
        action["port"] = json!(server.port);
    }
    common::expect(server.port, &json!({"httpRequest": {"path": "/pets"}, "priority": 10, "times": {"remainingTimes": 1}, "httpForwardValidateAction": action})).await;
    let r = send_json(server.port, method, "/pets", body).await;
    let verified = common::send(server.port, "PUT", "/mockserver/verify", &json!({"expectationId": {"id": "upstream"}, "times": {"atLeast": 1}}).to_string()).await;
    server.server.shutdown().await;
    (r, verified.status == 202)
}

/// One request with a JSON `content-type` when it has a body.
async fn send_json(port: u16, method: &str, path: &str, body: &str) -> common::Response {
    use std::io::{Read, Write};
    let (method, path, body) = (method.to_string(), path.to_string(), body.to_string());
    tokio::task::spawn_blocking(move || {
        let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        let content_type = if body.is_empty() { "" } else { "Content-Type: application/json\r\n" };
        write!(s, "{method} {path} HTTP/1.1\r\nHost: localhost:{port}\r\n{content_type}Content-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
        let mut raw = Vec::new();
        s.read_to_end(&mut raw).unwrap();
        let text = String::from_utf8_lossy(&raw).into_owned();
        let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
        common::Response { status: head.split(' ').nth(1).and_then(|s| s.parse().ok()).unwrap_or(0), head: head.to_string(), body: body.to_string() }
    })
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn should_forward_request_with_host_and_port() {
    let action = json!({"validateRequest": false, "validateResponse": false});
    let (r, reached) = validate_exchange(action, "GET", "", Some(json!({"statusCode": 200, "body": "forwarded"})), &[]).await;
    assert_eq!((r.status, r.body.as_str(), reached), (200, "forwarded", true));
}

#[tokio::test(flavor = "multi_thread")]
async fn should_block_forward_validate_to_private_target_when_ssrf_guard_enabled() {
    let action = json!({"host": "127.0.0.1", "port": 8080, "validateRequest": false, "validateResponse": false});
    let (r, reached) = validate_exchange(action, "GET", "", Some(json!({"statusCode": 200})), &[("forwardProxyBlockPrivateNetworks", "true")]).await;
    assert_eq!((r.status, reached), (502, false));
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reject_non_conformant_request_without_forwarding_in_strict_mode() {
    let action = json!({"validateRequest": true, "validateResponse": false, "validationMode": "STRICT"});
    let (r, reached) = validate_exchange(action, "POST", r#"{"id": "not_a_number", "name": "Fido"}"#, Some(json!({"statusCode": 200, "body": "forwarded"})), &[]).await;
    assert_eq!((r.status, reached), (400, false));
    assert!(r.body.contains("OpenAPI request validation failed"), "{}", r.body);
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reject_non_conformant_upstream_response_with_bad_gateway_in_strict_mode() {
    let action = json!({"validateRequest": false, "validateResponse": true, "validationMode": "STRICT"});
    let upstream = json!({"statusCode": 200, "headers": {"content-type": ["application/json"]}, "body": r#"{"not": "an array"}"#});
    let (r, _) = validate_exchange(action, "GET", "", Some(upstream), &[]).await;
    assert_eq!(r.status, 502);
    assert!(r.body.contains("OpenAPI response validation failed"), "{}", r.body);
}

#[tokio::test(flavor = "multi_thread")]
async fn should_forward_non_conformant_request_unchanged_in_log_only_mode() {
    let action = json!({"validateRequest": true, "validateResponse": false, "validationMode": "LOG_ONLY"});
    let (r, reached) = validate_exchange(action, "POST", r#"{"id": "not_a_number", "name": "Fido"}"#, Some(json!({"statusCode": 200, "body": "forwarded"})), &[]).await;
    assert_eq!((r.status, r.body.as_str(), reached), (200, "forwarded", true));
}

#[tokio::test(flavor = "multi_thread")]
async fn should_return_non_conformant_upstream_response_unchanged_in_log_only_mode() {
    let action = json!({"validateRequest": false, "validateResponse": true, "validationMode": "LOG_ONLY"});
    let upstream = json!({"statusCode": 200, "headers": {"content-type": ["application/json"]}, "body": r#"{"not": "an array"}"#});
    let (r, reached) = validate_exchange(action, "GET", "", Some(upstream), &[]).await;
    assert_eq!((r.status, r.body.as_str(), reached), (200, r#"{"not": "an array"}"#, true));
}

/// `shouldShouldFallbackMethodDefaultsTo5xx`, `…UsesCustomCodes`, `…HandlesEmptyList`, `…HandlesNullStatusCode`.
#[test]
fn should_fallback_defaults_to_5xx_and_honours_custom_codes() {
    use mock_server::should_fallback;
    for (status, expected) in [(500, true), (503, true), (599, true), (499, false), (600, false), (200, false), (404, false)] {
        assert_eq!(should_fallback(Some(status), &[]), expected, "{status} without custom codes");
    }
    for (status, expected) in [(429, true), (503, true), (500, false), (200, false)] {
        assert_eq!(should_fallback(Some(status), &[429, 503]), expected, "{status} with 429, 503");
    }
    assert!(should_fallback(None, &[]), "a missing status falls back");
}
