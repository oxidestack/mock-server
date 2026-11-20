//! Ports of mockserver-core's `RequestMatchersNamespaceTest` parts the oracle scenarios (`w2_ns_*`) cannot show:
//! the DEBUG diagnostic for a namespace-gated miss, and which clears log what.

use std::io::{Read, Write};

use serde_json::json;

use crate::common;

/// One request with extra headers on its own connection; the status and body.
async fn send(port: u16, method: &str, path: &str, headers: &[(&str, &str)], body: &str) -> (u16, String) {
    let (method, path, body) = (method.to_string(), path.to_string(), body.to_string());
    let headers: String = headers.iter().map(|(k, v)| format!("{k}: {v}\r\n")).collect();
    tokio::task::spawn_blocking(move || {
        let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        write!(s, "{method} {path} HTTP/1.1\r\nHost: localhost:{port}\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
        let mut raw = Vec::new();
        s.read_to_end(&mut raw).unwrap();
        let text = String::from_utf8_lossy(&raw).into_owned();
        let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
        (head.split(' ').nth(1).and_then(|s| s.parse().ok()).unwrap_or(0), body.to_string())
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn namespace_gated_silence_emits_debug_diagnostic() {
    let running = common::start(&[("logLevel", "DEBUG")]).await;
    common::expect(running.port, &json!({"httpRequest": {"path": "/somePath"}, "httpResponse": {"body": "a"}, "namespace": "team-a"})).await;
    let (status, _) = send(running.port, "GET", "/somePath", &[("X-MockServer-Namespace", "team-b")], "").await;
    assert_eq!(status, 404);
    let logs = common::logs(running.port).await;
    assert!(logs.contains("request in namespace:\n\n  team-b\n\n did not match any expectation; 1 expectation(s) skipped due to namespace mismatch"), "{logs}");
}

#[tokio::test]
async fn no_namespace_mismatch_produces_no_namespace_diagnostic() {
    let running = common::start(&[("logLevel", "DEBUG")]).await;
    common::expect(running.port, &json!({"httpRequest": {"path": "/somePath"}, "httpResponse": {"body": "g"}})).await;
    let (status, _) = send(running.port, "GET", "/otherPath", &[], "").await;
    assert_eq!(status, 404);
    // A namespaced request that is not gated (only global expectations exist) is silent too.
    let (status, _) = send(running.port, "GET", "/otherPath", &[("X-MockServer-Namespace", "team-a")], "").await;
    assert_eq!(status, 404);
    assert!(!common::logs(running.port).await.contains("namespace mismatch"));
}

#[tokio::test]
async fn namespace_diagnostic_is_debug_only() {
    let running = common::start(&[]).await;
    common::expect(running.port, &json!({"httpRequest": {"path": "/somePath"}, "httpResponse": {"body": "a"}, "namespace": "team-a"})).await;
    send(running.port, "GET", "/somePath", &[("X-MockServer-Namespace", "team-b")], "").await;
    assert!(!common::logs(running.port).await.contains("namespace mismatch"));
}

#[tokio::test]
async fn clear_by_namespace_emits_cleared_log_only_when_something_removed() {
    let running = common::start(&[]).await;
    common::expect(running.port, &json!({"httpRequest": {"path": "/a"}, "httpResponse": {"body": "a"}, "namespace": "team-a"})).await;
    common::expect(running.port, &json!({"httpRequest": {"path": "/g"}, "httpResponse": {"body": "g"}})).await;
    assert_eq!(send(running.port, "PUT", "/mockserver/clear?namespace=team-z", &[], "").await.0, 200);
    assert!(!common::logs(running.port).await.contains("cleared expectations in namespace"));
    assert_eq!(send(running.port, "PUT", "/mockserver/clear?namespace=team-a", &[], "").await.0, 200);
    let logs = common::logs(running.port).await;
    assert!(logs.contains("cleared expectations in namespace:\n\n  team-a\n"), "{logs}");
    assert_eq!(logs.matches("removed expectation:").count(), 1);
    // The global expectation is left, and so is the log.
    assert_eq!(send(running.port, "GET", "/g", &[], "").await, (200, "g".to_string()));
    assert_eq!(send(running.port, "GET", "/a", &[("X-MockServer-Namespace", "team-a")], "").await.0, 404);
}

#[tokio::test]
async fn clear_by_blank_namespace_is_no_op() {
    let running = common::start(&[]).await;
    common::expect(running.port, &json!({"httpRequest": {"path": "/a"}, "httpResponse": {"body": "a"}, "namespace": "team-a"})).await;
    common::expect(running.port, &json!({"httpRequest": {"path": "/g"}, "httpResponse": {"body": "g"}, "namespace": "  "})).await;
    // A blank header is no namespace: the request-matcher clear applies instead. A blank `?namespace=` is refused
    // since 9.2.0 (`ExpectationFilter.requireComplete`), as a clear of every namespace would surprise.
    assert_eq!(send(running.port, "PUT", "/mockserver/clear?type=expectations&namespace=%20", &[], r#"{"path": "/nothing"}"#).await.0, 400);
    assert_eq!(send(running.port, "PUT", "/mockserver/clear?type=expectations", &[("X-MockServer-Namespace", " ")], r#"{"path": "/nothing"}"#).await.0, 200);
    assert_eq!(send(running.port, "GET", "/a", &[("X-MockServer-Namespace", "team-a")], "").await, (200, "a".to_string()));
    assert_eq!(send(running.port, "GET", "/g", &[], "").await, (200, "g".to_string()));
}

#[tokio::test]
async fn namespace_header_does_not_participate_in_normal_header_matching() {
    let running = common::start(&[]).await;
    common::expect(running.port, &json!({"httpRequest": {"path": "/somePath", "headers": {"X-Custom": ["value"]}}, "httpResponse": {"body": "someBody"}})).await;
    let r = send(running.port, "GET", "/somePath", &[("X-Custom", "value"), ("X-MockServer-Namespace", "team-a")], "").await;
    assert_eq!(r, (200, "someBody".to_string()));
}

/// A bidi `Chat` call with `X-MockServer-Namespace: team-a`: the `greeting`s streamed back and the `grpc-status`.
async fn tenant_chat(port: u16) -> (Vec<String>, Option<String>) {
    use http_body_util::BodyExt;
    let frames = vec![crate::grpc_bidi_breakpoints::chat_frame("Alice")];
    let (connection, response) = crate::grpc_bidi_breakpoints::open_at(port, "/com.example.grpc.GreetingService/Chat", frames, &[("x-mockserver-namespace", "team-a")]).await;
    let status = response.headers().get("grpc-status").and_then(|v| v.to_str().ok()).map(str::to_string);
    let mut body = response.into_body();
    let (mut data, mut trailer_status) = (Vec::new(), status);
    while let Some(Ok(frame)) = body.frame().await {
        if let Some(chunk) = frame.data_ref() {
            data.extend_from_slice(chunk);
        }
        if let Some(t) = frame.trailers_ref() {
            trailer_status = t.get("grpc-status").and_then(|v| v.to_str().ok()).map(str::to_string);
        }
    }
    connection.abort();
    (crate::grpc_bidi_breakpoints::greetings(&data), trailer_status)
}

async fn bidi_server() -> common::Running {
    let descriptors = concat!(env!("CARGO_MANIFEST_DIR"), "/upstream/mockserver/mockserver/mockserver-core/src/test/resources/grpc");
    let server = common::start(&[("grpcDescriptorDirectory", descriptors), ("grpcBidiStreamingEnabled", "true")]).await;
    common::expect(
        server.port,
        &json!({
            "httpRequest": {"method": "POST", "path": "/com.example.grpc.GreetingService/Chat"},
            "grpcBidiResponse": {"statusName": "OK", "rules": [{"matchJson": ".*Alice.*", "responses": [{"json": "{\"greeting\": \"Hello Alice\"}"}]}]},
            "namespace": "team-a"
        }),
    )
    .await;
    server
}

/// `GrpcBidiRouterHandler.findAndConsumeMatchingBidiResponse`: the tenant's bidi expectation streams.
#[tokio::test(flavor = "multi_thread")]
async fn grpc_bidi_serves_the_tenants_bidi_expectation() {
    let server = bidi_server().await;
    assert_eq!(tenant_chat(server.port).await.0, vec!["Hello Alice".to_string()]);
}

/// `peekFirstMatchingExpectation` is not namespace-gated: another tenant's higher-priority expectation that is not a
/// bidi one wins the peek, so the call leaves the bidi router for the ordinary gRPC path and streams no rule's
/// responses. (Only the consuming match that follows a successful peek is gated.)
#[tokio::test(flavor = "multi_thread")]
async fn grpc_bidi_peek_ignores_namespaces_and_falls_back() {
    let server = bidi_server().await;
    common::expect(
        server.port,
        &json!({"priority": 10, "httpRequest": {"method": "POST", "path": "/com.example.grpc.GreetingService/Chat"}, "httpResponse": {"body": "other tenant"}, "namespace": "team-b"}),
    )
    .await;
    let (greetings, _) = tenant_chat(server.port).await;
    assert!(greetings.is_empty(), "{greetings:?}");
}
