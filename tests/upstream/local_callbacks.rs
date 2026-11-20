//! Callbacks that upstream's tests keep in the test JVM:
//! - object callbacks "via local JVM" (`LocalCallbackRegistry`), answered in-process without a WebSocket
//!   (`Server::register_object_callback`);
//! - `ForwardClientLazyCreationTest`, which reads the lazily created forward-client event-loop group. mock-server
//!   has no such group; what it stands for is that nothing connects upstream before the first forward, which the
//!   upstream-connection metric shows.

use mock_server::class_callback::{CallbackClass, CallbackError, ForwardCallback};
use serde_json::{Value, json};

use crate::common;

/// `shouldHandleLargeRequestBodyForResponseByObjectCallbackViaLocalJVM`.
async fn large_request_body_by_local_object_callback() {
    let server = common::start(&[]).await;
    server.server.register_object_callback(
        "local-client",
        CallbackClass::new().with_response(|request: &Value| {
            let length = mock_server_integration_testing_callbacks::body_text(request).len();
            Ok(json!({"statusCode": 200, "body": {"type": "JSON", "json": format!("{{\"requestBodyLength\":{length}}}")}, "connectionOptions": {"closeSocket": true}}))
        }),
    );
    common::expect(server.port, &json!({"httpRequest": {"path": "/object_callback"}, "times": {"remainingTimes": 2}, "httpResponseObjectCallback": {"clientId": "local-client"}})).await;
    let size = 5000;
    let body = format!("{{\"largeStringValue\":\"{}\"}}", "a".repeat(size));
    let r = common::exchange(server.port, common::Transport::Http, "POST", "/object_callback", &[("Content-Type", "application/json")], &body).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.text(), format!("{{\"requestBodyLength\":{}}}", size + "{\"largeStringValue\":\"\"}".len()));
}

#[tokio::test(flavor = "multi_thread")]
async fn extended_netty_should_handle_large_request_body_for_response_by_object_callback_via_local_jvm() {
    large_request_body_by_local_object_callback().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn http2_extended_should_handle_large_request_body_for_response_by_object_callback_via_local_jvm() {
    large_request_body_by_local_object_callback().await;
}

/// `forwardCreatesForwardClientGroupLazilyAndForwardingWorks`: a local forward callback, no upstream connection
/// before the first forward, one after it, and the upstream's body returned.
#[tokio::test(flavor = "multi_thread")]
async fn forward_creates_forward_client_group_lazily_and_forwarding_works() {
    struct ToUpstream(u16);
    impl ForwardCallback for ToUpstream {
        fn handle(&self, request: &Value) -> Result<Value, CallbackError> {
            let mut request = request.clone();
            request["path"] = json!("/upstream");
            let headers = request.as_object_mut().unwrap().entry("headers").or_insert_with(|| json!({})).as_object_mut().unwrap();
            headers.retain(|k, _| !k.eq_ignore_ascii_case("host"));
            headers.insert("Host".into(), json!([format!("127.0.0.1:{}", self.0)]));
            Ok(request)
        }
    }

    let upstream = common::start(&[]).await;
    common::expect(upstream.port, &json!({"httpRequest": {"path": "/upstream"}, "httpResponse": {"body": "upstream_body"}})).await;
    let proxy = common::start(&[("metricsEnabled", "true")]).await;
    proxy.server.register_object_callback("forwarder", CallbackClass::new().with_forward(ToUpstream(upstream.port)));
    common::expect(proxy.port, &json!({"httpRequest": {"path": "/proxy"}, "httpForwardObjectCallback": {"clientId": "forwarder"}})).await;
    let connections = |text: &str| text.lines().filter(|l| l.starts_with("mock_server_forward_upstream_protocol_total{")).count();
    let before = common::send(proxy.port, "GET", "/mockserver/metrics", "").await.body;
    assert_eq!(connections(&before), 0, "nothing connects upstream before the first forward");
    assert_eq!(common::send(proxy.port, "GET", "/proxy", "").await.body, "upstream_body");
    let after = common::send(proxy.port, "GET", "/mockserver/metrics", "").await.body;
    assert_eq!(connections(&after), 1, "the first forward connects upstream: {after}");
}
