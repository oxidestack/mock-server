//! `WebsocketCallbackRegistryIntegrationTest`: the WebSocket callback registry's counts (`Metrics`) as clients
//! register and leave, and as matched requests wait on them. Upstream reads the in-JVM `Metrics`; these read
//! `Server::metric`. The WebSocket client is the Java client's protocol, spoken by `common::callback_client`.

use std::sync::Arc;

use serde_json::{Value, json};

use crate::common::{self, Answer};

const CLIENTS: &str = "WEBSOCKET_CALLBACK_CLIENTS_COUNT";
const RESPONSE_HANDLERS: &str = "WEBSOCKET_CALLBACK_RESPONSE_HANDLERS_COUNT";
const FORWARD_HANDLERS: &str = "WEBSOCKET_CALLBACK_FORWARD_HANDLERS_COUNT";
const REQUEST: &str = "org.mockserver.model.HttpRequest";
const RESPONSE: &str = "org.mockserver.model.HttpResponse";

async fn server() -> Arc<common::Running> {
    Arc::new(common::start(&[("metricsEnabled", "true")]).await)
}

fn metric(server: &common::Running, name: &str) -> i64 {
    server.server.metric(name).unwrap()
}

/// An upstream that echoes the request body (upstream's `insecureEchoServer`).
async fn echo_server() -> common::Running {
    let echo = common::start(&[]).await;
    common::expect(echo.port, &json!({"httpRequest": {}, "httpResponseTemplate": {"templateType": "VELOCITY", "template": "{'statusCode': 200, 'body': '$!request.body'}"}})).await;
    echo
}

#[tokio::test(flavor = "multi_thread")]
async fn should_remove_websocket_callback_client_from_registry_for_client_reset_via_web_socket() {
    let server = server().await;
    let client = common::callback_client(server.port, Arc::new(|_: &str, _: &Value| (RESPONSE.to_string(), json!({})))).await;
    common::expect(server.port, &json!({"httpRequest": {}, "httpResponseObjectCallback": {"clientId": client.id}})).await;
    assert!(common::eventually(|| metric(&server, CLIENTS) == 1).await);
    assert_eq!(common::send(server.port, "PUT", "/mockserver/reset", "").await.status, 200);
    assert!(common::eventually(|| metric(&server, CLIENTS) == 0).await, "reset removes the client");
}

#[tokio::test(flavor = "multi_thread")]
async fn should_remove_websocket_callback_client_from_registry_for_client_stop_via_web_socket() {
    let server = server().await;
    let client = common::callback_client(server.port, Arc::new(|_: &str, _: &Value| (RESPONSE.to_string(), json!({})))).await;
    common::expect(server.port, &json!({"httpRequest": {}, "httpResponseObjectCallback": {"clientId": client.id}})).await;
    assert!(common::eventually(|| metric(&server, CLIENTS) == 1).await);
    server.server.stop_async().await.unwrap();
    assert!(common::eventually(|| metric(&server, CLIENTS) == 0).await, "stop removes the client");
}

#[tokio::test(flavor = "multi_thread")]
async fn should_remove_websocket_response_handler_from_registry_via_web_socket() {
    let server = server().await;
    let s = server.clone();
    let answer: Answer = Arc::new(move |_: &str, _: &Value| {
        (RESPONSE.to_string(), json!({"body": format!("websocket_response_handler_count_{}_{}", metric(&s, RESPONSE_HANDLERS), metric(&s, FORWARD_HANDLERS))}))
    });
    let client = common::callback_client(server.port, answer).await;
    common::expect(server.port, &json!({"httpRequest": {"path": "/websocket_response_handler"}, "times": {"remainingTimes": 1}, "httpResponseObjectCallback": {"clientId": client.id}})).await;
    assert!(common::eventually(|| metric(&server, CLIENTS) == 1).await);
    let r = common::send(server.port, "GET", "/websocket_response_handler", "").await;
    assert_eq!((r.status, r.body.as_str()), (200, "websocket_response_handler_count_1_0"));
    assert_eq!(metric(&server, RESPONSE_HANDLERS), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn should_remove_websocket_forward_handler_from_registry_via_web_socket() {
    let server = server().await;
    let echo = echo_server().await;
    let (s, echo_port) = (server.clone(), echo.port);
    let answer: Answer = Arc::new(move |_: &str, _: &Value| {
        let body = format!("websocket_forward_handler_count_{}_{}", metric(&s, FORWARD_HANDLERS), metric(&s, RESPONSE_HANDLERS));
        (REQUEST.to_string(), json!({"headers": {"Host": [format!("localhost:{echo_port}")]}, "body": body}))
    });
    let client = common::callback_client(server.port, answer).await;
    common::expect(server.port, &json!({"httpRequest": {"path": "/websocket_forward_handler"}, "httpForwardObjectCallback": {"clientId": client.id}})).await;
    assert!(common::eventually(|| metric(&server, CLIENTS) == 1).await);
    let r = common::send(server.port, "GET", "/websocket_forward_handler", "").await;
    assert_eq!((r.status, r.body.as_str()), (200, "websocket_forward_handler_count_1_0"));
    assert!(common::eventually(|| metric(&server, FORWARD_HANDLERS) == 0).await);
}

#[tokio::test(flavor = "multi_thread")]
async fn should_remove_websocket_forward_and_response_handler_from_registry_via_web_socket() {
    let server = server().await;
    let echo = echo_server().await;
    let (s, echo_port) = (server.clone(), echo.port);
    let answer: Answer = Arc::new(move |kind: &str, value: &Value| {
        let counts = format!("websocket_forward_handler_count_{}_{}", metric(&s, FORWARD_HANDLERS), metric(&s, RESPONSE_HANDLERS));
        if kind.ends_with("HttpRequestAndHttpResponse") {
            let mut response = value["httpResponse"].clone();
            let headers = response.as_object_mut().unwrap().entry("headers").or_insert_with(|| json!({}));
            headers.as_object_mut().unwrap().insert("x-response-test".into(), json!([counts]));
            (RESPONSE.to_string(), response)
        } else {
            (REQUEST.to_string(), json!({"headers": {"Host": [format!("localhost:{echo_port}")]}, "body": counts}))
        }
    });
    let client = common::callback_client(server.port, answer).await;
    common::expect(
        server.port,
        &json!({"httpRequest": {"path": "/websocket_forward_handler"}, "times": {"remainingTimes": 1}, "httpForwardObjectCallback": {"clientId": client.id, "responseCallback": true}}),
    )
    .await;
    assert!(common::eventually(|| metric(&server, CLIENTS) == 1).await);
    let r = common::exchange(server.port, common::Transport::Http, "GET", "/websocket_forward_handler", &[], "").await;
    assert_eq!(r.status, 200);
    assert_eq!(r.header("x-response-test"), Some("websocket_forward_handler_count_0_1"));
    assert_eq!(r.text(), "websocket_forward_handler_count_1_0");
    assert!(common::eventually(|| metric(&server, FORWARD_HANDLERS) == 0 && metric(&server, RESPONSE_HANDLERS) == 0).await);
}

/// A forward class callback with state of its own (`TestExpectationForwardAndResponseCallback`'s statics), through
/// a proxy to an upstream that closes each connection, 500 times.
#[tokio::test(flavor = "multi_thread")]
async fn should_forward_large_number_of_modified_request_and_return_modified_response_by_class_callback() {
    use mock_server::class_callback::{CallbackClass, CallbackError, ForwardAndResponseCallback};

    struct Modify {
        port: u16,
        added: String,
    }

    impl ForwardAndResponseCallback for Modify {
        fn handle(&self, request: &Value) -> Result<Value, CallbackError> {
            let mut request = request.clone();
            let headers = request.as_object_mut().unwrap().entry("headers").or_insert_with(|| json!({}));
            let headers = headers.as_object_mut().unwrap();
            headers.retain(|k, _| !k.eq_ignore_ascii_case("host"));
            headers.insert("host".into(), json!([format!("localhost:{}", self.port)]));
            Ok(request)
        }

        fn handle_response(&self, request: &Value, response: &Value) -> Result<Value, CallbackError> {
            let counter = mock_server_integration_testing_callbacks::first_header(request, "Counter");
            let mut response = response.clone();
            let o = response.as_object_mut().unwrap();
            o.insert("reasonPhrase".into(), json!(format!("OK {counter}")));
            o.insert("body".into(), json!(format!("modified body response {counter}")));
            let headers = o.entry("headers").or_insert_with(|| json!({})).as_object_mut().unwrap();
            headers.retain(|k, _| !k.eq_ignore_ascii_case("content-length"));
            headers.insert("AddedHeader".into(), json!([self.added]));
            Ok(response)
        }
    }

    let upstream = common::start(&[]).await;
    common::expect(
        upstream.port,
        &json!({"httpRequest": {"method": "GET", "path": "/api/v1/employees"}, "httpResponse": {"body": "original body response", "connectionOptions": {"suppressContentLengthHeader": true, "closeSocket": true}}}),
    )
    .await;
    let added = uuid::Uuid::new_v4().to_string();
    let proxy = common::start(&[]).await;
    proxy.server.register_callback_class("TestExpectationForwardAndResponseCallback", CallbackClass::new().with_forward_and_response(Modify { port: upstream.port, added: added.clone() }));
    common::expect(proxy.port, &json!({"httpRequest": {"path": "/api/v1/employees"}, "httpForwardClassCallback": {"callbackClass": "TestExpectationForwardAndResponseCallback"}})).await;
    for counter in 0..500 {
        let c = counter.to_string();
        let r = common::exchange(proxy.port, common::Transport::Http, "GET", "/api/v1/employees", &[("Counter", c.as_str())], "").await;
        assert_eq!(r.status, 200, "request {counter}");
        assert_eq!(r.header("AddedHeader"), Some(added.as_str()), "request {counter}");
        assert_eq!(r.text(), format!("modified body response {counter}"), "request {counter}");
    }
}
