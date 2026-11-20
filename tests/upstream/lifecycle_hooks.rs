//! In-JVM hooks upstream tests reach through the server object: `MockServer.registerListener`
//! (`MockServerListenerTest`), `mockserver.initializationClass` (`ExpectationInitializerIntegrationTest`), and a second
//! `new MockServer(port)` in the same JVM failing to bind (`PortBindingIntegrationTest`, `ExtendedNettyMockingIntegrationTest`).

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::common;

#[tokio::test(flavor = "multi_thread")]
async fn should_notify_listener() {
    let server = common::start(&[]).await;
    let seen: Arc<Mutex<Vec<Value>>> = Arc::default();
    let sink = seen.clone();
    server.server.register_listener(move |expectations| sink.lock().unwrap().extend(expectations.iter().cloned()));
    common::expect(server.port, &json!({"httpRequest": {"path": "/some/path"}, "httpResponse": {"body": "some_response_body"}})).await;
    let deadline = Instant::now() + Duration::from_secs(5);
    while seen.lock().unwrap().is_empty() && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let seen = seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 1, "{seen:?}");
    let e = &seen[0];
    assert_eq!(e["httpRequest"], json!({"path": "/some/path"}));
    assert_eq!(e["httpResponse"], json!({"body": "some_response_body"}));
    assert_eq!(e["times"], json!({"unlimited": true}));
    assert_eq!(e["timeToLive"], json!({"unlimited": true}));
    assert_eq!(e["priority"], json!(0));
    server.server.shutdown().await;
}

/// `shouldLoadExpectationsFromInitializerClass`: the initializer class is resolved like any callback class.
#[tokio::test(flavor = "multi_thread")]
async fn should_load_expectations_from_initializer_class() {
    let server = common::start_with_callback_classes(&[("initializationClass", "org.mockserver.netty.integration.mock.initializer.ExpectationInitializerIntegrationExample")]).await;
    assert_eq!(common::send(server.port, "GET", "/simpleFirst", "").await.body, "some first response");
    assert_eq!(common::send(server.port, "GET", "/simpleSecond", "").await.body, "some second response");
    server.server.shutdown().await;
}

/// `PortBindingIntegrationTest.throwsExpectionOnPortAlreadyBound`: a second server on a port the first one holds
/// fails to start, with `Exception while binding MockServer to port`.
#[tokio::test(flavor = "multi_thread")]
async fn throws_expection_on_port_already_bound() {
    let first = common::start(&[]).await;
    let mut config = mock_server::Config::for_tests();
    config.ports = vec![first.port];
    let second = mock_server::Server::start(config).await;
    let error = second.err().expect("the second server must not bind a port the first one holds");
    assert!(error.to_string().contains("Exception while binding MockServer to port"), "{error}");
    first.server.shutdown().await;
}

/// `ExtendedNettyMockingIntegrationTest.shouldThrowExceptionIfFailToBindToSocket`: `startClientAndServer` on the port
/// the class's own server already holds fails with `Exception while binding MockServer to port `.
#[tokio::test(flavor = "multi_thread")]
async fn extended_netty_should_throw_exception_if_fail_to_bind_to_socket() {
    let running = common::start(&[]).await;
    let mut config = mock_server::Config::for_tests();
    config.ports = vec![running.port];
    let error = mock_server::Server::start(config).await.err().expect("binding a held port fails");
    assert!(error.to_string().contains(&format!("Exception while binding MockServer to port {}", running.port)), "{error}");
    running.server.shutdown().await;
}
