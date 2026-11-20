//! `HttpStateSchedulerShutdownTest` and `MockServerEventLogEventualVerificationTest
//! .shouldAnswerAtOnceWhenTheSchedulerShutsDownAsTheDeadlineIsArmed` (upstream fe354ebd5, #118): once the scheduler
//! is shut down, a control-plane request whose work is offloaded onto it answers `503` itself instead of never
//! answering, and a verification with a `timeout` answers at once.
//!
//! In a stopping server that window lies between `scheduler.shutdown()` (after the drain) and the worker group's close
//! a few milliseconds later (`LifeCycle.stopAsync`), too short for a process scenario to time. Upstream's test shuts
//! the scheduler down on a running `HttpState`; these do the same to an in-process server through
//! `Server::shut_down_scheduler`, and send the requests over HTTP.

use std::time::{Duration, Instant};

use serde_json::json;

use crate::common;

fn petstore() -> String {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/upstream/mockserver/mockserver/mockserver-core/src/test/resources/org/mockserver/openapi/openapi_petstore_example.json");
    std::fs::read_to_string(path).expect("upstream/mockserver is initialised")
}

async fn shut_down() -> common::Running {
    let running = common::start(&[]).await;
    running.server.shut_down_scheduler();
    running
}

fn content_type(head: &str) -> Option<&str> {
    head.lines().find_map(|l| l.split_once(':').filter(|(n, _)| n.eq_ignore_ascii_case("content-type")).map(|(_, v)| v.trim()))
}

/// `dispatchOffTheEventLoop`'s refusal: `writeResponse(request, SERVICE_UNAVAILABLE, "unable to schedule request",
/// "text/plain")`.
fn assert_unable_to_schedule(response: &common::Response) {
    assert_eq!(response.status, 503, "{}\n{}", response.head, response.body);
    assert_eq!(response.body, "unable to schedule request");
    assert_eq!(content_type(&response.head), Some("text/plain; charset=utf-8"));
}

#[tokio::test(flavor = "multi_thread")]
async fn answers_an_open_api_import_with_503() {
    let running = shut_down().await;
    let response = common::send(running.port, "PUT", "/mockserver/openapi", &json!({"specUrlOrPayload": petstore()}).to_string()).await;
    assert_unable_to_schedule(&response);
    let active = common::send(running.port, "PUT", "/mockserver/retrieve?type=ACTIVE_EXPECTATIONS", "").await;
    assert_eq!(active.body.trim(), "[]", "the import never ran");
    running.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn answers_a_request_definition_naming_a_spec_with_503() {
    let running = shut_down().await;
    let spec = json!({"httpRequest": {"specUrlOrPayload": petstore(), "operationId": "listPets"}, "httpResponse": {"statusCode": 200}});
    assert_unable_to_schedule(&common::send(running.port, "PUT", "/mockserver/expectation", &spec.to_string()).await);
    // the bare alias is offloaded too (`request.matches("PUT", PATH_PREFIX + route, route)`)
    assert_unable_to_schedule(&common::send(running.port, "PUT", "/expectation", &spec.to_string()).await);
    // an expectation that names no spec is not offloaded
    let plain = common::send(running.port, "PUT", "/mockserver/expectation", &json!({"httpRequest": {"path": "/a"}, "httpResponse": {"statusCode": 200}}).to_string()).await;
    assert_eq!(plain.status, 201, "{}", plain.body);
    running.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn answers_a_retrieve_extracting_bodies_to_files_with_503() {
    let running = shut_down().await;
    let response = common::send(running.port, "PUT", "/mockserver/retrieve?type=RECORDED_EXPECTATIONS&extractBodiesLargerThan=10", "").await;
    assert_unable_to_schedule(&response);
    let plain = common::send(running.port, "PUT", "/mockserver/retrieve?type=RECORDED_EXPECTATIONS", "").await;
    assert_eq!(plain.status, 200, "{}", plain.body);
    running.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn answers_a_contract_test_with_503() {
    let running = shut_down().await;
    let body = json!({"spec": petstore(), "baseUrl": format!("http://localhost:{}", running.port), "operationId": "listPets"});
    let response = common::send(running.port, "PUT", "/mockserver/contractTest", &body.to_string()).await;
    assert_eq!(response.status, 503, "{}", response.body);
    assert_eq!(response.body, r#"{"error":"unable to schedule contract test: MockServer is stopping"}"#);
    assert_eq!(content_type(&response.head), Some("application/json; charset=utf-8"));
    running.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn answers_a_traffic_validation_with_503() {
    let running = shut_down().await;
    let response = common::send(running.port, "PUT", "/mockserver/trafficValidate", &json!({"spec": petstore()}).to_string()).await;
    assert_eq!(response.status, 503, "{}", response.body);
    assert_eq!(response.body, r#"{"error":"unable to schedule traffic validation: MockServer is stopping"}"#);
    assert_eq!(content_type(&response.head), Some("application/json; charset=utf-8"));
    running.server.shutdown().await;
}

/// `shouldAnswerAtOnceWhenTheSchedulerShutsDownAsTheDeadlineIsArmed`: the verification fails at once, rather than
/// waiting for a deadline nothing would fire.
#[tokio::test(flavor = "multi_thread")]
async fn answers_a_verification_with_a_timeout_at_once() {
    let running = shut_down().await;
    let started = Instant::now();
    let verification = json!({"httpRequest": {"path": "/never/arrives"}, "times": {"atLeast": 1, "atMost": 1}, "timeout": 20_000});
    let response = common::send(running.port, "PUT", "/mockserver/verify", &verification.to_string()).await;
    assert_eq!(response.status, 406, "{}", response.body);
    assert!(response.body.contains("/never/arrives"), "{}", response.body);
    assert!(started.elapsed() < Duration::from_secs(10), "answered after {:?}", started.elapsed());
    running.server.shutdown().await;
}
