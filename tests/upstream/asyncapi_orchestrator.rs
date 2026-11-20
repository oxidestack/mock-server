//! `AsyncApiMockOrchestratorTest`, `AsyncApiScheduledPublishResilienceTest` and `AsyncApiOrchestratorStopTest`
//! (mockserver-async): the orchestrator over a stub publisher standing in for the mocked `MessagePublisher`.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use mock_server::asyncapi::broker::{Counters, PublishOptions, Publisher};
use mock_server::asyncapi::orchestrator::{Orchestrator, inject_into_payload};
use mock_server::asyncapi::spec::{Channel, Message, Spec};
use serde_json::{Value, json};

use crate::asyncapi_stubs::StubPublisher;

fn stub() -> (Arc<StubPublisher>, Arc<dyn Publisher>) {
    let s = Arc::new(StubPublisher::default());
    (s.clone(), s)
}

fn orchestrator(channels: Vec<Channel>, publisher: Arc<dyn Publisher>) -> Orchestrator {
    Orchestrator::with_correlation_ids(Arc::new(Spec::new("2.6.0", "Test", channels)), publisher, Counters::default(), Arc::new(|| "fixed-corr-id".to_string()))
}

fn calls(s: &StubPublisher) -> Vec<(String, String, PublishOptions)> {
    s.calls.lock().clone()
}

fn message(name: &str, examples: Vec<Value>, key: Option<&str>, correlation: Option<&str>) -> Message {
    Message {
        name: Some(name.into()),
        payload_schema: None,
        examples,
        kafka_key: key.map(str::to_string),
        correlation_id_location: correlation.map(str::to_string),
    }
}

#[test]
fn correlation_ids_go_into_the_payload() {
    assert_eq!(inject_into_payload(r#"{"a":1}"#, "/id", "x"), r#"{"a":1,"id":"x"}"#);
    assert_eq!(inject_into_payload(r#"{"a":1}"#, "/meta/id", "x"), r#"{"a":1,"meta":{"id":"x"}}"#);
    assert_eq!(inject_into_payload(r#"{"meta":3}"#, "/meta/id", "x"), r#"{"meta":{"id":"x"}}"#);
    assert_eq!(inject_into_payload(r#"[1]"#, "/id", "x"), "[1]");
    assert_eq!(inject_into_payload(r#"{"a":1}"#, "/", "x"), r#"{"a":1}"#);
    assert_eq!(inject_into_payload(r#"{"a":1.50}"#, "/b", "x"), r#"{"a":1.5,"b":"x"}"#);
    // `shouldLeavePayloadUnchangedWhenNotJson`.
    assert_eq!(inject_into_payload("not-valid-json", "/correlationId", "x"), "not-valid-json");
}

// ---- AsyncApiMockOrchestratorTest ----

#[tokio::test]
async fn should_publish_example_for_each_channel() {
    let (s, p) = stub();
    let o = orchestrator(vec![Channel::new("users", vec![json!({"userId": "abc"})], None), Channel::new("orders", vec![json!({"orderId": 42})], None)], p);
    o.publish_all().await.unwrap();
    let c = calls(&s);
    assert_eq!((c[0].0.as_str(), c[0].1.as_str()), ("users", r#"{"userId":"abc"}"#));
    assert_eq!((c[1].0.as_str(), c[1].1.as_str()), ("orders", r#"{"orderId":42}"#));
    assert_eq!(s.flushes.load(Ordering::SeqCst), 1, "delivery must be confirmed before publishAll returns");
}

#[tokio::test]
async fn should_publish_synthesized_payload_when_no_example() {
    let (s, p) = stub();
    orchestrator(
        vec![Channel::new("events", Vec::new(), Some(json!({"type": "object", "properties": {"name": {"type": "string"}}})))],
        p,
    ).publish_all().await.unwrap();
    assert_eq!(calls(&s)[0].1, r#"{"name":"string"}"#);
}

#[tokio::test]
async fn should_publish_empty_object_when_no_example_and_no_schema() {
    let (s, p) = stub();
    orchestrator(vec![Channel::new("empty", Vec::new(), None)], p).publish_all().await.unwrap();
    assert_eq!(calls(&s)[0].1, "{}");
}

#[tokio::test]
async fn should_do_nothing_when_no_channels() {
    let (s, p) = stub();
    orchestrator(Vec::new(), p).publish_all().await.unwrap();
    assert!(calls(&s).is_empty());
    assert_eq!(s.flushes.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn should_start_and_stop_scheduled_publishing() {
    let (s, p) = stub();
    let o = orchestrator(vec![Channel::new("tick", vec![json!({"v": 1})], None)], p);
    o.start_publishing(50);
    tokio::time::sleep(Duration::from_millis(200)).await;
    o.stop().await;
    let published = calls(&s).len();
    assert!(published >= 2, "{published}");
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(calls(&s).len(), published, "nothing is published after stop");
}

#[tokio::test]
async fn should_thread_mqtt_bindings_to_publisher() {
    let (s, p) = stub();
    let channel = Channel { mqtt_qos: Some(2), mqtt_retain: Some(true), ..Channel::new("sensors/temp", vec![json!({"temp": 22})], None) };
    orchestrator(vec![channel], p).publish_all().await.unwrap();
    let o = &calls(&s)[0].2;
    assert_eq!((o.qos, o.retain, o.key.clone()), (Some(2), Some(true), None));
}

#[tokio::test]
async fn should_thread_kafka_key_to_publisher() {
    let (s, p) = stub();
    let channel = Channel { kafka_key: Some("order-key".into()), ..Channel::new("orders", vec![json!({"orderId": 42})], None) };
    orchestrator(vec![channel], p).publish_all().await.unwrap();
    let o = &calls(&s)[0].2;
    assert_eq!((o.key.as_deref(), o.qos), (Some("order-key"), None));
}

#[tokio::test]
async fn should_pass_none_options_when_channel_has_no_bindings() {
    let (s, p) = stub();
    orchestrator(vec![Channel::new("plain", vec![json!({"v": 1})], None)], p).publish_all().await.unwrap();
    let o = &calls(&s)[0].2;
    assert!(o.key.is_none() && o.qos.is_none() && o.retain.is_none() && o.headers.is_empty());
}

#[tokio::test]
async fn should_publish_one_per_message_for_multi_message_channel() {
    let (s, p) = stub();
    let (m1, m2) = (
        message("userEvent", vec![json!({"userId": "u1"})], Some("user-key"), None),
        message("orderEvent", vec![json!({"orderId": 42})], Some("order-key"), None),
    );
    let channel = Channel { kafka_key: Some("user-key".into()), messages: Some(vec![m1, m2]), ..Channel::new("events", vec![json!({"userId": "u1"})], None) };
    orchestrator(vec![channel], p).publish_all().await.unwrap();
    let c = calls(&s);
    assert_eq!(c.len(), 2);
    assert_eq!((c[0].1.as_str(), c[0].2.key.as_deref()), (r#"{"userId":"u1"}"#, Some("user-key")));
    assert_eq!((c[1].1.as_str(), c[1].2.key.as_deref()), (r#"{"orderId":42}"#, Some("order-key")));
}

#[tokio::test]
async fn should_publish_multi_message_with_channel_level_mqtt_bindings() {
    let (s, p) = stub();
    let messages = vec![message("tempMsg", vec![json!({"temp": 22})], None, None), message("humidMsg", vec![json!({"humidity": 60})], None, None)];
    let channel = Channel { mqtt_qos: Some(2), mqtt_retain: Some(true), messages: Some(messages), ..Channel::new("sensors", vec![json!({"temp": 22})], None) };
    orchestrator(vec![channel], p).publish_all().await.unwrap();
    let c = calls(&s);
    assert_eq!(c.len(), 2);
    assert!(c.iter().all(|(_, _, o)| o.qos == Some(2) && o.retain == Some(true) && o.key.is_none()));
}

#[tokio::test]
async fn should_publish_single_message_from_channel_with_no_explicit_messages() {
    let (s, p) = stub();
    let channel = Channel { kafka_key: Some("single-key".into()), ..Channel::new("single", vec![json!({"v": 1})], None) };
    orchestrator(vec![channel], p).publish_all().await.unwrap();
    let c = calls(&s);
    assert_eq!(c.len(), 1);
    assert_eq!((c[0].1.as_str(), c[0].2.key.as_deref()), (r#"{"v":1}"#, Some("single-key")));
    assert_eq!(s.flushes.load(Ordering::SeqCst), 1);
}

fn with_message(name: &str, example: Value, key: Option<&str>, correlation: Option<&str>) -> Channel {
    Channel {
        messages: Some(vec![message("m", vec![example.clone()], key, correlation), message("n", vec![example.clone()], key, correlation)]),
        ..Channel::new(name, vec![example], None)
    }
}

#[tokio::test]
async fn should_inject_correlation_id_into_headers() {
    let (s, p) = stub();
    orchestrator(vec![with_message("orders", json!({"orderId": 42}), None, Some("$message.header#/correlationId"))], p).publish_all().await.unwrap();
    let c = calls(&s);
    assert_eq!(c[0].1, r#"{"orderId":42}"#);
    assert_eq!(c[0].2.headers, [("correlationId".to_string(), "fixed-corr-id".to_string())]);
}

#[tokio::test]
async fn should_inject_correlation_id_into_payload_single_level() {
    let (s, p) = stub();
    orchestrator(vec![with_message("orders", json!({"orderId": 42}), None, Some("$message.payload#/correlationId"))], p).publish_all().await.unwrap();
    let published: Value = serde_json::from_str(&calls(&s)[0].1).unwrap();
    assert_eq!(published["correlationId"], "fixed-corr-id");
}

#[tokio::test]
async fn should_inject_correlation_id_into_payload_nested_pointer() {
    let (s, p) = stub();
    orchestrator(vec![with_message("topic", json!({"data": "hello"}), None, Some("$message.payload#/metadata/id"))], p).publish_all().await.unwrap();
    let published: Value = serde_json::from_str(&calls(&s)[0].1).unwrap();
    assert_eq!(published["metadata"]["id"], "fixed-corr-id");
    assert_eq!(published["data"], "hello");
}

/// Upstream swaps in an example generator that returns `not-valid-json`; the generator is not replaceable here, so the
/// injection is checked on that payload directly, and through the orchestrator on the nearest payload the example
/// generator produces that is no JSON object (a string example): both are published unchanged.
#[tokio::test]
async fn should_leave_payload_unchanged_when_not_json() {
    assert_eq!(inject_into_payload("not-valid-json", "/correlationId", "corr-id"), "not-valid-json");
    let (s, p) = stub();
    orchestrator(vec![with_message("topic", json!("not-valid-json"), None, Some("$message.payload#/correlationId"))], p).publish_all().await.unwrap();
    let c = calls(&s);
    assert_eq!(c[0].0, "topic");
    assert_eq!(c[0].1, r#""not-valid-json""#);
}

#[tokio::test]
async fn should_skip_correlation_id_for_unrecognised_location_prefix() {
    let (s, p) = stub();
    orchestrator(vec![with_message("topic", json!({"v": 1}), None, Some("$message.unknown#/field"))], p).publish_all().await.unwrap();
    let c = calls(&s);
    assert_eq!(c[0].1, r#"{"v":1}"#);
    assert!(c[0].2.headers.is_empty());
}

#[tokio::test]
async fn should_not_inject_correlation_id_when_location_is_null() {
    let (s, p) = stub();
    orchestrator(vec![with_message("topic", json!({"v": 1}), None, None)], p).publish_all().await.unwrap();
    let c = calls(&s);
    assert_eq!(c[0].1, r#"{"v":1}"#);
    assert!(c[0].2.key.is_none() && c[0].2.headers.is_empty());
}

#[tokio::test]
async fn should_combine_correlation_id_header_with_kafka_key() {
    let (s, p) = stub();
    orchestrator(vec![with_message("topic", json!({"v": 1}), Some("my-key"), Some("$message.header#/x-corr-id"))], p).publish_all().await.unwrap();
    let o = &calls(&s)[0].2;
    assert_eq!(o.key.as_deref(), Some("my-key"));
    assert_eq!(o.headers, [("x-corr-id".to_string(), "fixed-corr-id".to_string())]);
}

#[tokio::test]
async fn should_inject_correlation_id_via_channel_synthesized_message() {
    let (s, p) = stub();
    let channel = Channel { correlation_id_location: Some("$message.header#/corrId".into()), ..Channel::new("topic", vec![json!({"v": 1})], None) };
    orchestrator(vec![channel], p).publish_all().await.unwrap();
    assert_eq!(calls(&s)[0].2.headers, [("corrId".to_string(), "fixed-corr-id".to_string())]);
}

// ---- AsyncApiScheduledPublishResilienceTest ----

#[tokio::test(flavor = "multi_thread")]
async fn schedule_should_survive_a_failing_publish_cycle() {
    let (s, p) = stub();
    s.failing.lock().push("events".into());
    let o = orchestrator(vec![Channel::new("events", vec![json!({"v": 1})], None)], p);
    o.start_publishing(50);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while calls(&s).len() < 3 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(calls(&s).len() >= 3, "the schedule must keep running after a cycle fails");
    assert!(o.last_publish_failure().is_some_and(|f| f.contains("was not routed to any queue")));
    o.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn schedule_should_recover_once_publishing_succeeds_again() {
    let (s, p) = stub();
    s.fail_first.store(2, Ordering::SeqCst);
    let o = orchestrator(vec![Channel::new("events", vec![json!({"v": 1})], None)], p);
    o.start_publishing(50);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while calls(&s).len() < 4 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    o.stop().await;
    assert!(calls(&s).len() >= 4, "publishing must resume once the underlying cause clears");
    assert_eq!(o.last_publish_failure(), None, "a recovered cycle clears the recorded failure");
}

#[tokio::test]
async fn one_failing_channel_should_not_stop_the_others_publishing() {
    let (s, p) = stub();
    s.failing.lock().push("unbound".into());
    let channels = ["unbound", "healthy-a", "healthy-b"].iter().map(|n| Channel::new(n, vec![json!({"v": 1})], None)).collect();
    let failure = orchestrator(channels, p).publish_all().await.unwrap_err();
    let delivered: Vec<String> = calls(&s).into_iter().map(|(c, _, _)| c).filter(|c| c != "unbound").collect();
    assert_eq!(delivered, ["healthy-a", "healthy-b"]);
    assert_eq!(failure.message, "Publish cycle completed with 1 failure(s): unbound: was not routed to any queue");
}

// ---- AsyncApiOrchestratorStopTest ----

#[tokio::test(flavor = "multi_thread")]
async fn stop_should_wait_for_an_in_flight_publish_to_finish() {
    let (s, p) = stub();
    *s.delay.lock() = Some(Duration::from_millis(300));
    let o = orchestrator(vec![Channel::new("slow", vec![json!({"v": 1})], None)], p);
    o.start_publishing(10_000);
    tokio::time::sleep(Duration::from_millis(50)).await;
    o.stop().await;
    assert_eq!(calls(&s).len(), 1, "stop returns only once the publish in flight has completed");
}

#[tokio::test]
async fn stop_should_be_idempotent_and_return_promptly_when_idle() {
    let (_, p) = stub();
    let o = orchestrator(vec![Channel::new("idle", vec![json!({"v": 1})], None)], p);
    let started = std::time::Instant::now();
    o.stop().await;
    o.stop().await;
    assert!(started.elapsed() < Duration::from_secs(1));
}
