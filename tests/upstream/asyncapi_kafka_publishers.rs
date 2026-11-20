//! `KafkaMessagePublisherTest`, `KafkaMessagePublisherKeyHeadersTest`, `KafkaMessagePublisherDeliveryFailureTest` and
//! `KafkaAvroMessagePublisherTest` (mockserver-async). Upstream captures the `ProducerRecord` a mocked
//! `KafkaProducer` is given and drives its send callback; here the record is what `kafka::producer_record` builds for
//! a publish (the publisher sends exactly that), and the callback and `flush` are `kafka::Deliveries`, which the
//! publisher's sender reports to. Upstream's `publish(channel, key, payload, headers)` overload is the options' key
//! and headers here; a Java `null` for the options is `PublishOptions::none()`.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use mock_server::asyncapi::avro;
use mock_server::asyncapi::broker::{Error, PublishOptions, Publisher};
use mock_server::asyncapi::kafka::{AvroWriter, Deliveries, KafkaPublisher, ProducerRecord, producer_record};
use mock_server::asyncapi::registry::SchemaRegistryClient;
use serde_json::{Value, json};

use crate::common;

fn options(key: Option<&str>, headers: &[(&str, &str)]) -> PublishOptions {
    PublishOptions::new(key, None, None, headers).unwrap()
}

async fn record(channel: &str, payload: &str, options: &PublishOptions) -> ProducerRecord {
    producer_record(None, channel, payload, options).await.unwrap()
}

/// `record.headers().lastHeader(name)` as UTF-8.
fn last_header<'a>(record: &'a ProducerRecord, name: &str) -> Option<&'a str> {
    record.headers.iter().rev().find(|(k, _)| k == name).map(|(_, v)| std::str::from_utf8(v).unwrap())
}

// ---- KafkaMessagePublisherTest ----

#[tokio::test]
async fn should_send_producer_record_with_topic_and_payload() {
    let r = record("my-topic", r#"{"key":"value"}"#, &PublishOptions::none()).await;
    assert_eq!(r.topic, "my-topic");
    assert_eq!(r.value, r#"{"key":"value"}"#.as_bytes());
}

/// Upstream verifies the producer's `close()`; the closed producer is what shows here: it refuses the next send as
/// `KafkaProducer.send` does (`throwIfProducerClosed`), without waiting for any broker.
#[tokio::test]
async fn should_close_underlying_producer() {
    let publisher = KafkaPublisher::new("localhost:9092", None, None).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), publisher.close()).await.expect("close returns");
    let refused = tokio::time::timeout(Duration::from_secs(5), publisher.publish("my-topic", "{}", &PublishOptions::none())).await.expect("refused at once");
    assert_eq!(refused.unwrap_err().message, "Cannot perform operation after producer has been closed");
}

// ---- KafkaMessagePublisherKeyHeadersTest ----

#[tokio::test]
async fn should_send_record_with_key() {
    let r = record("my-topic", r#"{"data":1}"#, &options(Some("my-key"), &[])).await;
    assert_eq!((r.topic.as_str(), r.key.as_deref()), ("my-topic", Some("my-key")));
    assert_eq!(r.value, r#"{"data":1}"#.as_bytes());
}

#[tokio::test]
async fn should_send_record_with_null_key() {
    assert_eq!(record("my-topic", r#"{"data":1}"#, &options(None, &[])).await.key, None);
}

#[tokio::test]
async fn should_send_record_with_headers() {
    let r = record("my-topic", r#"{"data":1}"#, &options(Some("key1"), &[("trace-id", "abc123"), ("content-type", "application/json")])).await;
    assert_eq!(last_header(&r, "trace-id"), Some("abc123"));
    assert_eq!(last_header(&r, "content-type"), Some("application/json"));
}

#[tokio::test]
async fn should_send_without_headers_when_null() {
    assert!(record("my-topic", r#"{"data":1}"#, &options(Some("key1"), &[])).await.headers.is_empty());
}

#[tokio::test]
async fn should_send_via_default_interface_method() {
    let r = record("my-topic", r#"{"simple":true}"#, &PublishOptions::none()).await;
    assert_eq!((r.topic.as_str(), r.key.as_deref()), ("my-topic", None));
    assert_eq!(r.value, r#"{"simple":true}"#.as_bytes());
}

// ---- PublishOptions tests ----

#[tokio::test]
async fn should_send_with_key_from_publish_options() {
    let r = record("my-topic", r#"{"data":1}"#, &PublishOptions::new(Some("options-key"), None, None, &[]).unwrap()).await;
    assert_eq!((r.topic.as_str(), r.key.as_deref()), ("my-topic", Some("options-key")));
    assert_eq!(r.value, r#"{"data":1}"#.as_bytes());
}

#[tokio::test]
async fn should_send_with_null_key_when_publish_options_has_no_key() {
    let r = record("my-topic", r#"{"data":1}"#, &PublishOptions::new(None, Some(2), Some(true), &[]).unwrap()).await;
    assert_eq!(r.key, None);
}

#[tokio::test]
async fn should_send_with_null_key_when_publish_options_are_null() {
    assert_eq!(record("my-topic", r#"{"data":1}"#, &PublishOptions::default()).await.key, None);
}

#[tokio::test]
async fn should_send_with_null_key_when_publish_options_none() {
    assert_eq!(record("my-topic", r#"{"data":1}"#, &PublishOptions::none()).await.key, None);
}

// ---- PublishOptions with headers tests ----

#[tokio::test]
async fn should_send_headers_from_publish_options() {
    let r = record("my-topic", r#"{"data":1}"#, &options(Some("key1"), &[("correlationId", "corr-123")])).await;
    assert_eq!(r.key.as_deref(), Some("key1"));
    assert_eq!(last_header(&r, "correlationId"), Some("corr-123"));
}

#[tokio::test]
async fn should_not_add_headers_from_publish_options_when_empty() {
    assert!(record("my-topic", r#"{"data":1}"#, &options(Some("key1"), &[])).await.headers.is_empty());
}

#[tokio::test]
async fn should_combine_key_and_headers_from_publish_options() {
    let r = record("my-topic", r#"{"data":1}"#, &options(Some("my-key"), &[("x-corr-id", "abc"), ("x-trace-id", "xyz")])).await;
    assert_eq!(r.key.as_deref(), Some("my-key"));
    assert_eq!(r.headers.len(), 2);
    assert_eq!(last_header(&r, "x-corr-id"), Some("abc"));
    assert_eq!(last_header(&r, "x-trace-id"), Some("xyz"));
}

// ---- KafkaMessagePublisherDeliveryFailureTest ----

#[tokio::test(flavor = "multi_thread")]
async fn flush_should_drain_the_producer() {
    let deliveries = Arc::new(Deliveries::default());
    let acknowledged = Arc::new(AtomicBool::new(false));
    deliveries.started();
    tokio::spawn({
        let (deliveries, acknowledged) = (deliveries.clone(), acknowledged.clone());
        async move {
            tokio::time::sleep(Duration::from_millis(200)).await;
            acknowledged.store(true, Ordering::SeqCst);
            deliveries.completed("my-topic", Ok(()));
        }
    });
    deliveries.flush("message").await.unwrap();
    assert!(acknowledged.load(Ordering::SeqCst), "flush returns only once the send in flight has been acknowledged");
}

#[tokio::test]
async fn flush_should_report_a_delivery_failure() {
    let deliveries = Deliveries::default();
    deliveries.started();
    deliveries.completed("my-topic", Err(Error::new("broker unreachable")));
    let failure = deliveries.flush("message").await.expect_err("a failed delivery must be reported to the caller, not only logged");
    assert!(failure.message.contains("my-topic") && failure.message.contains("broker unreachable"), "{}", failure.message);
    assert_eq!(failure.message, "Failed to deliver message to Kafka topic 'my-topic': broker unreachable");
}

#[tokio::test]
async fn flush_should_not_throw_when_every_delivery_succeeded() {
    let deliveries = Deliveries::default();
    deliveries.started();
    deliveries.completed("my-topic", Ok(()));
    deliveries.flush("message").await.unwrap();
}

#[tokio::test]
async fn flush_should_not_repeat_a_previously_reported_failure() {
    let deliveries = Deliveries::default();
    deliveries.started();
    deliveries.completed("my-topic", Err(Error::new("broker unreachable")));
    assert!(deliveries.flush("message").await.is_err(), "reported once");
    deliveries.flush("message").await.expect("a later, successful flush must not resurface the old failure");
}

// ---- KafkaAvroMessagePublisherTest ----

const SCHEMA: &str = r#"{"type":"record","name":"Order","fields":[{"name":"orderId","type":"int"},{"name":"item","type":"string"}]}"#;

fn writer(registry: Option<Arc<SchemaRegistryClient>>, id: i32) -> AvroWriter {
    AvroWriter::new(Some(SCHEMA), registry, id).unwrap()
}

#[tokio::test]
async fn should_frame_registryless_message_with_fixed_schema_id() {
    let r = producer_record(Some(&writer(None, 77)), "orders", r#"{"orderId":42,"item":"widget"}"#, &PublishOptions::none()).await.unwrap();
    assert!(avro::is_wire_format(&r.value));
    let (id, payload) = avro::unframe(&r.value).unwrap();
    assert_eq!(id, 77);
    let json = avro::avro_to_json(&avro::parse_schema(SCHEMA).unwrap(), payload).unwrap();
    assert_eq!(serde_json::from_str::<Value>(&json).unwrap(), json!({"orderId": 42, "item": "widget"}));
}

/// The registry is an in-process server answering the registration, where upstream mocks the client.
#[tokio::test(flavor = "multi_thread")]
async fn should_use_registry_id_when_registry_present() {
    let server = common::start(&[]).await;
    let registration = json!({"method": "POST", "path": "/subjects/orders-value/versions"});
    common::expect(server.port, &json!({"httpRequest": registration, "httpResponse": {"statusCode": 200, "body": r#"{"id":555}"#}})).await;
    let registry = Arc::new(SchemaRegistryClient::new(&format!("http://localhost:{}/", server.port)).unwrap());
    let r = producer_record(Some(&writer(Some(registry), 1)), "orders", r#"{"orderId":1,"item":"x"}"#, &PublishOptions::none()).await.unwrap();
    assert_eq!(avro::unframe(&r.value).unwrap().0, 555);
    let sent: Vec<Value> = serde_json::from_str(&common::send(server.port, "PUT", "/mockserver/retrieve?type=REQUESTS", "").await.body).unwrap();
    assert_eq!(sent.len(), 1);
    assert_eq!((sent[0]["method"].as_str(), sent[0]["path"].as_str()), (Some("POST"), Some("/subjects/orders-value/versions")));
}

#[tokio::test]
async fn should_apply_key_and_headers_from_publish_options() {
    let options = PublishOptions::new(Some("order-key"), None, None, &[("correlationId", "corr-9")]).unwrap();
    let r = producer_record(Some(&writer(None, 1)), "orders", r#"{"orderId":3,"item":"y"}"#, &options).await.unwrap();
    assert_eq!(r.key.as_deref(), Some("order-key"));
    assert!(last_header(&r, "correlationId").is_some());
}

/// Upstream's connecting constructor checks the schema first; so does the load here (`asyncapi::connect` builds the
/// writer before the producer).
#[test]
fn should_reject_missing_schema() {
    assert_eq!(AvroWriter::new(None, None, 1).err().unwrap().message, "an Avro schema is required to publish Avro messages");
}

#[tokio::test]
async fn should_raise_when_payload_does_not_match_schema() {
    let failure = producer_record(Some(&writer(None, 1)), "orders", r#"{"orderId":"not-an-int","item":"z"}"#, &PublishOptions::none()).await.unwrap_err();
    assert!(failure.message.starts_with("Failed to Avro-encode payload for Kafka topic 'orders': "), "{}", failure.message);
}
