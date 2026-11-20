//! `KafkaMessageSubscriberTest` and `KafkaAvroSchemaIdMismatchTest` (mockserver-async). Upstream hands the
//! subscriber a mocked `KafkaConsumer` whose `poll` returns prepared records; here the subscriber is built on a
//! bootstrap address nothing listens on (its poll loop keeps retrying without reaching a broker) and the prepared
//! records go through `record`, what the poll loop does with each record it polls.

use std::time::{Duration, Instant};

use bytes::Bytes;
use mock_server::asyncapi::avro::{frame, json_to_avro, parse_schema};
use mock_server::asyncapi::broker::{Counters, Subscriber};
use mock_server::asyncapi::kafka::{AvroReader, ConsumerRecord, KafkaSubscriber};
use mock_server::asyncapi::store::DEFAULT_MAX_RECORDED_MESSAGES;

/// `new KafkaMessageSubscriber(mockConsumer, maxRecordedMessages)`.
async fn subscriber(max_recorded: i64) -> KafkaSubscriber {
    KafkaSubscriber::new("127.0.0.1:1", "test-group", max_recorded, None, None, Counters::default()).await.unwrap()
}

/// `new ConsumerRecord<>(topic, partition, offset, key, value)`, with headers.
fn record(topic: &str, key: Option<&str>, value: &str, headers: &[(&str, &str)]) -> ConsumerRecord {
    let bytes = |s: &str| Bytes::from(s.as_bytes().to_vec());
    ConsumerRecord {
        topic: topic.to_string(),
        key: key.map(bytes),
        value: Some(bytes(value)),
        headers: headers.iter().map(|(k, v)| (k.to_string(), Some(bytes(v)))).collect(),
    }
}

// ---- KafkaMessageSubscriberTest ----

/// `consumer.subscribe([test-topic])` happens on the poll thread: here the topic joins the subscription the poll
/// loop joins the group with.
#[tokio::test]
async fn should_subscribe_to_topic() {
    let s = subscriber(DEFAULT_MAX_RECORDED_MESSAGES as i64).await;
    s.subscribe("test-topic").await.unwrap();
    assert!(s.subscription().contains(&"test-topic".to_string()));
    s.close().await;
}

#[tokio::test]
async fn should_return_empty_list_when_no_messages() {
    let s = subscriber(DEFAULT_MAX_RECORDED_MESSAGES as i64).await;
    assert!(s.recorded("nonexistent").is_empty());
    s.close().await;
}

#[tokio::test]
async fn should_record_messages_from_poll() {
    let s = subscriber(DEFAULT_MAX_RECORDED_MESSAGES as i64).await;
    s.subscribe("my-topic").await.unwrap();
    s.record(record("my-topic", Some("key1"), r#"{"data":1}"#, &[("trace-id", "abc123")])).await;
    let messages = s.recorded("my-topic");
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].channel, "my-topic");
    assert_eq!(messages[0].key.as_deref(), Some("key1"));
    assert_eq!(messages[0].payload.as_deref(), Some(r#"{"data":1}"#));
    assert_eq!(messages[0].header("trace-id"), Some("abc123"));
    s.close().await;
}

#[tokio::test]
async fn should_return_all_recorded_messages() {
    let s = subscriber(DEFAULT_MAX_RECORDED_MESSAGES as i64).await;
    s.subscribe("topic-a").await.unwrap();
    s.subscribe("topic-b").await.unwrap();
    s.record(record("topic-a", None, r#"{"a":1}"#, &[])).await;
    s.record(record("topic-b", None, r#"{"b":2}"#, &[])).await;
    assert_eq!(s.all_recorded().len(), 2);
    s.close().await;
}

#[tokio::test]
async fn should_clear_on_close() {
    let s = subscriber(DEFAULT_MAX_RECORDED_MESSAGES as i64).await;
    s.subscribe("topic-x").await.unwrap();
    s.record(record("topic-x", None, r#"{"x":1}"#, &[])).await;
    s.close().await;
    assert!(s.recorded("topic-x").is_empty());
    assert!(s.all_recorded().is_empty());
}

#[tokio::test]
async fn should_evict_oldest_when_cap_reached() {
    let s = subscriber(3).await;
    s.subscribe("capped-topic").await.unwrap();
    for i in 0..5 {
        s.record(record("capped-topic", Some(&format!("key{i}")), &format!("value{i}"), &[])).await;
    }
    let payloads: Vec<String> = s.recorded("capped-topic").into_iter().filter_map(|m| m.payload).collect();
    assert_eq!(payloads, ["value2", "value3", "value4"], "only the last 3 messages are kept");
    s.close().await;
}

/// `subscribe` only queues the subscription for the poll loop: it returns at once, without waiting for a broker
/// (none listens on the bootstrap address), and the poll loop picks the topic up.
#[tokio::test]
async fn should_queue_subscribe_ops_and_not_call_consumer_directly_from_caller_thread() {
    let s = subscriber(DEFAULT_MAX_RECORDED_MESSAGES as i64).await;
    let started = Instant::now();
    s.subscribe("queued-topic").await.unwrap();
    assert!(started.elapsed() < Duration::from_millis(500), "subscribe waited {:?}", started.elapsed());
    assert!(s.subscription().contains(&"queued-topic".to_string()));
    assert!(s.is_healthy(), "the poll loop keeps running while the broker is unreachable");
    s.close().await;
}

/// The poll loop starts once and subscribes the consumer to every topic.
#[tokio::test]
async fn should_start_poll_loop_exactly_once_with_multiple_subscribes() {
    let s = subscriber(DEFAULT_MAX_RECORDED_MESSAGES as i64).await;
    for topic in ["topic-1", "topic-2", "topic-3"] {
        s.subscribe(topic).await.unwrap();
    }
    assert_eq!(s.subscription(), ["topic-1", "topic-2", "topic-3"]);
    s.close().await;
}

// ---- KafkaAvroSchemaIdMismatchTest ----

/// The schema the subscriber is configured with (id 1).
const CONFIGURED_SCHEMA: &str = r#"{"type":"record","name":"User","fields":[{"name":"firstName","type":"string"},{"name":"lastName","type":"string"}]}"#;
/// A different schema (id 7) of the same wire shape with the fields the other way round: its binary decodes cleanly
/// against the configured one, the two values transposed.
const OTHER_SCHEMA: &str = r#"{"type":"record","name":"User","fields":[{"name":"lastName","type":"string"},{"name":"firstName","type":"string"}]}"#;
const CONFIGURED_SCHEMA_ID: i32 = 1;
const OTHER_SCHEMA_ID: i32 = 7;

/// `KafkaAvroMessageSubscriber`'s value decoding, registry-less with the configured inline schema.
fn avro_reader() -> AvroReader {
    AvroReader::new(None, Some(CONFIGURED_SCHEMA), CONFIGURED_SCHEMA_ID).unwrap()
}

#[tokio::test]
async fn should_decode_message_framed_with_the_configured_schema_id() {
    let binary = json_to_avro(&parse_schema(CONFIGURED_SCHEMA).unwrap(), r#"{"firstName":"Ada","lastName":"Lovelace"}"#).unwrap();
    let json = avro_reader().decode(&frame(CONFIGURED_SCHEMA_ID, &binary)).await;
    assert!(json.contains(r#""firstName":"Ada""#), "{json}");
    assert!(json.contains(r#""lastName":"Lovelace""#), "{json}");
}

#[tokio::test]
async fn should_not_decode_message_framed_with_a_different_schema_id() {
    // Written by a producer using a different schema, framed with its own schema id.
    let binary = json_to_avro(&parse_schema(OTHER_SCHEMA).unwrap(), r#"{"lastName":"Lovelace","firstName":"Ada"}"#).unwrap();
    let json = avro_reader().decode(&frame(OTHER_SCHEMA_ID, &binary)).await;
    assert!(!json.contains(r#""firstName":"Lovelace""#), "a mismatched schema id must not be decoded into transposed values: {json}");
    assert!(!json.contains(r#""lastName":"Ada""#), "{json}");
}

#[tokio::test]
async fn should_record_non_avro_payloads_unchanged() {
    let plain = r#"{"not":"avro"}"#;
    assert_eq!(avro_reader().decode(plain.as_bytes()).await, plain);
}
