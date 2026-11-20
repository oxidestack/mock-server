//! `MqttMessageSubscriberTest` and `MqttWildcardSubscriptionTest` (mockserver-async). Upstream hands the subscriber
//! a mocked Paho `MqttClient` and calls the callback it installs; here the subscriber connects to a stub broker
//! (`asyncapi_mqtt_stub`) that records the subscriptions and delivers the messages.

use mock_server::asyncapi::broker::{Counters, Subscriber};
use mock_server::asyncapi::mqtt::{MqttSubscriber, Version};
use mock_server::asyncapi::store::DEFAULT_MAX_RECORDED_MESSAGES;

use crate::asyncapi_mqtt_stub::{StubMqttBroker, eventually};

/// `new MqttMessageSubscriber(client, qos, maxRecordedMessages)` (or the MQTT 5 one) on the stub broker.
pub async fn subscriber(broker: &StubMqttBroker, qos: u8, max_recorded: i64, version: Version) -> MqttSubscriber {
    MqttSubscriber::connect(&broker.url, "test-subscriber", qos, max_recorded, None, version, Counters::default()).await.unwrap()
}

async fn v3(qos: u8, max_recorded: i64) -> (StubMqttBroker, MqttSubscriber) {
    let broker = StubMqttBroker::start(false).await;
    let s = subscriber(&broker, qos, max_recorded, Version::V3).await;
    (broker, s)
}

fn payloads(s: &MqttSubscriber, channel: &str) -> Vec<String> {
    s.recorded(channel).into_iter().filter_map(|m| m.payload).collect()
}

// ---- MqttMessageSubscriberTest ----

#[tokio::test]
async fn should_subscribe_to_topic() {
    let (broker, s) = v3(1, DEFAULT_MAX_RECORDED_MESSAGES as i64).await;
    s.subscribe("sensor/temp").await.unwrap();
    assert_eq!(broker.subscriptions(), [("sensor/temp".to_string(), 1)]);
    s.close().await;
}

#[tokio::test]
async fn should_record_messages_via_callback() {
    let (broker, s) = v3(1, DEFAULT_MAX_RECORDED_MESSAGES as i64).await;
    s.subscribe("sensor/temp").await.unwrap();
    broker.deliver("sensor/temp", r#"{"temp":22.5}"#, &[]);
    assert!(eventually(|| !s.recorded("sensor/temp").is_empty()).await);
    let messages = s.recorded("sensor/temp");
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].channel, "sensor/temp");
    assert_eq!(messages[0].payload.as_deref(), Some(r#"{"temp":22.5}"#));
    assert_eq!(messages[0].key, None);
    assert!(messages[0].headers.is_empty());
    s.close().await;
}

#[tokio::test]
async fn should_return_empty_list_for_unknown_topic() {
    let (_broker, s) = v3(1, DEFAULT_MAX_RECORDED_MESSAGES as i64).await;
    assert!(s.recorded("unknown").is_empty());
    s.close().await;
}

#[tokio::test]
async fn should_return_all_recorded_messages() {
    let (broker, s) = v3(1, DEFAULT_MAX_RECORDED_MESSAGES as i64).await;
    s.subscribe("topic-a").await.unwrap();
    s.subscribe("topic-b").await.unwrap();
    broker.deliver("topic-a", r#"{"a":1}"#, &[]);
    broker.deliver("topic-b", r#"{"b":2}"#, &[]);
    assert!(eventually(|| s.all_recorded().len() == 2).await, "{:?}", s.all_recorded());
    s.close().await;
}

/// `close` disconnects a connected client, then forgets what was recorded.
#[tokio::test]
async fn should_clear_on_close() {
    let (broker, s) = v3(1, DEFAULT_MAX_RECORDED_MESSAGES as i64).await;
    s.subscribe("topic-x").await.unwrap();
    broker.deliver("topic-x", r#"{"x":1}"#, &[]);
    assert!(eventually(|| !s.recorded("topic-x").is_empty()).await);
    s.close().await;
    assert!(s.recorded("topic-x").is_empty());
    assert!(eventually(|| broker.disconnects() == 1).await, "the connected client disconnects");
}

#[tokio::test]
async fn should_evict_oldest_when_cap_reached() {
    let (broker, s) = v3(1, 3).await;
    s.subscribe("bounded-topic").await.unwrap();
    for i in 0..5 {
        broker.deliver("bounded-topic", &format!("value{i}"), &[]);
    }
    assert!(eventually(|| payloads(&s, "bounded-topic").last().map(String::as_str) == Some("value4")).await);
    assert_eq!(payloads(&s, "bounded-topic"), ["value2", "value3", "value4"], "only the last 3 messages are kept");
    s.close().await;
}

// ---- MqttWildcardSubscriptionTest ----

#[tokio::test]
async fn should_retrieve_messages_on_concrete_topic_via_single_level_wildcard_filter() {
    let (broker, s) = v3(1, DEFAULT_MAX_RECORDED_MESSAGES as i64).await;
    s.subscribe("sensors/+/temperature").await.unwrap();
    broker.deliver("sensors/kitchen/temperature", r#"{"temp":21}"#, &[]);
    assert!(eventually(|| !s.recorded("sensors/+/temperature").is_empty()).await, "the wildcard filter matches the concrete topic the message arrived on");
    let by_filter = s.recorded("sensors/+/temperature");
    assert_eq!(by_filter.len(), 1);
    assert_eq!(by_filter[0].payload.as_deref(), Some(r#"{"temp":21}"#));
    assert_eq!(by_filter[0].channel, "sensors/kitchen/temperature", "the recorded channel remains the concrete topic");
    s.close().await;
}

#[tokio::test]
async fn should_retrieve_messages_across_levels_via_multi_level_wildcard_filter() {
    let (broker, s) = v3(1, DEFAULT_MAX_RECORDED_MESSAGES as i64).await;
    s.subscribe("sensors/#").await.unwrap();
    broker.deliver("sensors/kitchen/temperature", "a", &[]);
    broker.deliver("sensors/hall/humidity/raw", "b", &[]);
    broker.deliver("actuators/valve", "c", &[]);
    assert!(eventually(|| s.all_recorded().len() == 3).await);
    let mut by_filter = payloads(&s, "sensors/#");
    by_filter.sort();
    assert_eq!(by_filter, ["a", "b"], "the multi-level wildcard matches every topic beneath the prefix");
    s.close().await;
}

#[tokio::test]
async fn should_not_match_unrelated_topics_for_wildcard_filter() {
    let (broker, s) = v3(1, DEFAULT_MAX_RECORDED_MESSAGES as i64).await;
    s.subscribe("sensors/+/temperature").await.unwrap();
    // One level too deep: '+' matches exactly one level.
    broker.deliver("sensors/kitchen/inner/temperature", "x", &[]);
    broker.deliver("sensors/kitchen/humidity", "y", &[]);
    assert!(eventually(|| s.all_recorded().len() == 2).await);
    assert!(s.recorded("sensors/+/temperature").is_empty());
    s.close().await;
}

#[tokio::test]
async fn should_still_match_exact_topic_when_filter_has_no_wildcard() {
    let (broker, s) = v3(1, DEFAULT_MAX_RECORDED_MESSAGES as i64).await;
    s.subscribe("sensors/kitchen/temperature").await.unwrap();
    broker.deliver("sensors/kitchen/temperature", "exact", &[]);
    assert!(eventually(|| s.recorded("sensors/kitchen/temperature").len() == 1).await);
    assert!(s.recorded("sensors/other/temperature").is_empty());
    s.close().await;
}

#[tokio::test]
async fn mqtt5_should_retrieve_messages_on_concrete_topic_via_wildcard_filter() {
    let broker = StubMqttBroker::start(true).await;
    let s = subscriber(&broker, 1, DEFAULT_MAX_RECORDED_MESSAGES as i64, Version::V5).await;
    s.subscribe("sensors/+/temperature").await.unwrap();
    broker.deliver("sensors/kitchen/temperature", r#"{"temp":21}"#, &[]);
    assert!(eventually(|| !s.recorded("sensors/+/temperature").is_empty()).await, "MQTT 5 shares MQTT 3.1.1 wildcard semantics");
    let by_filter = s.recorded("sensors/+/temperature");
    assert_eq!(by_filter.len(), 1);
    assert_eq!(by_filter[0].payload.as_deref(), Some(r#"{"temp":21}"#));
    s.close().await;
}
