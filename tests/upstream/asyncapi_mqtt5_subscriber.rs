//! `Mqtt5MessageSubscriberTest` (mockserver-async): the MQTT 5 subscriber over a stub broker (`asyncapi_mqtt_stub`)
//! standing in for the mocked Paho v5 `MqttClient`, including user properties recorded as headers.

use mock_server::asyncapi::broker::Subscriber;
use mock_server::asyncapi::mqtt::{MqttSubscriber, Version};
use mock_server::asyncapi::store::DEFAULT_MAX_RECORDED_MESSAGES;

use crate::asyncapi_mqtt_stub::{StubMqttBroker, eventually};
use crate::asyncapi_mqtt_subscriber::subscriber;

async fn v5(max_recorded: i64) -> (StubMqttBroker, MqttSubscriber) {
    let broker = StubMqttBroker::start(true).await;
    let s = subscriber(&broker, 1, max_recorded, Version::V5).await;
    (broker, s)
}

// ---- Mqtt5MessageSubscriberTest ----

#[tokio::test]
async fn should_subscribe_to_topic() {
    let (broker, s) = v5(DEFAULT_MAX_RECORDED_MESSAGES as i64).await;
    s.subscribe("sensor/temp").await.unwrap();
    assert_eq!(broker.subscriptions(), [("sensor/temp".to_string(), 1)]);
    s.close().await;
}

#[tokio::test]
async fn should_record_messages_via_callback() {
    let (broker, s) = v5(DEFAULT_MAX_RECORDED_MESSAGES as i64).await;
    s.subscribe("sensor/temp").await.unwrap();
    broker.deliver("sensor/temp", r#"{"temp":22.5}"#, &[]);
    assert!(eventually(|| !s.recorded("sensor/temp").is_empty()).await);
    let messages = s.recorded("sensor/temp");
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].payload.as_deref(), Some(r#"{"temp":22.5}"#));
    assert_eq!(messages[0].key, None);
    s.close().await;
}

#[tokio::test]
async fn should_record_user_properties_as_headers() {
    let (broker, s) = v5(DEFAULT_MAX_RECORDED_MESSAGES as i64).await;
    s.subscribe("events").await.unwrap();
    broker.deliver("events", r#"{"e":1}"#, &[("correlationId", "corr-77")]);
    assert!(eventually(|| !s.recorded("events").is_empty()).await);
    let messages = s.recorded("events");
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].header("correlationId"), Some("corr-77"));
    s.close().await;
}

#[tokio::test]
async fn should_report_unhealthy_after_disconnect() {
    let (broker, s) = v5(DEFAULT_MAX_RECORDED_MESSAGES as i64).await;
    assert!(s.is_healthy());
    broker.disconnect();
    assert!(eventually(|| !s.is_healthy()).await, "a disconnected subscriber is no longer healthy");
    s.close().await;
}

#[tokio::test]
async fn should_evict_oldest_when_cap_reached() {
    let (broker, s) = v5(2).await;
    s.subscribe("bounded").await.unwrap();
    for i in 0..4 {
        broker.deliver("bounded", &format!("v{i}"), &[]);
    }
    let payloads = || s.recorded("bounded").into_iter().filter_map(|m| m.payload).collect::<Vec<_>>();
    assert!(eventually(|| payloads().last().map(String::as_str) == Some("v3")).await);
    assert_eq!(payloads(), ["v2", "v3"]);
    s.close().await;
}
