//! `MqttMessagePublisherTest`, `MqttMessagePublisherQosTest` and `Mqtt5MessagePublisherTest` (mockserver-async).
//! Upstream hands the publisher a mocked Paho `MqttClient` and captures the `MqttMessage` it publishes; here the
//! publisher connects to a fake broker in the test, which records the PUBLISH packets (topic, QoS, retain flag,
//! payload, MQTT 5 user properties) and the DISCONNECT it receives.

use std::sync::Arc;
use std::time::Duration;

use mock_server::asyncapi::broker::{PublishOptions, Publisher};
use mock_server::asyncapi::mqtt::{MqttPublisher, Version, outgoing_message};
use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

// ---- the fake broker ----

#[derive(Clone, Debug)]
struct Published {
    topic: String,
    qos: u8,
    retain: bool,
    payload: Vec<u8>,
    user_properties: Vec<(String, String)>,
}

#[derive(Default)]
struct Seen {
    publishes: Vec<Published>,
    disconnects: usize,
}

/// An MQTT 3.1.1 / 5 broker for one client: CONNACK, PUBACK (QoS 1), PUBREC then PUBCOMP (QoS 2), PINGRESP. With
/// `drop_after_connect` it ends the connection right after the CONNACK.
struct FakeBroker {
    port: u16,
    seen: Arc<Mutex<Seen>>,
}

impl FakeBroker {
    async fn start(drop_after_connect: bool) -> FakeBroker {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Seen::default()));
        tokio::spawn({
            let seen = seen.clone();
            async move {
                while let Ok((stream, _)) = listener.accept().await {
                    tokio::spawn(serve(stream, seen.clone(), drop_after_connect));
                }
            }
        });
        FakeBroker { port, seen }
    }

    fn url(&self) -> String {
        format!("tcp://127.0.0.1:{}", self.port)
    }

    /// The publishes received, once there are `n` (up to 5 s).
    async fn publishes(&self, n: usize) -> Vec<Published> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while self.seen.lock().publishes.len() < n && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        self.seen.lock().publishes.clone()
    }
}

async fn read_varint(stream: &mut TcpStream) -> Option<usize> {
    let (mut value, mut shift) = (0usize, 0);
    loop {
        let byte = stream.read_u8().await.ok()?;
        value |= ((byte & 0x7f) as usize) << shift;
        if byte & 0x80 == 0 {
            return Some(value);
        }
        shift += 7;
    }
}

fn varint_at(body: &[u8], at: &mut usize) -> usize {
    let (mut value, mut shift) = (0usize, 0);
    loop {
        let byte = body[*at];
        *at += 1;
        value |= ((byte & 0x7f) as usize) << shift;
        if byte & 0x80 == 0 {
            return value;
        }
        shift += 7;
    }
}

fn string_at(body: &[u8], at: &mut usize) -> String {
    let len = u16::from_be_bytes([body[*at], body[*at + 1]]) as usize;
    let s = String::from_utf8(body[*at + 2..*at + 2 + len].to_vec()).unwrap();
    *at += 2 + len;
    s
}

/// MQTT 5 properties: the user properties, the others skipped by their type.
fn user_properties(props: &[u8]) -> Vec<(String, String)> {
    let (mut at, mut out) = (0, Vec::new());
    while at < props.len() {
        let id = props[at];
        at += 1;
        match id {
            0x26 => {
                let k = string_at(props, &mut at);
                out.push((k, string_at(props, &mut at)));
            }
            0x01 => at += 1,
            0x02 => at += 4,
            0x23 => at += 2,
            0x0b => {
                varint_at(props, &mut at);
            }
            0x03 | 0x08 | 0x09 => {
                string_at(props, &mut at);
            }
            other => panic!("unexpected PUBLISH property {other:#x}"),
        }
    }
    out
}

async fn serve(mut stream: TcpStream, seen: Arc<Mutex<Seen>>, drop_after_connect: bool) {
    let mut v5 = false;
    loop {
        let Ok(first) = stream.read_u8().await else { return };
        let Some(len) = read_varint(&mut stream).await else { return };
        let mut body = vec![0; len];
        if stream.read_exact(&mut body).await.is_err() {
            return;
        }
        match first >> 4 {
            1 => {
                let mut at = 0;
                string_at(&body, &mut at);
                v5 = body[at] == 5;
                let ack: &[u8] = if v5 { &[0x20, 0x03, 0x00, 0x00, 0x00] } else { &[0x20, 0x02, 0x00, 0x00] };
                stream.write_all(ack).await.unwrap();
                if drop_after_connect {
                    return;
                }
            }
            3 => {
                let (qos, retain) = ((first >> 1) & 0x03, first & 0x01 == 1);
                let mut at = 0;
                let topic = string_at(&body, &mut at);
                let pkid = if qos > 0 {
                    at += 2;
                    [body[at - 2], body[at - 1]]
                } else {
                    [0, 0]
                };
                let properties = if v5 {
                    let n = varint_at(&body, &mut at);
                    at += n;
                    user_properties(&body[at - n..at])
                } else {
                    Vec::new()
                };
                seen.lock().publishes.push(Published { topic, qos, retain, payload: body[at..].to_vec(), user_properties: properties });
                match qos {
                    1 => stream.write_all(&[0x40, 0x02, pkid[0], pkid[1]]).await.unwrap(),
                    2 => stream.write_all(&[0x50, 0x02, pkid[0], pkid[1]]).await.unwrap(),
                    _ => {}
                }
            }
            6 => stream.write_all(&[0x70, 0x02, body[0], body[1]]).await.unwrap(),
            12 => stream.write_all(&[0xd0, 0x00]).await.unwrap(),
            14 => {
                seen.lock().disconnects += 1;
                return;
            }
            _ => {}
        }
    }
}

async fn publisher(broker: &FakeBroker, qos: u8, version: Version) -> MqttPublisher {
    MqttPublisher::connect(&broker.url(), "test-pub", qos, None, version).await.unwrap()
}

/// Publishes `payload` with `options` through a publisher of `qos` and returns what the broker received.
async fn published(qos: u8, version: Version, payload: &str, options: &PublishOptions) -> Published {
    let broker = FakeBroker::start(false).await;
    let p = publisher(&broker, qos, version).await;
    p.publish("topic", payload, options).await.unwrap();
    let received = broker.publishes(1).await;
    p.close().await;
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].topic, "topic");
    received[0].clone()
}

fn qos_retain(qos: Option<i32>, retain: Option<bool>) -> PublishOptions {
    PublishOptions::new(None, qos, retain, &[]).unwrap()
}

// ---- MqttMessagePublisherTest ----

#[tokio::test(flavor = "multi_thread")]
async fn should_publish_mqtt_message_with_topic_and_payload() {
    let broker = FakeBroker::start(false).await;
    let p = publisher(&broker, 1, Version::V3).await;
    p.publish("sensor/temperature", r#"{"temp": 22.5}"#, &PublishOptions::none()).await.unwrap();
    let received = broker.publishes(1).await;
    assert_eq!(received[0].topic, "sensor/temperature");
    assert_eq!(String::from_utf8(received[0].payload.clone()).unwrap(), r#"{"temp": 22.5}"#);
    assert_eq!(received[0].qos, 1);
    p.close().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_disconnect_and_close_client() {
    let broker = FakeBroker::start(false).await;
    let p = publisher(&broker, 1, Version::V3).await;
    assert!(p.is_connected());
    p.close().await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while broker.seen.lock().disconnects == 0 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(broker.seen.lock().disconnects, 1, "a connected client is disconnected");
    assert!(!p.is_connected(), "and closed");
}

#[tokio::test(flavor = "multi_thread")]
async fn should_close_without_disconnect_if_not_connected() {
    let broker = FakeBroker::start(true).await;
    let p = publisher(&broker, 1, Version::V3).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while p.is_connected() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(!p.is_connected(), "the broker ended the connection");
    tokio::time::timeout(Duration::from_secs(5), p.close()).await.expect("close returns");
    assert_eq!(broker.seen.lock().disconnects, 0);
}

// ---- MqttMessagePublisherQosTest ----

#[tokio::test(flavor = "multi_thread")]
async fn should_publish_with_qos0() {
    assert_eq!(published(0, Version::V3, r#"{"qos":0}"#, &PublishOptions::none()).await.qos, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn should_publish_with_qos2() {
    assert_eq!(published(2, Version::V3, r#"{"qos":2}"#, &PublishOptions::none()).await.qos, 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn should_publish_binary_payload() {
    let broker = FakeBroker::start(false).await;
    let p = publisher(&broker, 1, Version::V3).await;
    p.publish_bytes("topic", &[0x01, 0x02, 0x03, 0x04], &PublishOptions::none()).await.unwrap();
    assert_eq!(broker.publishes(1).await[0].payload, [0x01, 0x02, 0x03, 0x04]);
    p.close().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_report_configured_qos() {
    let broker = FakeBroker::start(false).await;
    let p = publisher(&broker, 2, Version::V3).await;
    assert_eq!(p.qos(), 2);
    p.close().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_convert_string_to_utf8_bytes() {
    let received = published(1, Version::V3, "Hello World", &PublishOptions::none()).await;
    assert_eq!(String::from_utf8(received.payload).unwrap(), "Hello World");
}

// ---- PublishOptions tests ----

#[tokio::test(flavor = "multi_thread")]
async fn should_apply_publish_options_qos_and_retain() {
    let received = published(1, Version::V3, r#"{"data":1}"#, &qos_retain(Some(2), Some(true))).await;
    assert_eq!((received.qos, received.retain), (2, true));
}

#[tokio::test(flavor = "multi_thread")]
async fn should_fall_back_to_instance_qos_when_options_qos_is_null() {
    let received = published(0, Version::V3, r#"{"data":1}"#, &qos_retain(None, Some(true))).await;
    assert_eq!((received.qos, received.retain), (0, true));
}

#[tokio::test(flavor = "multi_thread")]
async fn should_not_set_retained_when_options_retain_is_null() {
    let received = published(1, Version::V3, r#"{"data":1}"#, &qos_retain(None, None)).await;
    assert_eq!((received.qos, received.retain), (1, false));
}

#[tokio::test(flavor = "multi_thread")]
async fn should_use_instance_defaults_when_options_are_null() {
    let received = published(1, Version::V3, r#"{"data":1}"#, &PublishOptions::default()).await;
    assert_eq!((received.qos, received.retain), (1, false));
}

#[tokio::test(flavor = "multi_thread")]
async fn should_use_instance_defaults_when_options_none() {
    let received = published(2, Version::V3, r#"{"data":1}"#, &PublishOptions::none()).await;
    assert_eq!((received.qos, received.retain), (2, false));
}

#[tokio::test(flavor = "multi_thread")]
async fn should_ignore_kafka_key_in_mqtt_publish_options() {
    let received = published(1, Version::V3, r#"{"data":1}"#, &PublishOptions::new(Some("kafka-key"), Some(0), Some(false), &[]).unwrap()).await;
    assert_eq!((received.qos, received.retain), (0, false));
}

#[tokio::test(flavor = "multi_thread")]
async fn should_not_throw_when_publish_options_has_headers() {
    let options = PublishOptions::new(None, None, None, &[("correlationId", "corr-123")]).unwrap();
    let received = published(1, Version::V3, r#"{"data":1}"#, &options).await;
    assert_eq!(String::from_utf8(received.payload).unwrap(), r#"{"data":1}"#);
    assert_eq!(received.qos, 1);
    // MQTT 3.1.1 has no user properties: the headers are dropped.
    assert!(outgoing_message(br#"{"data":1}"#, 1, &options, Version::V3).user_properties.is_empty());
}

// ---- Mqtt5MessagePublisherTest ----

#[tokio::test(flavor = "multi_thread")]
async fn should_publish_payload_with_configured_qos() {
    let received = published(2, Version::V5, r#"{"a":1}"#, &PublishOptions::none()).await;
    assert_eq!(received.qos, 2);
    assert_eq!(String::from_utf8(received.payload).unwrap(), r#"{"a":1}"#);
}

#[tokio::test(flavor = "multi_thread")]
async fn should_apply_qos_and_retain_from_options() {
    let received = published(0, Version::V5, r#"{"a":1}"#, &qos_retain(Some(1), Some(true))).await;
    assert_eq!((received.qos, received.retain), (1, true));
}

#[tokio::test(flavor = "multi_thread")]
async fn should_deliver_headers_as_user_properties() {
    let options = PublishOptions::new(None, None, None, &[("correlationId", "corr-123")]).unwrap();
    let received = published(1, Version::V5, r#"{"a":1}"#, &options).await;
    assert_eq!(received.user_properties, [("correlationId".to_string(), "corr-123".to_string())]);
}

#[tokio::test(flavor = "multi_thread")]
async fn mqtt5_should_publish_binary_payload() {
    let broker = FakeBroker::start(false).await;
    let p = publisher(&broker, 1, Version::V5).await;
    p.publish_bytes("topic", &[0x01, 0x02, 0x03], &PublishOptions::none()).await.unwrap();
    assert_eq!(broker.publishes(1).await[0].payload, [0x01, 0x02, 0x03]);
    p.close().await;
}

#[tokio::test]
async fn should_reject_invalid_qos_in_constructor() {
    let failure = MqttPublisher::connect("tcp://localhost:1883", "client", 5, None, Version::V5).await.err().unwrap();
    assert_eq!(failure.message, "MQTT QoS must be 0, 1, or 2; got: 5");
}

#[tokio::test(flavor = "multi_thread")]
async fn mqtt5_should_report_configured_qos() {
    let broker = FakeBroker::start(false).await;
    let p = publisher(&broker, 2, Version::V5).await;
    assert_eq!(p.qos(), 2);
    p.close().await;
}
