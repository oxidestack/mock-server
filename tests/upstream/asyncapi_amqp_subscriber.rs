//! `AmqpMessageSubscriberTest` (mockserver-async). Upstream drives the subscriber over a mocked RabbitMQ `Channel`
//! and checks the declarations and consumes it makes and what a delivery records. Here the same decisions are
//! checked where the subscriber makes them: `consume_source` (what `subscribe` declares, binds and consumes) and
//! `consumed_message` (what a delivery records), with the channel's store as the subscriber keeps it.

use std::collections::BTreeMap;

use lapin::ExchangeKind;
use lapin::types::{AMQPValue, FieldTable, LongString, ShortString};
use mock_server::asyncapi::amqp::{ConsumeSource, consume_source, consumed_message};
use mock_server::asyncapi::spec::{AmqpBinding, AmqpChannelType};
use mock_server::asyncapi::store::ConsumedMessages;

/// A delivery's headers, as the Java client sends `Map.of(…)` (long strings).
fn headers(entries: &[(&str, &str)]) -> FieldTable {
    let table: BTreeMap<ShortString, AMQPValue> = entries.iter().map(|(k, v)| (ShortString::from(*k), AMQPValue::LongString(LongString::from(*v)))).collect();
    FieldTable::from(table)
}

// ---- AmqpMessageSubscriberTest ----

#[test]
fn should_declare_and_consume_queue_based_channel() {
    let binding = AmqpBinding::new(AmqpChannelType::Queue, None, None, true, Some("orders-q"), true, None);
    // The named queue is declared (durable) and consumed.
    assert_eq!(consume_source("orders", Some(&binding)), ConsumeSource::Queue { name: "orders-q".into(), durable: true });
    // A delivery is recorded against the channel name.
    let recorder = ConsumedMessages::new(100);
    recorder.ensure("orders").unwrap();
    recorder.record(consumed_message("orders", br#"{"orderId":42}"#, Some(&headers(&[("trace", "abc")]))));
    let messages = recorder.exact("orders");
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].channel, "orders");
    assert_eq!(messages[0].payload.as_deref(), Some(r#"{"orderId":42}"#));
    assert_eq!(messages[0].header("trace"), Some("abc"));
    assert_eq!(messages[0].key, None);
}

#[test]
fn should_declare_exchange_bind_private_queue_for_routing_key_channel() {
    let binding = AmqpBinding::new(AmqpChannelType::RoutingKey, Some("events"), Some("topic"), true, None, true, None);
    // `exchangeDeclare("events", TOPIC, true)`, then a private queue bound on the channel name and consumed.
    assert_eq!(
        consume_source("user.signedup", Some(&binding)),
        ConsumeSource::Exchange { exchange: "events".into(), kind: ExchangeKind::Topic, durable: true, routing_key: "user.signedup".into() }
    );
}

#[test]
fn should_normalise_non_lowercase_exchange_type() {
    let binding = AmqpBinding::new(AmqpChannelType::RoutingKey, Some("events"), Some("Topic"), true, None, true, None);
    let ConsumeSource::Exchange { kind, .. } = consume_source("user.signedup", Some(&binding)) else { panic!("an exchange-routed channel") };
    assert_eq!(kind, ExchangeKind::Topic, "mixed-case \"Topic\" is normalised to TOPIC, matching the publisher");
}

#[test]
fn should_consume_channel_name_queue_when_no_binding() {
    assert_eq!(consume_source("plain-channel", None), ConsumeSource::Queue { name: "plain-channel".into(), durable: true });
}

#[test]
fn should_evict_oldest_when_cap_reached() {
    assert_eq!(consume_source("bounded", None), ConsumeSource::Queue { name: "bounded".into(), durable: true });
    let recorder = ConsumedMessages::new(2);
    recorder.ensure("bounded").unwrap();
    for i in 0..4 {
        recorder.record(consumed_message("bounded", format!("v{i}").as_bytes(), None));
    }
    let payloads: Vec<String> = recorder.exact("bounded").into_iter().filter_map(|m| m.payload).collect();
    assert_eq!(payloads, ["v2", "v3"]);
}
