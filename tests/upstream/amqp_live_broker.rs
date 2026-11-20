//! `AmqpLiveBrokerIntegrationTest` (mockserver-async): the AMQP adapters against RabbitMQ 3.13. The originals'
//! plain RabbitMQ Java clients are plain `lapin` clients here.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use lapin::options::{BasicGetOptions, ExchangeDeclareOptions, QueueBindOptions, QueueDeclareOptions};
use lapin::types::FieldTable;

use mock_server::asyncapi::amqp::{AmqpPublisher, AmqpSubscriber};
use mock_server::asyncapi::broker::{Counters, PublishOptions, Publisher, Subscriber};
use mock_server::asyncapi::orchestrator::Orchestrator;
use mock_server::asyncapi::spec::{AmqpBinding, AmqpChannelType, Channel, Spec};

use crate::brokers::{self, Container, block};

const AMQP_PORT: u16 = 5672;

fn rabbit() -> &'static Container {
    static BROKER: OnceLock<Container> = OnceLock::new();
    BROKER.get_or_init(|| {
        let mut spec = brokers::Spec::new(brokers::RABBITMQ);
        spec.ports = vec![(0, AMQP_PORT)];
        spec.ready = "Server startup complete";
        let container = Container::start(spec);
        // The port accepts connections a moment after the log line.
        brokers::eventually(Duration::from_secs(30), || std::net::TcpStream::connect(("127.0.0.1", container.port(AMQP_PORT))).ok().map(|_| ()));
        container
    })
}

fn amqp_uri() -> String {
    format!("amqp://localhost:{}", rabbit().port(AMQP_PORT))
}

fn spec_with_channel(name: &str, binding: AmqpBinding) -> Spec {
    Spec::new("2.6.0", "Test", vec![Channel { amqp_binding: Some(binding), ..Channel::new(name, Vec::new(), None) }])
}

/// A plain client connection and channel (`ConnectionFactory.newConnection()` in the originals).
fn plain_channel() -> (lapin::Connection, lapin::Channel) {
    let uri = amqp_uri();
    block(async move {
        let connection = lapin::Connection::connect(&uri, lapin::ConnectionProperties::default()).await.expect("plain connection");
        let channel = connection.create_channel().await.expect("plain channel");
        (connection, channel)
    })
}

/// `pollQueue`: `basicGet` with auto-ack every 200 ms for up to 10 s.
fn poll_queue(channel: &lapin::Channel, queue: &str) -> Option<String> {
    let (channel, queue) = (channel.clone(), queue.to_string());
    block(async move {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while tokio::time::Instant::now() < deadline {
            if let Ok(Some(message)) = channel.basic_get(queue.as_str().into(), BasicGetOptions { no_ack: true }).await {
                return Some(String::from_utf8_lossy(&message.delivery.data).into_owned());
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        None
    })
}

/// `basicGet`: a fresh connection, the queue declared, then polled.
fn basic_get(queue: &str) -> Option<String> {
    let (connection, channel) = plain_channel();
    let q = queue.to_string();
    let c = channel.clone();
    block(async move { c.queue_declare(q.as_str().into(), QueueDeclareOptions { durable: true, ..Default::default() }, FieldTable::default()).await.expect("\
        declare") });
    let received = poll_queue(&channel, queue);
    block(async move {
        let _ = connection.close(200, "OK".into()).await;
    });
    received
}

/// Declares a topic exchange and a queue bound to it on `routing_key`.
fn bind_consumer_queue(channel: &lapin::Channel, exchange: &str, queue: &str, routing_key: &str) {
    let (channel, exchange, queue, routing_key) = (channel.clone(), exchange.to_string(), queue.to_string(), routing_key.to_string());
    block(async move {
        channel.exchange_declare(
            exchange.as_str().into(),
            lapin::ExchangeKind::Topic,
            ExchangeDeclareOptions { durable: true, ..Default::default() },
            FieldTable::default(),
        ).await.unwrap();
        channel.queue_declare(queue.as_str().into(), QueueDeclareOptions { durable: true, ..Default::default() }, FieldTable::default()).await.unwrap();
        channel.queue_bind(
            queue.as_str().into(),
            exchange.as_str().into(),
            routing_key.as_str().into(),
            QueueBindOptions::default(),
            FieldTable::default(),
        ).await.unwrap();
    });
}

fn close(connection: lapin::Connection) {
    block(async move {
        let _ = connection.close(200, "OK".into()).await;
    });
}

#[test]
fn should_publish_to_queue_bound_channel_via_live_broker() {
    if !brokers::enabled("should_publish_to_queue_bound_channel_via_live_broker") {
        return;
    }
    let queue = "live-orders-queue";
    let spec = spec_with_channel("orders", AmqpBinding::new(AmqpChannelType::Queue, None, None, true, Some(queue), true, None));
    let publisher = Arc::new(block(AmqpPublisher::connect(&amqp_uri(), Some(&spec))).unwrap());
    block(publisher.publish("orders", r#"{"orderId":42}"#, &PublishOptions::none())).unwrap();
    block(publisher.close());
    assert_eq!(basic_get(queue).as_deref(), Some(r#"{"orderId":42}"#), "message should be on the queue");
}

#[test]
fn should_publish_to_exchange_with_routing_key_via_live_broker() {
    if !brokers::enabled("should_publish_to_exchange_with_routing_key_via_live_broker") {
        return;
    }
    let (exchange, channel_name, bound_queue) = ("live-events", "user.signedup", "live-events-consumer");
    let spec = spec_with_channel(channel_name, AmqpBinding::new(AmqpChannelType::RoutingKey, Some(exchange), Some("topic"), true, None, true, None));
    let (connection, channel) = plain_channel();
    bind_consumer_queue(&channel, exchange, bound_queue, channel_name);
    let publisher = Arc::new(block(AmqpPublisher::connect(&amqp_uri(), Some(&spec))).unwrap());
    block(publisher.publish(channel_name, r#"{"user":"alice"}"#, &PublishOptions::none())).unwrap();
    block(publisher.close());
    assert_eq!(poll_queue(&channel, bound_queue).as_deref(), Some(r#"{"user":"alice"}"#), "routed message should be on the bound queue");
    close(connection);
}

#[test]
fn should_fail_publish_when_no_queue_is_bound_to_exchange() {
    if !brokers::enabled("should_fail_publish_when_no_queue_is_bound_to_exchange") {
        return;
    }
    let (exchange, channel_name) = ("live-unrouted-events", "orders.unrouted");
    let spec = spec_with_channel(channel_name, AmqpBinding::new(AmqpChannelType::RoutingKey, Some(exchange), Some("topic"), true, None, true, None));
    let publisher = Arc::new(block(AmqpPublisher::connect(&amqp_uri(), Some(&spec))).unwrap());
    let failure = block(publisher.publish(channel_name, r#"{"orderId":1}"#, &PublishOptions::none())).err();
    block(publisher.close());
    let failure = failure.expect("publishing to an exchange with no bound queue must not report success");
    assert!(failure.message.contains("was not routed to any queue"), "{failure:?}");
}

#[test]
fn should_succeed_once_a_queue_is_bound_to_the_exchange() {
    if !brokers::enabled("should_succeed_once_a_queue_is_bound_to_the_exchange") {
        return;
    }
    let (exchange, channel_name, bound_queue) = ("live-rebound-events", "orders.rebound", "live-rebound-consumer");
    let spec = spec_with_channel(channel_name, AmqpBinding::new(AmqpChannelType::RoutingKey, Some(exchange), Some("topic"), true, None, true, None));
    let (connection, channel) = plain_channel();
    bind_consumer_queue(&channel, exchange, bound_queue, channel_name);
    let publisher = Arc::new(block(AmqpPublisher::connect(&amqp_uri(), Some(&spec))).unwrap());
    block(publisher.publish(channel_name, r#"{"orderId":2}"#, &PublishOptions::none())).unwrap();
    block(publisher.close());
    assert_eq!(poll_queue(&channel, bound_queue).as_deref(), Some(r#"{"orderId":2}"#));
    close(connection);
}

#[test]
fn orchestrator_should_publish_example_to_live_broker() {
    if !brokers::enabled("orchestrator_should_publish_example_to_live_broker") {
        return;
    }
    let queue = "live-orchestrator-queue";
    let spec_json = format!(
        concat!(
            r#"{{"asyncapi":"2.6.0","info":{{"title":"Orders"}},"channels":{{"orders":{{  "#,
            r#""bindings":{{"amqp":{{"is":"queue","queue":{{"name":"{queue}","durable":true}}}}}},  "#,
            r#""publish":{{"message":{{"payload":{{"type":"object"}},    "examples":[{{"payload":{{"hello":"world"}}}}]}}}}}}}}}}"#,
        ),
        queue = queue
    );
    let spec = Arc::new(mock_server::asyncapi::spec::parse(&spec_json).unwrap());
    let publisher = Arc::new(block(AmqpPublisher::connect(&amqp_uri(), Some(&spec))).unwrap());
    let orchestrator = Arc::new(Orchestrator::new(spec, publisher.clone(), Default::default()));
    block(orchestrator.publish_all()).unwrap();
    block(async move { publisher.close().await });
    assert_eq!(basic_get(queue).as_deref(), Some(r#"{"hello":"world"}"#), "orchestrator-published example should land on the queue");
}

fn poll_recorded(subscriber: &AmqpSubscriber, channel: &str) -> Vec<mock_server::asyncapi::store::ConsumedMessage> {
    brokers::eventually(Duration::from_secs(10), || Some(subscriber.recorded(channel)).filter(|m| !m.is_empty())).unwrap_or_default()
}

#[test]
fn subscriber_should_record_from_queue_bound_channel() {
    if !brokers::enabled("subscriber_should_record_from_queue_bound_channel") {
        return;
    }
    let queue = "live-sub-orders-queue";
    let spec = spec_with_channel("orders", AmqpBinding::new(AmqpChannelType::Queue, None, None, true, Some(queue), true, None));
    let subscriber = Arc::new(block(AmqpSubscriber::connect(&amqp_uri(), Some(&spec), 100, Counters::default())).unwrap());
    block(subscriber.subscribe("orders")).unwrap();
    let publisher = Arc::new(block(AmqpPublisher::connect(&amqp_uri(), Some(&spec))).unwrap());
    block(publisher.publish("orders", r#"{"orderId":7}"#, &PublishOptions::none())).unwrap();
    block(publisher.close());
    let messages = poll_recorded(&subscriber, "orders");
    assert!(!messages.is_empty(), "subscriber should record the published message");
    assert_eq!(messages[0].channel, "orders");
    assert_eq!(messages[0].payload.as_deref(), Some(r#"{"orderId":7}"#));
    block(subscriber.close());
}

#[test]
fn subscriber_should_record_from_exchange_routing_key_channel() {
    if !brokers::enabled("subscriber_should_record_from_exchange_routing_key_channel") {
        return;
    }
    let (exchange, channel_name) = ("live-sub-events", "user.created");
    let spec = spec_with_channel(channel_name, AmqpBinding::new(AmqpChannelType::RoutingKey, Some(exchange), Some("topic"), true, None, true, None));
    let subscriber = Arc::new(block(AmqpSubscriber::connect(&amqp_uri(), Some(&spec), 100, Counters::default())).unwrap());
    block(subscriber.subscribe(channel_name)).unwrap();
    let publisher = Arc::new(block(AmqpPublisher::connect(&amqp_uri(), Some(&spec))).unwrap());
    block(publisher.publish(channel_name, r#"{"user":"bob"}"#, &PublishOptions::none())).unwrap();
    block(publisher.close());
    let messages = poll_recorded(&subscriber, channel_name);
    assert!(!messages.is_empty(), "subscriber should record the routed message");
    assert_eq!(messages[0].payload.as_deref(), Some(r#"{"user":"bob"}"#));
    block(subscriber.close());
}

// ---- Not an upstream test: the handshake the broker refuses (checked against the oracle) ----

#[test]
fn unknown_virtual_host_fails_the_connection_at_once() {
    if !brokers::enabled("unknown_virtual_host_fails_the_connection_at_once") {
        return;
    }
    // `127.0.0.1`, not `localhost`: the port is published on IPv4 only, and the Java client (as `connect` does)
    // tries every address of the host in shuffled order and throws the last failure, so `localhost`'s `::1` would
    // end it as "Connection refused" whenever it came last.
    let uri = format!("amqp://127.0.0.1:{}/no-such-vhost", rabbit().port(AMQP_PORT));
    let started = std::time::Instant::now();
    let error = block(AmqpPublisher::connect(&uri, None)).err().expect("the broker refuses the virtual host");
    assert_eq!(error.message, "Failed to connect to AMQP broker: null");
    assert!(started.elapsed() < Duration::from_secs(5), "refused at once, not after the handshake timeout: {:?}", started.elapsed());
}

/// Not an upstream test: the Java client's automatic recovery, as the oracle shows it. A publish while the broker
/// is gone fails with `AlreadyClosedException`'s text; once the broker is back the declared exchange is declared
/// again at once, before anything is published.
#[test]
fn recovery_reports_the_closed_connection_and_redeclares_topology() {
    if !brokers::enabled("recovery_reports_the_closed_connection_and_redeclares_topology") {
        return;
    }
    let (broker, port) = Container::start_on_free_port(|port| {
        let mut spec = brokers::Spec::new(brokers::RABBITMQ);
        spec.ports = vec![(port, AMQP_PORT)];
        spec.ready = "Server startup complete";
        spec
    });
    let uri = format!("amqp://localhost:{port}");
    brokers::eventually(Duration::from_secs(30), || std::net::TcpStream::connect(("127.0.0.1", port)).ok().map(|_| ()));
    let binding = AmqpBinding::new(AmqpChannelType::RoutingKey, Some("recovery-ex"), Some("topic"), false, None, true, Some("rk"));
    let spec = spec_with_channel("recovering", binding);
    let publisher = block(AmqpPublisher::connect(&uri, Some(&spec))).unwrap();
    let _ = block(publisher.publish("recovering", "{}", &PublishOptions::none()));
    broker.stop();
    let error = block(publisher.publish("recovering", "{}", &PublishOptions::none())).expect_err("no broker");
    assert_eq!(
        error.message,
        "Failed to publish to AMQP channel 'recovering': connection is already closed due to connection error; protocol method: \
         #method<connection.close>(reply-code=320, reply-text=CONNECTION_FORCED - broker forced connection closure with reason 'shutdown', \
         class-id=0, method-id=0)"
    );
    broker.restart("Server startup complete");
    let declared = brokers::eventually(Duration::from_secs(30), || {
        block(async {
            let connection = lapin::Connection::connect(&uri, lapin::ConnectionProperties::default()).await.ok()?;
            let channel = connection.create_channel().await.ok()?;
            let passive = ExchangeDeclareOptions { passive: true, ..Default::default() };
            channel.exchange_declare("recovery-ex".into(), lapin::ExchangeKind::Topic, passive, FieldTable::default()).await.ok()
        })
    });
    assert!(declared.is_some(), "the recorded exchange is declared again by recovery");
    block(publisher.close());
}
