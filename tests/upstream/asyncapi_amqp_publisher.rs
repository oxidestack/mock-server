//! `AmqpMessagePublisherTest` (mockserver-async). The destination tests call `amqp::resolve_destination` as upstream
//! calls `resolveDestination`. Where upstream hands the publisher a mocked RabbitMQ `Channel` and verifies the calls
//! made on it, the publisher here connects to a fake AMQP 0-9-1 broker in the test, which records the methods it
//! receives (`channel.open`, `confirm.select`, `exchange.declare`, `queue.declare`, `basic.publish` with its
//! properties and body, `channel.close`, `connection.close`) and answers each publish as the test scripts it: an ack,
//! a nack, a `basic.return` before the ack, a late ack, or nothing.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use mock_server::asyncapi::amqp::{AmqpPublisher, Destination, resolve_destination};
use mock_server::asyncapi::broker::{PublishOptions, Publisher};
use mock_server::asyncapi::spec::{AmqpBinding, AmqpChannelType, Channel, Spec};
use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ---- the fake broker ----

/// A method the broker received.
#[derive(Clone, Debug, PartialEq)]
enum Received {
    ChannelOpen(u16),
    ConfirmSelect(u16),
    ExchangeDeclare { name: String, kind: String, durable: bool },
    QueueDeclare { name: String, durable: bool, exclusive: bool, auto_delete: bool },
    Publish(Publish),
    ChannelClose(u16),
    ConnectionClose,
}

#[derive(Clone, Debug, PartialEq)]
struct Publish {
    channel: u16,
    exchange: String,
    routing_key: String,
    mandatory: bool,
    /// The content header's `headers` property; `None` when the message has no properties at all.
    headers: Option<Vec<(String, String)>>,
    body: Vec<u8>,
}

/// How the broker answers a publish on a channel in confirm mode.
#[derive(Clone, Copy)]
enum Answer {
    Ack,
    Nack,
    /// `basic.return` (`mandatory` and unroutable), then the ack.
    Return(u16, &'static str),
    AckAfter(Duration),
    Nothing,
}

#[derive(Default)]
struct Script {
    answers: VecDeque<Answer>,
    /// `confirm.select` is refused with a `channel.close` 540 (a broker without publisher confirms).
    refuse_confirms: bool,
}

struct FakeBroker {
    port: u16,
    received: Arc<Mutex<Vec<Received>>>,
    script: Arc<Mutex<Script>>,
}

impl FakeBroker {
    async fn start() -> FakeBroker {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (received, script) = (Arc::new(Mutex::new(Vec::new())), Arc::new(Mutex::new(Script::default())));
        tokio::spawn({
            let (received, script) = (received.clone(), script.clone());
            async move {
                while let Ok((stream, _)) = listener.accept().await {
                    tokio::spawn(serve(stream, received.clone(), script.clone()));
                }
            }
        });
        FakeBroker { port, received, script }
    }

    fn uri(&self) -> String {
        format!("amqp://guest:guest@127.0.0.1:{}", self.port)
    }

    fn answer(&self, answer: Answer) {
        self.script.lock().answers.push_back(answer);
    }

    fn received(&self) -> Vec<Received> {
        self.received.lock().clone()
    }

    fn publishes(&self) -> Vec<Publish> {
        self.received().into_iter().filter_map(|r| if let Received::Publish(p) = r { Some(p) } else { None }).collect()
    }

    /// The publishes, once there are `n` (up to 5 s): without confirms a publish returns before the broker has it.
    async fn wait_for_publishes(&self, n: usize) -> Vec<Publish> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while self.publishes().len() < n && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        self.publishes()
    }

    fn exchange_declares(&self) -> Vec<Received> {
        self.received().into_iter().filter(|r| matches!(r, Received::ExchangeDeclare { .. })).collect()
    }

    fn channel_closes(&self) -> usize {
        self.received().iter().filter(|r| matches!(r, Received::ChannelClose(_))).count()
    }
}

fn short(s: &str) -> Vec<u8> {
    let mut out = vec![s.len() as u8];
    out.extend_from_slice(s.as_bytes());
    out
}

fn long(s: &[u8]) -> Vec<u8> {
    let mut out = (s.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(s);
    out
}

fn frame(kind: u8, channel: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![kind];
    out.extend_from_slice(&channel.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out.push(0xce);
    out
}

fn method(channel: u16, class: u16, id: u16, args: &[u8]) -> Vec<u8> {
    let mut payload = class.to_be_bytes().to_vec();
    payload.extend_from_slice(&id.to_be_bytes());
    payload.extend_from_slice(args);
    frame(1, channel, &payload)
}

struct Reader<'a> {
    data: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    fn take(&mut self, n: usize) -> &[u8] {
        self.at += n;
        &self.data[self.at - n..self.at]
    }

    fn u8(&mut self) -> u8 {
        self.take(1)[0]
    }

    fn u16(&mut self) -> u16 {
        u16::from_be_bytes(self.take(2).try_into().unwrap())
    }

    fn u32(&mut self) -> u32 {
        u32::from_be_bytes(self.take(4).try_into().unwrap())
    }

    fn u64(&mut self) -> u64 {
        u64::from_be_bytes(self.take(8).try_into().unwrap())
    }

    fn short(&mut self) -> String {
        let n = self.u8() as usize;
        String::from_utf8(self.take(n).to_vec()).unwrap()
    }

    /// A field table of long strings (all a publish's headers carry).
    fn table(&mut self) -> Vec<(String, String)> {
        let end = self.u32() as usize + self.at;
        let mut out = Vec::new();
        while self.at < end {
            let key = self.short();
            assert_eq!(self.u8(), b'S', "a long-string header");
            let n = self.u32() as usize;
            out.push((key, String::from_utf8(self.take(n).to_vec()).unwrap()));
        }
        out
    }
}

/// `connection.start`'s server properties: RabbitMQ's capabilities.
fn server_properties() -> Vec<u8> {
    let mut capabilities = Vec::new();
    for name in ["publisher_confirms", "basic.nack", "exchange_exchange_bindings", "consumer_cancel_notify", "connection.blocked"] {
        capabilities.extend(short(name));
        capabilities.extend([b't', 1]);
    }
    let mut table = short("capabilities");
    table.push(b'F');
    table.extend(long(&capabilities));
    long(&table)
}

async fn serve(stream: tokio::net::TcpStream, received: Arc<Mutex<Vec<Received>>>, script: Arc<Mutex<Script>>) {
    let (mut reader, mut writer) = stream.into_split();
    let (out, mut outgoing) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    tokio::spawn(async move {
        while let Some(bytes) = outgoing.recv().await {
            if writer.write_all(&bytes).await.is_err() {
                return;
            }
        }
    });
    let mut header = [0u8; 8];
    if reader.read_exact(&mut header).await.is_err() {
        return;
    }
    let mut start = vec![0, 9];
    start.extend(server_properties());
    start.extend(long(b"PLAIN AMQPLAIN"));
    start.extend(long(b"en_US"));
    let _ = out.send(method(0, 10, 10, &start));
    // Per channel: the next delivery tag once in confirm mode, and a publish waiting for its content.
    let mut confirm_tags: std::collections::HashMap<u16, u64> = Default::default();
    let mut pending: Option<(Publish, u64)> = None;
    loop {
        let mut head = [0u8; 7];
        if reader.read_exact(&mut head).await.is_err() {
            return;
        }
        let (kind, channel, size) = (head[0], u16::from_be_bytes([head[1], head[2]]), u32::from_be_bytes([head[3], head[4], head[5], head[6]]) as usize);
        let mut payload = vec![0; size + 1];
        if reader.read_exact(&mut payload).await.is_err() {
            return;
        }
        payload.pop();
        let mut r = Reader { data: &payload, at: 0 };
        let record = |event: Received| received.lock().push(event);
        match kind {
            1 => match (r.u16(), r.u16()) {
                (10, 11) => {
                    let _ = out.send(method(0, 10, 30, &[&2047u16.to_be_bytes()[..], &131072u32.to_be_bytes(), &0u16.to_be_bytes()].concat()));
                }
                (10, 31) => {}
                (10, 40) => {
                    let _ = out.send(method(0, 10, 41, &short("")));
                }
                (10, 50) => {
                    record(Received::ConnectionClose);
                    let _ = out.send(method(0, 10, 51, &[]));
                }
                (20, 10) => {
                    record(Received::ChannelOpen(channel));
                    let _ = out.send(method(channel, 20, 11, &long(b"")));
                }
                (20, 40) => {
                    record(Received::ChannelClose(channel));
                    let _ = out.send(method(channel, 20, 41, &[]));
                }
                (20, 41) => {}
                (85, 10) => {
                    record(Received::ConfirmSelect(channel));
                    if script.lock().refuse_confirms {
                        let text = short("NOT_IMPLEMENTED - confirm.select not supported");
                        let args = [&540u16.to_be_bytes()[..], &text, &85u16.to_be_bytes(), &10u16.to_be_bytes()].concat();
                        let _ = out.send(method(channel, 20, 40, &args));
                    } else {
                        confirm_tags.insert(channel, 1);
                        let _ = out.send(method(channel, 85, 11, &[]));
                    }
                }
                (40, 10) => {
                    r.u16();
                    let (name, kind, flags) = (r.short(), r.short(), r.u8());
                    record(Received::ExchangeDeclare { name, kind, durable: flags & 0x02 != 0 });
                    let _ = out.send(method(channel, 40, 11, &[]));
                }
                (50, 10) => {
                    r.u16();
                    let (name, flags) = (r.short(), r.u8());
                    let (durable, exclusive, auto_delete) = (flags & 0x02 != 0, flags & 0x04 != 0, flags & 0x08 != 0);
                    record(Received::QueueDeclare { name: name.clone(), durable, exclusive, auto_delete });
                    let _ = out.send(method(channel, 50, 11, &[short(&name), vec![0; 8]].concat()));
                }
                (60, 40) => {
                    r.u16();
                    let (exchange, routing_key, flags) = (r.short(), r.short(), r.u8());
                    let publish = Publish { channel, exchange, routing_key, mandatory: flags & 0x01 != 0, headers: None, body: Vec::new() };
                    pending = Some((publish, 0));
                }
                (class, id) => panic!("unexpected method {class}.{id}"),
            },
            2 => {
                r.u16();
                r.u16();
                let size = r.u64();
                let flags = r.u16();
                let (mut publish, _) = pending.take().expect("a content header follows basic.publish");
                if flags != 0 {
                    assert_eq!(flags, 0x2000, "only the headers property is set");
                    publish.headers = Some(r.table());
                }
                pending = Some((publish, size));
            }
            3 => {
                if let Some((publish, _)) = pending.as_mut() {
                    publish.body.extend_from_slice(&payload);
                }
            }
            _ => {}
        }
        // A publish whose body is complete is recorded and answered.
        if matches!(&pending, Some((p, size)) if kind != 1 && p.body.len() as u64 == *size) {
            let (publish, _) = pending.take().unwrap();
            let channel = publish.channel;
            received.lock().push(Received::Publish(publish.clone()));
            let Some(tag) = confirm_tags.get_mut(&channel) else { continue };
            let delivery_tag = *tag;
            *tag += 1;
            let ack = method(channel, 60, 80, &[&delivery_tag.to_be_bytes()[..], &[0]].concat());
            match script.lock().answers.pop_front().unwrap_or(Answer::Ack) {
                Answer::Ack => {
                    let _ = out.send(ack);
                }
                Answer::Nack => {
                    let _ = out.send(method(channel, 60, 120, &[&delivery_tag.to_be_bytes()[..], &[0]].concat()));
                }
                Answer::Return(code, text) => {
                    let args = [&code.to_be_bytes()[..], &short(text), &short(&publish.exchange), &short(&publish.routing_key)].concat();
                    let _ = out.send(method(channel, 60, 50, &args));
                    let header = [&60u16.to_be_bytes()[..], &0u16.to_be_bytes(), &(publish.body.len() as u64).to_be_bytes(), &0u16.to_be_bytes()].concat();
                    let _ = out.send(frame(2, channel, &header));
                    if !publish.body.is_empty() {
                        let _ = out.send(frame(3, channel, &publish.body));
                    }
                    let _ = out.send(ack);
                }
                Answer::AckAfter(delay) => {
                    let out = out.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(delay).await;
                        let _ = out.send(ack);
                    });
                }
                Answer::Nothing => {}
            }
        }
    }
}

fn spec_with_channel(name: &str, binding: Option<AmqpBinding>) -> Spec {
    Spec::new("2.6.0", "Test", vec![Channel { amqp_binding: binding, ..Channel::new(name, Vec::new(), None) }])
}

fn routing_key_binding(exchange: &str, kind: &str, routing_key: Option<&str>) -> AmqpBinding {
    AmqpBinding::new(AmqpChannelType::RoutingKey, Some(exchange), Some(kind), true, None, true, routing_key)
}

async fn connect(broker: &FakeBroker, spec: Option<&Spec>) -> AmqpPublisher {
    AmqpPublisher::connect(&broker.uri(), spec).await.unwrap()
}

fn publish(channel: u16, exchange: &str, routing_key: &str, mandatory: bool, body: &str) -> Publish {
    Publish { channel, exchange: exchange.into(), routing_key: routing_key.into(), mandatory, headers: None, body: body.as_bytes().to_vec() }
}

// ---- AmqpMessagePublisherTest: destination derivation (pure, broker-free) ----

fn destination(exchange: &str, routing_key: &str) -> Destination {
    Destination { exchange: exchange.into(), routing_key: routing_key.into() }
}

#[test]
fn should_derive_default_exchange_with_channel_name_when_no_binding() {
    assert_eq!(resolve_destination("orders", None), destination("", "orders"));
}

#[test]
fn should_derive_exchange_and_channel_name_routing_key_for_routing_key_binding() {
    assert_eq!(resolve_destination("user.signedup", Some(&routing_key_binding("events", "topic", None))), destination("events", "user.signedup"));
}

#[test]
fn should_prefer_explicit_routing_key_over_channel_name() {
    assert_eq!(resolve_destination("channel-name", Some(&routing_key_binding("events", "topic", Some("explicit.key")))), destination("events", "explicit.key"));
}

#[test]
fn should_derive_default_exchange_and_queue_name_for_queue_binding() {
    let binding = AmqpBinding::new(AmqpChannelType::Queue, None, None, true, Some("orders-queue"), true, None);
    assert_eq!(resolve_destination("orders", Some(&binding)), destination("", "orders-queue"));
}

#[test]
fn should_fall_back_to_channel_name_for_queue_binding_without_queue_name() {
    let binding = AmqpBinding::new(AmqpChannelType::Queue, None, None, true, None, true, None);
    assert_eq!(resolve_destination("orders", Some(&binding)), destination("", "orders"));
}

// ---- publishing ----

#[tokio::test(flavor = "multi_thread")]
async fn should_publish_to_default_exchange_when_no_binding() {
    let broker = FakeBroker::start().await;
    let p = connect(&broker, Some(&spec_with_channel("plain", None))).await;
    p.publish("plain", r#"{"a":1}"#, &PublishOptions::none()).await.unwrap();
    assert_eq!(broker.publishes(), [publish(1, "", "plain", true, r#"{"a":1}"#)]);
    assert!(broker.exchange_declares().is_empty(), "the default exchange must not be declared");
    p.close().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_declare_and_publish_to_exchange_for_routing_key_binding() {
    let broker = FakeBroker::start().await;
    let p = connect(&broker, Some(&spec_with_channel("user.signedup", Some(routing_key_binding("events", "topic", None))))).await;
    p.publish("user.signedup", r#"{"e":1}"#, &PublishOptions::none()).await.unwrap();
    assert_eq!(broker.exchange_declares(), [Received::ExchangeDeclare { name: "events".into(), kind: "topic".into(), durable: true }]);
    assert_eq!(broker.publishes(), [publish(1, "events", "user.signedup", true, r#"{"e":1}"#)]);
    p.close().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_declare_queue_and_publish_to_default_exchange_for_queue_binding() {
    let broker = FakeBroker::start().await;
    let binding = AmqpBinding::new(AmqpChannelType::Queue, None, None, true, Some("orders-queue"), true, None);
    let p = connect(&broker, Some(&spec_with_channel("orders", Some(binding)))).await;
    p.publish("orders", r#"{"o":1}"#, &PublishOptions::none()).await.unwrap();
    let declared: Vec<Received> = broker.received().into_iter().filter(|r| matches!(r, Received::QueueDeclare { .. })).collect();
    assert_eq!(declared, [Received::QueueDeclare { name: "orders-queue".into(), durable: true, exclusive: false, auto_delete: false }]);
    assert_eq!(broker.publishes(), [publish(1, "", "orders-queue", true, r#"{"o":1}"#)]);
    p.close().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_declare_exchange_only_once_across_multiple_publishes() {
    let broker = FakeBroker::start().await;
    let p = connect(&broker, Some(&spec_with_channel("c", Some(routing_key_binding("events", "direct", None))))).await;
    p.publish("c", r#"{"n":1}"#, &PublishOptions::none()).await.unwrap();
    p.publish("c", r#"{"n":2}"#, &PublishOptions::none()).await.unwrap();
    assert_eq!(broker.exchange_declares().len(), 1);
    let publishes = broker.publishes();
    assert_eq!(publishes.len(), 2);
    assert!(publishes.iter().all(|p| p.exchange == "events" && p.routing_key == "c" && p.mandatory));
    p.close().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_emit_headers_as_amqp_properties() {
    let broker = FakeBroker::start().await;
    let p = connect(&broker, Some(&spec_with_channel("c", None))).await;
    p.publish("c", r#"{"x":1}"#, &PublishOptions::with_headers(&[("correlationId", "abc-123")])).await.unwrap();
    let sent = &broker.publishes()[0];
    assert_eq!((sent.exchange.as_str(), sent.routing_key.as_str(), sent.mandatory), ("", "c", true));
    assert_eq!(sent.headers, Some(vec![("correlationId".to_string(), "abc-123".to_string())]));
    p.close().await;
}

// ---- unroutable message detection (AMQP 0-9-1 §3.1.3) ----

/// The return listener shows in `should_fail_publish_when_broker_returns_message_as_unroutable`: a `basic.return`
/// fails the publish.
#[tokio::test(flavor = "multi_thread")]
async fn should_put_channel_into_confirm_mode_and_listen_for_returns() {
    let broker = FakeBroker::start().await;
    let p = connect(&broker, Some(&spec_with_channel("c", None))).await;
    assert_eq!(broker.received(), [Received::ChannelOpen(1), Received::ConfirmSelect(1)]);
    p.close().await;
}

/// The publish returns only once the broker's confirm has arrived, and waiting for it never closes the channel (the
/// Java client's `waitForConfirmsOrDie` would).
#[tokio::test(flavor = "multi_thread")]
async fn should_wait_for_publisher_confirm_on_every_publish() {
    let broker = FakeBroker::start().await;
    let p = connect(&broker, Some(&spec_with_channel("c", None))).await;
    broker.answer(Answer::AckAfter(Duration::from_millis(500)));
    let started = Instant::now();
    p.publish("c", r#"{"x":1}"#, &PublishOptions::none()).await.unwrap();
    assert!(started.elapsed() >= Duration::from_millis(450), "returned after {:?}, before the confirm", started.elapsed());
    assert_eq!(broker.channel_closes(), 0);
    p.close().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_fail_publish_when_broker_returns_message_as_unroutable() {
    let broker = FakeBroker::start().await;
    let p = connect(&broker, Some(&spec_with_channel("orders.new", Some(routing_key_binding("events", "topic", None))))).await;
    broker.answer(Answer::Return(312, "NO_ROUTE"));
    let failure = p.publish("orders.new", r#"{"o":1}"#, &PublishOptions::none()).await.expect_err("an unroutable publish must not be reported as success");
    assert!(failure.message.contains("was not routed to any queue"), "{}", failure.message);
    assert_eq!(
        failure.message,
        "Message published to AMQP channel 'orders.new' was not routed to any queue: \
         no queue is bound to exchange 'events' for routing key 'orders.new' (broker returned 312 NO_ROUTE)"
    );
    p.close().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_not_fail_subsequent_publish_after_an_unroutable_one() {
    let broker = FakeBroker::start().await;
    let p = connect(&broker, Some(&spec_with_channel("c", None))).await;
    broker.answer(Answer::Return(312, "NO_ROUTE"));
    assert!(p.publish("c", r#"{"n":1}"#, &PublishOptions::none()).await.is_err(), "the first publish is unroutable");
    p.publish("c", r#"{"n":2}"#, &PublishOptions::none()).await.expect("the return state must not leak between publishes");
    p.close().await;
}

/// A broker without publisher confirms closes the channel that asked for them; the publisher opens another and
/// publishes on it without `mandatory` and without waiting for a confirm (the broker sends none).
#[tokio::test(flavor = "multi_thread")]
async fn should_replace_closed_channel_and_keep_publishing_when_confirms_are_unsupported() {
    let broker = FakeBroker::start().await;
    broker.script.lock().refuse_confirms = true;
    let p = connect(&broker, Some(&spec_with_channel("c", None))).await;
    assert_eq!(broker.received(), [Received::ChannelOpen(1), Received::ConfirmSelect(1), Received::ChannelOpen(2)], "the dead channel is replaced");
    tokio::time::timeout(Duration::from_secs(3), p.publish("c", r#"{"x":1}"#, &PublishOptions::none())).await.expect("no confirm is awaited").unwrap();
    assert_eq!(broker.wait_for_publishes(1).await, [publish(2, "", "c", false, r#"{"x":1}"#)], "published on the replacement, not on the closed channel");
    p.close().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_fail_publish_on_nack_without_closing_the_channel() {
    let broker = FakeBroker::start().await;
    let p = connect(&broker, Some(&spec_with_channel("c", None))).await;
    broker.answer(Answer::Nack);
    let failure = p.publish("c", r#"{"x":1}"#, &PublishOptions::none()).await.expect_err("a nacked message must not be reported as published");
    assert_eq!(failure.message, "Failed to publish to AMQP channel 'c': broker nacked the message");
    assert_eq!(broker.channel_closes(), 0);
    p.publish("c", r#"{"x":2}"#, &PublishOptions::none()).await.expect("the publisher still works once the broker recovers");
    p.close().await;
}

/// `CONFIRM_TIMEOUT` is 5 s, so this test takes that long.
#[tokio::test(flavor = "multi_thread")]
async fn should_fail_publish_on_confirm_timeout_without_closing_the_channel() {
    let broker = FakeBroker::start().await;
    let p = connect(&broker, Some(&spec_with_channel("c", None))).await;
    broker.answer(Answer::Nothing);
    let failure = p.publish("c", r#"{"x":1}"#, &PublishOptions::none()).await.expect_err("a confirm timeout must not be reported as published");
    assert!(failure.message.starts_with("Failed to publish to AMQP channel 'c': "), "{}", failure.message);
    assert_eq!(broker.channel_closes(), 0);
    p.publish("c", r#"{"x":2}"#, &PublishOptions::none()).await.expect("the channel survives, so publishing resumes");
    assert_eq!(broker.publishes().last(), Some(&publish(1, "", "c", true, r#"{"x":2}"#)));
    p.close().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn close_should_close_channel_and_connection() {
    let broker = FakeBroker::start().await;
    let p = connect(&broker, None).await;
    p.close().await;
    let received = broker.received();
    assert!(received.contains(&Received::ChannelClose(1)), "{received:?}");
    assert_eq!(received.last(), Some(&Received::ConnectionClose));
}
