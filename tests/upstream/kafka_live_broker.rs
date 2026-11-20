//! `KafkaLiveBrokerIntegrationTest`, `KafkaSecurityLiveBrokerIntegrationTest`, `KafkaAvroLiveBrokerIntegrationTest` and
//! `AsyncApiControlPlaneLiveBrokerIntegrationTest` (mockserver-async): the Kafka adapters and the control plane's
//! load → publish → consume path against cp-kafka 7.6.1. The originals' plain `KafkaConsumer` checks read the
//! topic with an independent client (`rskafka`) here.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use mock_server::asyncapi::broker::{ErrorKind, PublishOptions, Publisher, Subscriber};
use mock_server::asyncapi::kafka::{KafkaPublisher, KafkaSecurity, KafkaSubscriber};
use mock_server::asyncapi::orchestrator::Orchestrator;
use mock_server::asyncapi::spec::{Channel, Spec};

use crate::brokers::{self, Kafka, block};

/// `PublishOptions` with a key and headers.
fn options(key: Option<&str>, headers: &[(&str, &str)]) -> PublishOptions {
    PublishOptions { key: key.map(str::to_string), ..PublishOptions::with_headers(headers) }
}

fn kafka() -> &'static Kafka {
    static BROKER: OnceLock<Kafka> = OnceLock::new();
    BROKER.get_or_init(|| brokers::kafka(&[]))
}

fn payload(record: &rskafka::record::Record) -> Option<String> {
    record.value.as_ref().map(|v| String::from_utf8_lossy(v).into_owned())
}

// ---- KafkaLiveBrokerIntegrationTest ----

#[test]
fn should_publish_and_consume_message_via_live_kafka_broker() {
    if !brokers::enabled("should_publish_and_consume_message_via_live_kafka_broker") {
        return;
    }
    let topic = "test-publish-consume";
    let publisher = Arc::new(block(KafkaPublisher::new(&kafka().bootstrap, None, None)).unwrap());
    block(publisher.publish(topic, r#"{"orderId":42}"#, &options(None, &[]))).unwrap();
    block(publisher.close());
    let record = brokers::consume_one(&kafka().bootstrap, topic, None).expect("message should have been received from Kafka");
    assert_eq!(payload(&record).as_deref(), Some(r#"{"orderId":42}"#));
}

#[test]
fn should_publish_with_key_and_headers_via_live_broker() {
    if !brokers::enabled("should_publish_with_key_and_headers_via_live_broker") {
        return;
    }
    let topic = "test-key-headers";
    let publisher = Arc::new(block(KafkaPublisher::new(&kafka().bootstrap, None, None)).unwrap());
    block(publisher.publish(topic, r#"{"id":1}"#, &options(Some("order-123"), &[("trace-id", "abc-123")]))).unwrap();
    block(publisher.close());
    let record = brokers::consume_one(&kafka().bootstrap, topic, None).expect("message should have been received");
    assert_eq!(record.key.as_deref(), Some(b"order-123".as_slice()));
    assert_eq!(payload(&record).as_deref(), Some(r#"{"id":1}"#));
    assert!(record.headers.contains_key("trace-id"));
}

#[test]
fn subscriber_should_record_messages_from_live_broker_kafka() {
    if !brokers::enabled("subscriber_should_record_messages_from_live_broker_kafka") {
        return;
    }
    let topic = "test-subscriber-recording";
    let publisher = Arc::new(block(KafkaPublisher::new(&kafka().bootstrap, None, None)).unwrap());
    block(publisher.publish(topic, r#"{"event":"created"}"#, &options(Some("key-1"), &[]))).unwrap();
    block(publisher.close());
    let subscriber = Arc::new(block(KafkaSubscriber::new(&kafka().bootstrap, "test-subscriber-group", 1000, None, None, Default::default())).unwrap());
    block(subscriber.subscribe(topic)).unwrap();
    let messages = brokers::eventually(Duration::from_secs(30), || Some(subscriber.recorded(topic)).filter(|m| !m.is_empty())).unwrap_or_default();
    assert!(!messages.is_empty(), "subscriber should have recorded at least one message");
    assert_eq!(messages[0].channel, topic);
    assert_eq!(messages[0].key.as_deref(), Some("key-1"));
    assert_eq!(messages[0].payload.as_deref(), Some(r#"{"event":"created"}"#));
    block(subscriber.close());
}

#[test]
fn orchestrator_should_publish_examples_to_live_broker() {
    if !brokers::enabled("orchestrator_should_publish_examples_to_live_broker") {
        return;
    }
    let topic = "test-orchestrator";
    let spec = Spec::new("2.6.0", "Test API", vec![Channel::new(topic, vec![serde_json::json!({"hello": "world"})], None)]);
    let publisher = Arc::new(block(KafkaPublisher::new(&kafka().bootstrap, None, None)).unwrap());
    let orchestrator = Arc::new(Orchestrator::new(Arc::new(spec), publisher.clone(), Default::default()));
    block(orchestrator.publish_all()).unwrap();
    block(async move { publisher.close().await });
    let record = brokers::consume_one(&kafka().bootstrap, topic, None).expect("orchestrator-published message should land on Kafka");
    assert_eq!(payload(&record).as_deref(), Some(r#"{"hello":"world"}"#));
}

// ---- KafkaSecurityLiveBrokerIntegrationTest ----

const PLAIN_LOGIN_MODULE: &str = "org.apache.kafka.common.security.plain.PlainLoginModule";
/// The client's login module as the oracle image names it: its kafka-clients is relocated, so upstream's
/// `PLAIN_LOGIN_MODULE` (unshaded in its own test JVM) does not load there, nor here (scenario
/// `asyncapi_kafka_unshaded_login_module`). The broker keeps Kafka's own name.
const CLIENT_LOGIN_MODULE: &str = "shaded_package.org.apache.kafka.common.security.plain.PlainLoginModule";

fn sasl_kafka() -> &'static Kafka {
    static BROKER: OnceLock<Kafka> = OnceLock::new();
    BROKER.get_or_init(|| {
        let jaas = format!(r#"{PLAIN_LOGIN_MODULE} required username="admin" password="admin-secret" user_alice="alice-secret";"#);
        brokers::kafka(&[
            ("KAFKA_LISTENER_SECURITY_PROTOCOL_MAP", "BROKER:PLAINTEXT,PLAINTEXT:SASL_PLAINTEXT,CONTROLLER:PLAINTEXT"),
            ("KAFKA_SASL_ENABLED_MECHANISMS", "PLAIN"),
            ("KAFKA_LISTENER_NAME_PLAINTEXT_SASL_ENABLED_MECHANISMS", "PLAIN"),
            ("KAFKA_LISTENER_NAME_PLAINTEXT_PLAIN_SASL_JAAS_CONFIG", &jaas),
        ])
    })
}

fn sasl_security(username: &str, password: &str) -> KafkaSecurity {
    KafkaSecurity {
        security_protocol: Some("SASL_PLAINTEXT".into()),
        sasl_mechanism: Some("PLAIN".into()),
        sasl_jaas_config: Some(format!(r#"{CLIENT_LOGIN_MODULE} required username="{username}" password="{password}";"#)),
        ..KafkaSecurity::default()
    }
}

#[test]
fn credentialed_publisher_reaches_sasl_broker_and_message_is_consumable() {
    if !brokers::enabled("credentialed_publisher_reaches_sasl_broker_and_message_is_consumable") {
        return;
    }
    let topic = "test-sasl-positive";
    let publisher = Arc::new(block(KafkaPublisher::new(&sasl_kafka().bootstrap, Some(&sasl_security("alice", "alice-secret")), None)).unwrap());
    block(publisher.publish(topic, r#"{"orderId":42}"#, &options(None, &[]))).unwrap();
    block(publisher.flush()).expect("with correct credentials flush must not fail");
    block(publisher.close());
    let record = brokers::consume_one(&sasl_kafka().bootstrap, topic, Some(("alice", "alice-secret"))).expect("message published with valid SASL credentials \
        should have been received");
    assert_eq!(payload(&record).as_deref(), Some(r#"{"orderId":42}"#));
}

#[test]
fn publisher_with_wrong_credentials_is_rejected_by_sasl_broker() {
    if !brokers::enabled("publisher_with_wrong_credentials_is_rejected_by_sasl_broker") {
        return;
    }
    let publisher = Arc::new(block(KafkaPublisher::new(&sasl_kafka().bootstrap, Some(&sasl_security("alice", "WRONG-secret")), None)).unwrap());
    let caught = block(publisher.publish("test-sasl-negative", r#"{"orderId":99}"#, &options(None, &[]))).err().or_else(|| block(publisher.flush()).err());
    block(publisher.close());
    let caught = caught.expect("a wrong-credential publish must be rejected, not silently accepted");
    assert!(caught.has_kind(ErrorKind::Authentication), "rejection must be an authentication failure: {caught:?}");
}

/// `saslLoadRequest`: a spec with one channel whose on-load example is `{"orderId":7}`, SASL_PLAINTEXT/PLAIN to
/// `bootstrap`, no JAAS configuration (a request cannot carry one since 9.2.0).
fn sasl_load_request(topic: &str, bootstrap: &str) -> String {
    let spec = format!(
        r#"{{"asyncapi":"2.6.0","info":{{"title":"t","version":"1"}},"channels":{{"{topic}":{{"publish":{{"message":{{"payload":{{"type":"object","example":{{"orderId":7}}}}}}}}}}}}}}"#
    );
    serde_json::json!({
        "spec": spec,
        "brokerConfig": {"kafkaBootstrapServers": bootstrap, "kafkaSecurity": {"securityProtocol": "SASL_PLAINTEXT", "saslMechanism": "PLAIN"}},
    })
    .to_string()
}

/// `startupSaslConfiguration`: the SASL broker as `asyncKafkaBootstrapServers` and alice's JAAS configuration as
/// the startup-only `asyncKafkaSaslJaasConfig`.
async fn startup_sasl_server() -> (crate::common::Running, String) {
    let bootstrap = tokio::task::spawn_blocking(|| sasl_kafka().bootstrap.clone()).await.unwrap();
    let jaas = sasl_security("alice", "alice-secret").sasl_jaas_config.unwrap();
    let server = crate::common::start(&[("asyncKafkaBootstrapServers", &bootstrap), ("asyncKafkaSaslJaasConfig", &jaas)]).await;
    (server, bootstrap)
}

/// 9.2.0 (#119): the startup-only `asyncKafkaSaslJaasConfig` reaches the broker through the control plane: a load
/// that selects SASL_PLAINTEXT/PLAIN, without (and unable to send) a JAAS configuration, authenticates with the
/// startup one and its on-load message is consumable.
#[tokio::test(flavor = "multi_thread")]
async fn control_plane_authenticates_with_the_startup_jaas_config() {
    if !brokers::enabled("control_plane_authenticates_with_the_startup_jaas_config") {
        return;
    }
    let topic = "test-sasl-control-plane";
    let (server, bootstrap) = startup_sasl_server().await;
    let load = crate::common::send(server.port, "PUT", "/mockserver/asyncapi", &sasl_load_request(topic, &bootstrap)).await;
    assert_eq!(load.status, 201, "{}", load.body);
    let loaded: serde_json::Value = serde_json::from_str(&load.body).unwrap();
    assert_eq!(loaded["publishers"], 1);
    assert!(loaded.get("validationIssues").is_none(), "the on-load publish must not have failed authentication: {loaded}");
    let record = tokio::task::spawn_blocking(move || brokers::consume_one(&bootstrap, topic, Some(("alice", "alice-secret")))).await.unwrap();
    assert_eq!(record.as_ref().and_then(payload).as_deref(), Some(r#"{"orderId":7}"#));
    crate::common::send(server.port, "PUT", "/mockserver/reset", "").await;
}

/// 9.2.0 (#119): the startup JAAS is bound to the startup `asyncKafkaBootstrapServers`: a request naming another
/// bootstrap is refused before any Kafka client is built, so nothing ever connects to it.
#[tokio::test(flavor = "multi_thread")]
async fn control_plane_refuses_to_send_the_startup_jaas_config_to_another_bootstrap() {
    if !brokers::enabled("control_plane_refuses_to_send_the_startup_jaas_config_to_another_bootstrap") {
        return;
    }
    let (server, _) = startup_sasl_server().await;
    let decoy = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    decoy.set_nonblocking(true).unwrap();
    let decoy_bootstrap = format!("127.0.0.1:{}", decoy.local_addr().unwrap().port());
    let load = crate::common::send(server.port, "PUT", "/mockserver/asyncapi", &sasl_load_request("test-sasl-refused", &decoy_bootstrap)).await;
    assert_eq!(load.status, 400, "load must refuse the request with a client error (400): {}", load.body);
    assert!(load.body.contains("'kafkaBootstrapServers' must be omitted or match"), "{}", load.body);
    let status: serde_json::Value = serde_json::from_str(&crate::common::send(server.port, "GET", "/mockserver/asyncapi", "").await.body).unwrap();
    assert_eq!(status["publishers"], 0);
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while std::time::Instant::now() < deadline {
        if let Ok((_, peer)) = decoy.accept() {
            panic!("the refused request connected to {peer}");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    crate::common::send(server.port, "PUT", "/mockserver/reset", "").await;
}

// ---- AsyncApiControlPlaneLiveBrokerIntegrationTest ----

#[tokio::test(flavor = "multi_thread")]
async fn load_should_connect_to_live_broker_and_publish_on_load() {
    if !brokers::enabled("load_should_connect_to_live_broker_and_publish_on_load") {
        return;
    }
    let bootstrap = tokio::task::spawn_blocking(|| kafka().bootstrap.clone()).await.unwrap();
    let server = crate::common::start(&[]).await;
    let topic = "control-plane-live-load";
    let expected = r#"{"orderId":42,"status":"created"}"#;
    let body = serde_json::json!({
        "spec": {
            "asyncapi": "2.6.0",
            "info": {"title": "Control-Plane Live Broker", "version": "1.0.0"},
            "channels": {topic: {"publish": {"message": {"payload": {"type": "object", "example": {"orderId": 42, "status": "created"}}}}}},
        },
        "brokerConfig": {"kafkaBootstrapServers": bootstrap, "publishOnLoad": true, "consume": true, "kafkaGroupId": "control-plane-subscriber-group"},
    });
    let load = crate::common::send(server.port, "PUT", "/mockserver/asyncapi", &body.to_string()).await;
    assert_eq!(load.status, 201, "{}", load.body);
    let load: serde_json::Value = serde_json::from_str(&load.body).unwrap();
    assert_eq!(load["loaded"], true);
    assert!(load["publishers"].as_i64().unwrap() >= 1, "a Kafka publisher should have been created against the live broker");
    assert!(load.get("validationIssues").is_none(), "no load-time publish failure should have been recorded: {load}");
    let consumed = {
        let bootstrap = bootstrap.clone();
        tokio::task::spawn_blocking(move || brokers::consume_one(&bootstrap, topic, None)).await.unwrap()
    };
    assert_eq!(
        consumed.as_ref().and_then(payload).as_deref(),
        Some(expected),
        "the control-plane's publishOnLoad message should have landed on the live broker",
    );
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let status = loop {
        let status: serde_json::Value = serde_json::from_str(&crate::common::send(server.port, "GET", "/mockserver/asyncapi", "").await.body).unwrap();
        if !status["recordedMessages"].as_array().unwrap().is_empty() || tokio::time::Instant::now() >= deadline {
            break status;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    };
    assert_eq!(status["loaded"], true);
    assert!(status["publishers"].as_i64().unwrap() >= 1);
    assert!(status["subscribers"].as_i64().unwrap() >= 1);
    assert!(status.get("lastPublishFailure").is_none());
    let recorded = status["recordedMessages"].as_array().unwrap();
    assert!(!recorded.is_empty(), "the control-plane subscriber should have recorded the on-load message: {status}");
    assert_eq!(recorded[0]["channel"], topic);
    assert_eq!(recorded[0]["payload"], expected);
    crate::common::send(server.port, "PUT", "/mockserver/reset", "").await;
}

// ---- KafkaAvroLiveBrokerIntegrationTest (registry-less) ----

const AVRO_SCHEMA: &str = r#"{"type":"record","name":"Order","fields":[{"name":"orderId","type":"int"},{"name":"item","type":"string"}]}"#;

fn avro_publisher(schema: &str, id: i32) -> Arc<KafkaPublisher> {
    let writer = mock_server::asyncapi::kafka::AvroWriter::new(Some(schema), None, id).unwrap();
    Arc::new(block(KafkaPublisher::new(&kafka().bootstrap, None, Some(writer))).unwrap())
}

fn json(text: &str) -> serde_json::Value {
    serde_json::from_str(text).unwrap()
}

#[test]
fn should_publish_confluent_framed_avro_readable_by_plain_consumer() {
    if !brokers::enabled("should_publish_confluent_framed_avro_readable_by_plain_consumer") {
        return;
    }
    let topic = "avro-publish";
    let publisher = avro_publisher(AVRO_SCHEMA, 77);
    block(publisher.publish(topic, r#"{"orderId":42,"item":"widget"}"#, &options(None, &[]))).unwrap();
    block(publisher.close());
    let record = brokers::consume_one(&kafka().bootstrap, topic, None).expect("Avro message should land on Kafka");
    let value = record.value.expect("a value");
    assert!(mock_server::asyncapi::avro::is_wire_format(&value), "value should carry the Confluent wire-format header");
    let (id, payload) = mock_server::asyncapi::avro::unframe(&value).unwrap();
    assert_eq!(id, 77);
    let schema = mock_server::asyncapi::avro::parse_schema(AVRO_SCHEMA).unwrap();
    let decoded = mock_server::asyncapi::avro::avro_to_json(&schema, payload).unwrap();
    assert_eq!(json(&decoded), json(r#"{"orderId":42,"item":"widget"}"#));
}

fn avro_subscriber(group: &str, id: i32) -> Arc<KafkaSubscriber> {
    Arc::new(block(KafkaSubscriber::new(&kafka().bootstrap, group, 100, None, Some((None, Some(AVRO_SCHEMA), id)), Default::default())).unwrap())
}

#[test]
fn should_round_trip_avro_through_mock_server_adapters() {
    if !brokers::enabled("should_round_trip_avro_through_mock_server_adapters") {
        return;
    }
    let topic = "avro-roundtrip";
    let publisher = avro_publisher(AVRO_SCHEMA, 55);
    block(publisher.publish(topic, r#"{"orderId":9,"item":"gadget"}"#, &options(None, &[]))).unwrap();
    block(publisher.close());
    let subscriber = avro_subscriber("avro-roundtrip-group", 55);
    block(subscriber.subscribe(topic)).unwrap();
    let messages = brokers::eventually(Duration::from_secs(30), || Some(subscriber.recorded(topic)).filter(|m| !m.is_empty())).unwrap_or_default();
    assert!(!messages.is_empty(), "subscriber should record the decoded Avro message");
    assert_eq!(json(messages[0].payload.as_deref().unwrap()), json(r#"{"orderId":9,"item":"gadget"}"#));
    block(subscriber.close());
}

#[test]
fn should_not_decode_message_written_with_a_different_schema_id() {
    if !brokers::enabled("should_not_decode_message_written_with_a_different_schema_id") {
        return;
    }
    let topic = "avro-schema-id-mismatch";
    let other = r#"{"type":"record","name":"Order","fields":[{"name":"quantity","type":"long"},{"name":"customer","type":"string"}]}"#;
    let publisher = avro_publisher(other, 98);
    block(publisher.publish(topic, r#"{"quantity":3,"customer":"acme"}"#, &options(None, &[]))).unwrap();
    block(publisher.close());
    let subscriber = avro_subscriber("avro-mismatch-group", 55);
    block(subscriber.subscribe(topic)).unwrap();
    let messages = brokers::eventually(Duration::from_secs(30), || Some(subscriber.recorded(topic)).filter(|m| !m.is_empty())).unwrap_or_default();
    assert!(!messages.is_empty(), "the message should still be recorded");
    let payload = messages[0].payload.clone().unwrap_or_default();
    assert!(!payload.contains(r#""orderId":3"#), "a mismatched schema must not be decoded into the configured schema's fields: {payload}");
    assert!(!payload.contains(r#""item":"acme""#));
    block(subscriber.close());
}

// ---- Broker-client fidelity: what kafka-clients 4.3.1 does that the originals do not exercise ----

/// `kafka-topics --create` inside the broker container, over its inter-broker listener.
fn create_topic(topic: &str, partitions: u32, config: &[&str]) {
    create_topic_on(kafka(), topic, &["--partitions", &partitions.to_string()], config);
}

/// `kafka-topics --create` on `broker` with `layout` (`--partitions <n>` or `--replica-assignment <list>`).
fn create_topic_on(broker: &Kafka, topic: &str, layout: &[&str], config: &[&str]) {
    let mut args = vec!["exec".to_string(), broker.container.id.clone(), "kafka-topics".into(), "--bootstrap-server".into(), "localhost:9093".into()];
    args.extend(["--create".into(), "--topic".into(), topic.into()]);
    args.extend(layout.iter().map(|a| a.to_string()));
    for c in config {
        args.extend(["--config".to_string(), c.to_string()]);
    }
    let out = std::process::Command::new("docker").args(&args).output().unwrap();
    assert!(out.status.success(), "kafka-topics: {}", String::from_utf8_lossy(&out.stderr));
}

/// A topic whose `compression.type` makes the broker recompress every batch with lz4 or zstd: the subscriber
/// decodes the batches as `KafkaConsumer` does (it used to skip them).
#[test]
fn subscriber_records_lz4_and_zstd_compressed_batches() {
    if !brokers::enabled("subscriber_records_lz4_and_zstd_compressed_batches") {
        return;
    }
    for codec in ["lz4", "zstd"] {
        let topic = format!("test-compressed-{codec}");
        create_topic(&topic, 1, &[&format!("compression.type={codec}")]);
        let publisher = Arc::new(block(KafkaPublisher::new(&kafka().bootstrap, None, None)).unwrap());
        for n in 0..3 {
            block(publisher.publish(&topic, &format!(r#"{{"n":{n},"codec":"{codec}"}}"#), &options(Some("k"), &[("h", "v")]))).unwrap();
        }
        block(publisher.flush()).unwrap();
        block(publisher.close());
        let subscriber = Arc::new(block(KafkaSubscriber::new(&kafka().bootstrap, &format!("compressed-{codec}"), 1000, None, None, Default::default())).unwrap());
        block(subscriber.subscribe(&topic)).unwrap();
        let messages = brokers::eventually(Duration::from_secs(30), || Some(subscriber.recorded(&topic)).filter(|m| m.len() >= 3)).unwrap_or_default();
        let payloads: Vec<_> = messages.iter().map(|m| m.payload.clone().unwrap_or_default()).collect();
        assert_eq!(payloads, (0..3).map(|n| format!(r#"{{"n":{n},"codec":"{codec}"}}"#)).collect::<Vec<_>>(), "{codec}");
        assert_eq!(messages[0].key.as_deref(), Some("k"));
        block(subscriber.close());
    }
}

/// `BuiltInPartitioner`: keyless records published back to back stay on one partition until twice `batch.size`
/// (32768 bytes) went to it (a record of 1000 bytes never fills a batch), then move to a random one, which may be the
/// same. Every run of consecutive records on one partition is at least 31 records long (31 × 1070 bytes when each
/// record has a batch of its own, 33 when they share batches), except the last.
#[test]
fn keyless_records_stick_to_one_partition_per_batch_size() {
    if !brokers::enabled("keyless_records_stick_to_one_partition_per_batch_size") {
        return;
    }
    let topic = "test-sticky-partitioner";
    create_topic(topic, 3, &[]);
    let publisher = Arc::new(block(KafkaPublisher::new(&kafka().bootstrap, None, None)).unwrap());
    let filler = "x".repeat(1000 - 12);
    for n in 0..100 {
        block(publisher.publish(topic, &format!("{n:04} {filler}       "), &options(None, &[]))).unwrap();
    }
    block(publisher.flush()).unwrap();
    block(publisher.close());
    let bootstrap = kafka().bootstrap.clone();
    let mut partition_of = [usize::MAX; 100];
    block(async {
        let client = rskafka::client::ClientBuilder::new(vec![bootstrap]).build().await.unwrap();
        for p in 0..3 {
            let partition = client.partition_client(topic, p, rskafka::client::partition::UnknownTopicHandling::Retry).await.unwrap();
            let mut offset = 0;
            loop {
                let (records, high_watermark) = partition.fetch_records(offset, 1..10_000_000, 500).await.unwrap();
                for r in &records {
                    let n: usize = String::from_utf8_lossy(&r.record.value.clone().unwrap()[..4]).parse().unwrap();
                    partition_of[n] = p as usize;
                    offset = r.offset + 1;
                }
                if offset >= high_watermark {
                    break;
                }
            }
        }
    });
    assert!(partition_of.iter().all(|p| *p < 3), "every record is on some partition: {partition_of:?}");
    let mut runs = Vec::new();
    let mut start = 0;
    for n in 1..=100 {
        if n == 100 || partition_of[n] != partition_of[start] {
            runs.push(n - start);
            start = n;
        }
    }
    assert!(runs[..runs.len() - 1].iter().all(|r| *r >= 31), "runs of one partition: {runs:?} ({partition_of:?})");
}

// ---- a group whose members agree on `cooperative-sticky` ----

/// One record per partition of `topic`, valued `<tag>-p<partition>`, produced with an independent client.
fn produce_per_partition(broker: &Kafka, topic: &str, partitions: i32, tag: &str) {
    let bootstrap = broker.bootstrap.clone();
    block(async {
        let client = rskafka::client::ClientBuilder::new(vec![bootstrap]).build().await.unwrap();
        for p in 0..partitions {
            let partition = client.partition_client(topic, p, rskafka::client::partition::UnknownTopicHandling::Retry).await.unwrap();
            let record = rskafka::record::Record {
                key: None,
                value: Some(format!("{tag}-p{p}").into_bytes()),
                headers: Default::default(),
                timestamp: chrono::Utc::now(),
            };
            partition.produce(vec![record], rskafka::client::partition::Compression::NoCompression).await.unwrap();
        }
    });
}

/// A Java `KafkaConsumer` in `group` configured with one assignor alone (`CooperativeStickyAssignor` makes its
/// rebalance protocol COOPERATIVE): the broker image's `kafka-console-consumer`, with a client id (`java-member` sorts
/// after our `consumer-…` member ids) and maybe a `client.rack`, exiting after `timeout_ms` (60 s here) without
/// records. The values it prints are collected.
struct JavaMember {
    child: std::process::Child,
    values: Arc<std::sync::Mutex<Vec<String>>>,
}

impl JavaMember {
    fn start(group: &str, topic: &str) -> JavaMember {
        JavaMember::start_on(kafka(), group, topic, "CooperativeStickyAssignor", "java-member", None, 60_000)
    }

    fn start_on(broker: &Kafka, group: &str, topic: &str, assignor: &str, client_id: &str, rack: Option<&str>, timeout_ms: u32) -> JavaMember {
        use std::io::BufRead;
        let mut command = std::process::Command::new("docker");
        command
            .args(["exec", &broker.container.id, "kafka-console-consumer", "--bootstrap-server", "localhost:9093", "--topic", topic, "--group", group])
            .args(["--consumer-property", &format!("partition.assignment.strategy=org.apache.kafka.clients.consumer.{assignor}")])
            .args(["--consumer-property", &format!("client.id={client_id}"), "--consumer-property", "auto.offset.reset=earliest", "--timeout-ms", &timeout_ms.to_string()]);
        if let Some(rack) = rack {
            command.args(["--consumer-property", &format!("client.rack={rack}")]);
        }
        let mut child = command
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let values = Arc::new(std::sync::Mutex::new(Vec::new()));
        let stdout = child.stdout.take().unwrap();
        let sink = values.clone();
        std::thread::spawn(move || {
            for line in std::io::BufReader::new(stdout).lines().map_while(Result::ok) {
                sink.lock().unwrap().push(line);
            }
        });
        JavaMember { child, values }
    }

    fn values(&self) -> Vec<String> {
        self.values.lock().unwrap().clone()
    }
}

impl Drop for JavaMember {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Waits (up to 90 s) until `group` has two members holding two partitions each, as `kafka-consumer-groups
/// --describe --members` reports them: the rebalances the second member's arrival starts are over.
fn settled(broker: &Kafka, group: &str) {
    let mut last = String::new();
    let done = brokers::eventually(Duration::from_secs(90), || {
        let out = std::process::Command::new("docker")
            .args(["exec", &broker.container.id, "kafka-consumer-groups", "--bootstrap-server", "localhost:9093", "--describe", "--members", "--group", group])
            .output()
            .ok()?;
        last = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        let counts: Vec<&str> = last.lines().filter(|l| l.starts_with(group)).filter_map(|l| l.split_whitespace().last()).collect();
        (counts == ["2", "2"]).then_some(())
    });
    assert!(done.is_some(), "the group never settled on two members with two partitions each:\n{last}");
}

/// The partitions of the `<tag>-p<n>` values in `values`, sorted.
fn partitions_of(values: &[String], tag: &str) -> Vec<i32> {
    let prefix = format!("{tag}-p");
    let mut out: Vec<i32> = values.iter().filter_map(|v| v.strip_prefix(&prefix)).map(|p| p.parse().unwrap()).collect();
    out.sort();
    out
}

/// Waits until our subscriber and the Java member together hold every partition's `tag` record, then returns the
/// partitions each consumed.
fn split(subscriber: &KafkaSubscriber, java: &JavaMember, topic: &str, tag: &str, partitions: usize) -> (Vec<i32>, Vec<i32>) {
    let ours = || partitions_of(&subscriber.recorded(topic).iter().filter_map(|m| m.payload.clone()).collect::<Vec<_>>(), tag);
    brokers::eventually(Duration::from_secs(60), || (ours().len() + partitions_of(&java.values(), tag).len() >= partitions).then_some(()));
    // A record consumed twice would show up a little later.
    std::thread::sleep(Duration::from_secs(2));
    (ours(), partitions_of(&java.values(), tag))
}

/// Our subscriber leads the group (it joined first, alone, with `range`); the Java member joins and the group's
/// protocol becomes `cooperative-sticky`, so the leader assigns with `CooperativeStickyAssignor`: round robin over the
/// sorted member ids (ours p0 and p2, the Java member's p1 and p3) where `RangeAssignor` gives contiguous ranges.
#[test]
fn leader_assigns_with_cooperative_sticky_when_a_java_member_joins() {
    if !brokers::enabled("leader_assigns_with_cooperative_sticky_when_a_java_member_joins") {
        return;
    }
    let (topic, group) = ("test-cooperative-leader", "cooperative-leader-group");
    create_topic(topic, 4, &[]);
    produce_per_partition(kafka(), topic, 4, "warm");
    let subscriber = Arc::new(block(KafkaSubscriber::new(&kafka().bootstrap, group, 1000, None, None, Default::default())).unwrap());
    block(subscriber.subscribe(topic)).unwrap();
    let warmed = brokers::eventually(Duration::from_secs(30), || {
        (subscriber.recorded(topic).iter().filter(|m| m.payload.as_deref().is_some_and(|p| p.starts_with("warm-"))).count() >= 4).then_some(())
    });
    assert!(warmed.is_some(), "our subscriber alone consumes every partition");
    let java = JavaMember::start(group, topic);
    // Joining, the Java member makes the group rebalance; then the next records show the split.
    settled(kafka(), group);
    produce_per_partition(kafka(), topic, 4, "next");
    let (ours, theirs) = split(&subscriber, &java, topic, "next", 4);
    assert_eq!((ours.clone(), theirs.clone()), (vec![0, 2], vec![1, 3]), "ours {ours:?}, the Java member's {theirs:?}");
    assert!(partitions_of(&java.values(), "warm").is_empty(), "the Java member resumes from our committed offsets");
    block(subscriber.close());
}

/// The Java member leads and owns every partition; when our subscriber joins, the cooperative leader first takes p2
/// and p3 away from itself (our member gets nothing), revokes them and rejoins, and our member, rejoining on the
/// heartbeat's `REBALANCE_IN_PROGRESS`, then gets them: each record is consumed once.
#[test]
fn member_takes_partitions_a_java_cooperative_leader_revokes() {
    if !brokers::enabled("member_takes_partitions_a_java_cooperative_leader_revokes") {
        return;
    }
    let (topic, group) = ("test-cooperative-member", "cooperative-member-group");
    create_topic(topic, 4, &[]);
    produce_per_partition(kafka(), topic, 4, "warm");
    let java = JavaMember::start(group, topic);
    let warmed = brokers::eventually(Duration::from_secs(60), || (partitions_of(&java.values(), "warm").len() >= 4).then_some(()));
    assert!(warmed.is_some(), "the Java member alone consumes every partition: {:?}", java.values());
    let subscriber = Arc::new(block(KafkaSubscriber::new(&kafka().bootstrap, group, 1000, None, None, Default::default())).unwrap());
    block(subscriber.subscribe(topic)).unwrap();
    settled(kafka(), group);
    produce_per_partition(kafka(), topic, 4, "next");
    let (ours, theirs) = split(&subscriber, &java, topic, "next", 4);
    assert_eq!((ours.clone(), theirs.clone()), (vec![2, 3], vec![0, 1]), "ours {ours:?}, the Java member's {theirs:?}");
    block(subscriber.close());
}

// ---- rack-aware assignment when our subscriber leads racked Java members ----

/// The two-broker cluster with racks (`brokers::kafka_racked`).
fn racked() -> &'static Kafka {
    static CLUSTER: OnceLock<Kafka> = OnceLock::new();
    CLUSTER.get_or_init(brokers::kafka_racked)
}

/// Our subscriber (no `client.rack`, as `KafkaMessageSubscriber`) leads `group` over a four-partition topic whose p0
/// and p1 live only on rack `a` (node 1) and p2 and p3 only on rack `b` (node 2); a Java member with `client.rack=b`
/// and client id `a-java-member` (its member id sorts before ours) joins with `assignor`. Returns the partitions each
/// consumed once the group settled: rounds of one record per partition are produced until two rounds in a row split
/// two and two the same way (no `kafka-consumer-groups` polling: each poll starts a JVM, and on a loaded machine
/// the two-broker cluster's admin calls timed out). The two cases run one at a time.
fn racked_split(topic: &str, group: &str, assignor: &str) -> (Vec<i32>, Vec<i32>) {
    static ONE_AT_A_TIME: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _turn = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    create_topic_on(racked(), topic, &["--replica-assignment", "1,1,2,2"], &[]);
    produce_per_partition(racked(), topic, 4, "warm");
    let subscriber = Arc::new(block(KafkaSubscriber::new(&racked().bootstrap, group, 1000, None, None, Default::default())).unwrap());
    block(subscriber.subscribe(topic)).unwrap();
    let warmed = brokers::eventually(Duration::from_secs(30), || {
        (subscriber.recorded(topic).iter().filter(|m| m.payload.as_deref().is_some_and(|p| p.starts_with("warm-"))).count() >= 4).then_some(())
    });
    assert!(warmed.is_some(), "our subscriber alone consumes every partition");
    let java = JavaMember::start_on(racked(), group, topic, assignor, "a-java-member", Some("b"), 300_000);
    let deadline = std::time::Instant::now() + Duration::from_secs(600);
    let mut last = None;
    let settled = loop {
        let round = format!("r{}", last.as_ref().map_or(0, |(n, _)| n + 1));
        produce_per_partition(racked(), topic, 4, &round);
        let this = split(&subscriber, &java, topic, &round, 4);
        if this.0.len() == 2 && this.1.len() == 2 && last.as_ref().is_some_and(|(_, l)| *l == this) {
            break this;
        }
        assert!(std::time::Instant::now() < deadline, "the group never settled two and two; last round {this:?}, Java member {:?}", java.values());
        last = Some((last.as_ref().map_or(0, |(n, _)| n + 1), this));
    };
    block(subscriber.close());
    settled
}

/// `RangeAssignor` (kafka-clients 4.3.1 on these inputs): the racked Java member, first in member order, takes the
/// rack-`b` partitions p2 and p3 and ours the rest; without racks the Java member would take p0 and p1.
#[test]
fn leader_assigns_range_by_rack_to_a_racked_java_member() {
    if !brokers::enabled("leader_assigns_range_by_rack_to_a_racked_java_member") {
        return;
    }
    let (ours, theirs) = racked_split("test-racked-range", "racked-range-group", "RangeAssignor");
    assert_eq!((ours.clone(), theirs.clone()), (vec![0, 1], vec![2, 3]), "ours {ours:?}, the Java member's {theirs:?}");
}

/// `CooperativeStickyAssignor` (kafka-clients 4.3.1 on these inputs): the rack-aware round robin gives the racked Java
/// member p2 and p3 and ours p0 and p1; without racks it would give the Java member p0 and p2.
#[test]
fn leader_assigns_cooperative_sticky_by_rack_to_a_racked_java_member() {
    if !brokers::enabled("leader_assigns_cooperative_sticky_by_rack_to_a_racked_java_member") {
        return;
    }
    let (ours, theirs) = racked_split("test-racked-sticky", "racked-sticky-group", "CooperativeStickyAssignor");
    assert_eq!((ours.clone(), theirs.clone()), (vec![0, 1], vec![2, 3]), "ours {ours:?}, the Java member's {theirs:?}");
}

// ---- the idempotent sender's producer id ----

/// kafka-clients' `Sender` asks for its producer id right after its first metadata (`bumpIdempotentEpochAndResetIdIfNeeded`),
/// not at the first record: with no `send`, the broker's request log shows the producer's ApiVersions, Metadata and
/// InitProducerId, in that order, and no Produce.
#[test]
fn init_producer_id_follows_the_first_metadata_without_a_send() {
    if !brokers::enabled("init_producer_id_follows_the_first_metadata_without_a_send") {
        return;
    }
    // A broker of its own: only this producer's requests (client id `producer-<n>`) are in its log.
    let broker = brokers::kafka(&[("KAFKA_LOG4J_LOGGERS", "kafka.request.logger=DEBUG")]);
    let publisher = block(KafkaPublisher::new(&broker.bootstrap, None, None)).unwrap();
    let keys = |logs: &str| -> Vec<String> {
        logs.lines()
            .filter(|l| l.contains("Completed request:") && l.contains(r#""clientId":"producer-"#))
            .filter_map(|l| l.split(r#""requestApiKeyName":""#).nth(1)?.split('"').next().map(str::to_string))
            .collect()
    };
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let mut seen = keys(&broker.container.logs());
    while !seen.iter().any(|k| k == "INIT_PRODUCER_ID") && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(250));
        seen = keys(&broker.container.logs());
    }
    block(publisher.close());
    let position = |name: &str| seen.iter().position(|k| k == name);
    let (metadata, init) = (position("METADATA"), position("INIT_PRODUCER_ID"));
    assert!(init.is_some(), "no InitProducerId without a send: {seen:?}");
    assert!(metadata < init, "InitProducerId before the first Metadata: {seen:?}");
    assert!(position("API_VERSIONS") < metadata, "{seen:?}");
    assert!(position("PRODUCE").is_none(), "a Produce with no record sent: {seen:?}");
}
