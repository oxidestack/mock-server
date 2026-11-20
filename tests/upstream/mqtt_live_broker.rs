//! `MqttLiveBrokerIntegrationTest`, `Mqtt5LiveBrokerIntegrationTest`, `MqttTlsLiveBrokerIntegrationTest` and
//! `MqttTlsHandshakeLiveBrokerIntegrationTest` (mockserver-async): the MQTT adapters against Mosquitto 2.0.22. The
//! "plain Paho" clients of the originals are plain `rumqttc` clients here.

use std::sync::mpsc;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use mock_server::asyncapi::broker::{Counters, ErrorKind, PublishOptions, Publisher, Subscriber};
use mock_server::asyncapi::mqtt::{MqttPublisher, MqttSecurity, MqttSubscriber, Version};
use mock_server::asyncapi::orchestrator::Orchestrator;
use mock_server::asyncapi::spec::{Channel, Spec};
use mock_server::asyncapi::store::ConsumedMessage;

use crate::brokers::{self, Container, block};

const MQTT_PORT: u16 = 1883;
const MQTT_TLS_PORT: u16 = 8883;

fn plain_broker() -> &'static Container {
    static BROKER: OnceLock<Container> = OnceLock::new();
    BROKER.get_or_init(|| brokers::mosquitto(MQTT_PORT, "allow_anonymous true\n", Vec::new(), None))
}

fn url(container: &Container) -> String {
    format!("tcp://localhost:{}", container.port(MQTT_PORT))
}

/// A message received: topic, payload and user properties.
type Message = (String, Vec<u8>, Vec<(String, String)>);

/// A plain client (Paho's `MqttClient` in the originals): subscribe and receive, or publish.
struct PlainClient {
    v3: Option<rumqttc::Client>,
    v5: Option<rumqttc::v5::Client>,
    messages: mpsc::Receiver<Message>,
    subscribed: mpsc::Receiver<()>,
    published: mpsc::Receiver<()>,
}

impl PlainClient {
    fn connect(port: u16, id: &str, version: Version, credentials: Option<(&str, &str)>, tls: Option<Arc<rustls::ClientConfig>>) -> PlainClient {
        let (tx, messages) = mpsc::channel();
        let (sub_tx, subscribed) = mpsc::channel();
        let (pub_tx, published) = mpsc::channel();
        let (ready_tx, ready) = mpsc::channel();
        let client = match version {
            Version::V3 => {
                let mut options = rumqttc::MqttOptions::new(id, "localhost", port);
                if let Some((u, p)) = credentials {
                    options.set_credentials(u, p);
                }
                if let Some(config) = tls {
                    options.set_transport(rumqttc::Transport::tls_with_config(rumqttc::TlsConfiguration::Rustls(config)));
                }
                let (client, mut connection) = rumqttc::Client::new(options, 10);
                std::thread::spawn(move || {
                    for event in connection.iter() {
                        match event {
                            Ok(rumqttc::Event::Incoming(rumqttc::Incoming::ConnAck(_))) => {
                                let _ = ready_tx.send(());
                            }
                            Ok(rumqttc::Event::Incoming(rumqttc::Incoming::Publish(p))) => {
                                let _ = tx.send((p.topic, p.payload.to_vec(), Vec::new()));
                            }
                            Ok(rumqttc::Event::Incoming(rumqttc::Incoming::SubAck(_))) => {
                                let _ = sub_tx.send(());
                            }
                            Ok(rumqttc::Event::Incoming(rumqttc::Incoming::PubAck(_))) => {
                                let _ = pub_tx.send(());
                            }
                            Ok(_) => {}
                            Err(_) => break,
                        }
                    }
                });
                PlainClient { v3: Some(client), v5: None, messages, subscribed, published }
            }
            Version::V5 => {
                let mut options = rumqttc::v5::MqttOptions::new(id, "localhost", port);
                if let Some((u, p)) = credentials {
                    options.set_credentials(u, p);
                }
                let (client, mut connection) = rumqttc::v5::Client::new(options, 10);
                std::thread::spawn(move || {
                    use rumqttc::v5::mqttbytes::v5::Packet;
                    for event in connection.iter() {
                        match event {
                            Ok(rumqttc::v5::Event::Incoming(Packet::ConnAck(_))) => {
                                let _ = ready_tx.send(());
                            }
                            Ok(rumqttc::v5::Event::Incoming(Packet::Publish(p))) => {
                                let props = p.properties.map(|p| p.user_properties).unwrap_or_default();
                                let _ = tx.send((String::from_utf8_lossy(&p.topic).into_owned(), p.payload.to_vec(), props));
                            }
                            Ok(rumqttc::v5::Event::Incoming(Packet::SubAck(_))) => {
                                let _ = sub_tx.send(());
                            }
                            Ok(rumqttc::v5::Event::Incoming(Packet::PubAck(_))) => {
                                let _ = pub_tx.send(());
                            }
                            Ok(_) => {}
                            Err(_) => break,
                        }
                    }
                });
                PlainClient { v3: None, v5: Some(client), messages, subscribed, published }
            }
        };
        ready.recv_timeout(Duration::from_secs(10)).expect("plain client connects");
        client
    }

    fn subscribe(&self, topic: &str) {
        if let Some(c) = &self.v3 {
            c.subscribe(topic, rumqttc::QoS::AtLeastOnce).unwrap();
        }
        if let Some(c) = &self.v5 {
            c.subscribe(topic, rumqttc::v5::mqttbytes::QoS::AtLeastOnce).unwrap();
        }
        self.subscribed.recv_timeout(Duration::from_secs(10)).expect("suback");
    }

    /// Publishes at QoS 1 and waits for the PUBACK, as Paho's blocking `publish` does.
    fn publish(&self, topic: &str, payload: &[u8], user_properties: &[(&str, &str)]) {
        if let Some(c) = &self.v3 {
            c.publish(topic, rumqttc::QoS::AtLeastOnce, false, payload.to_vec()).unwrap();
        }
        if let Some(c) = &self.v5 {
            let properties = rumqttc::v5::mqttbytes::v5::PublishProperties {
                user_properties: user_properties.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
                ..Default::default()
            };
            c.publish_with_properties(topic, rumqttc::v5::mqttbytes::QoS::AtLeastOnce, false, payload.to_vec(), properties).unwrap();
        }
        self.published.recv_timeout(Duration::from_secs(10)).expect("puback");
    }

    fn receive(&self) -> Option<Message> {
        self.messages.recv_timeout(Duration::from_secs(10)).ok()
    }

    fn disconnect(&self) {
        if let Some(c) = &self.v3 {
            let _ = c.disconnect();
        }
        if let Some(c) = &self.v5 {
            let _ = c.disconnect();
        }
    }
}

fn poll_recorded(subscriber: &MqttSubscriber, channel: &str, at_least: usize) -> Vec<ConsumedMessage> {
    brokers::eventually(Duration::from_secs(10), || {
        let messages = subscriber.recorded(channel);
        (messages.len() >= at_least).then_some(messages)
    })
    .unwrap_or_else(|| subscriber.recorded(channel))
}

fn payloads(messages: &[ConsumedMessage]) -> Vec<String> {
    messages.iter().filter_map(|m| m.payload.clone()).collect()
}

// ---- MqttLiveBrokerIntegrationTest ----

#[test]
fn should_publish_and_receive_message_via_live_mqtt_broker() {
    if !brokers::enabled("should_publish_and_receive_message_via_live_mqtt_broker") {
        return;
    }
    let broker = plain_broker();
    let topic = "test/publish-receive";
    let plain = PlainClient::connect(broker.port(MQTT_PORT), "test-plain-subscriber", Version::V3, None, None);
    plain.subscribe(topic);
    let publisher = Arc::new(block(MqttPublisher::connect(&url(broker), "test-publisher", 1, None, Version::V3)).unwrap());
    block(publisher.publish_bytes(topic, br#"{"orderId":42}"#, &PublishOptions::none())).unwrap();
    let (_, payload, _) = plain.receive().expect("message should have been received from MQTT");
    assert_eq!(payload, br#"{"orderId":42}"#);
    block(publisher.close());
    plain.disconnect();
}

#[test]
fn should_publish_binary_payload_via_live_broker() {
    if !brokers::enabled("should_publish_binary_payload_via_live_broker") {
        return;
    }
    let broker = plain_broker();
    let topic = "test/binary";
    let plain = PlainClient::connect(broker.port(MQTT_PORT), "test-binary-subscriber", Version::V3, None, None);
    plain.subscribe(topic);
    let publisher = Arc::new(block(MqttPublisher::connect(&url(broker), "test-binary-publisher", 1, None, Version::V3)).unwrap());
    block(publisher.publish_bytes(topic, &[0x00, 0x01, 0x02, 0x03], &PublishOptions::none())).unwrap();
    let (_, payload, _) = plain.receive().expect("binary message should have been received");
    assert_eq!(payload, [0x00, 0x01, 0x02, 0x03]);
    block(publisher.close());
    plain.disconnect();
}

#[test]
fn subscriber_should_record_messages_from_live_broker() {
    if !brokers::enabled("subscriber_should_record_messages_from_live_broker") {
        return;
    }
    let broker = plain_broker();
    let topic = "test/subscriber-record";
    let subscriber = Arc::new(block(MqttSubscriber::connect(&url(broker), "test-ms-subscriber", 1, 1000, None, Version::V3, Counters::default())).unwrap());
    block(subscriber.subscribe(topic)).unwrap();
    std::thread::sleep(Duration::from_millis(500));
    let plain = PlainClient::connect(broker.port(MQTT_PORT), "test-plain-publisher", Version::V3, None, None);
    plain.publish(topic, br#"{"event":"created"}"#, &[]);
    plain.disconnect();
    let messages = poll_recorded(&subscriber, topic, 1);
    assert!(!messages.is_empty(), "subscriber should have recorded at least one message");
    assert_eq!(messages[0].channel, topic);
    assert_eq!(messages[0].payload.as_deref(), Some(r#"{"event":"created"}"#));
    block(subscriber.close());
}

#[test]
fn subscriber_should_record_wildcard_subscription_from_live_broker() {
    if !brokers::enabled("subscriber_should_record_wildcard_subscription_from_live_broker") {
        return;
    }
    let broker = plain_broker();
    let filter = "wildcard/+/events";
    let broker_url = url(broker);
    let connect = MqttSubscriber::connect(&broker_url, "test-wildcard-subscriber", 1, 1000, None, Version::V3, Counters::default());
    let subscriber = Arc::new(block(connect).unwrap());
    block(subscriber.subscribe(filter)).unwrap();
    std::thread::sleep(Duration::from_millis(500));
    let plain = PlainClient::connect(broker.port(MQTT_PORT), "test-wildcard-publisher", Version::V3, None, None);
    plain.publish("wildcard/alpha/events", br#"{"n":1}"#, &[]);
    plain.publish("wildcard/beta/events", br#"{"n":2}"#, &[]);
    plain.disconnect();
    let messages = poll_recorded(&subscriber, filter, 2);
    assert_eq!(messages.len(), 2, "messages delivered on concrete topics must be retrievable by the wildcard filter");
    let mut got = payloads(&messages);
    got.sort();
    assert_eq!(got, [r#"{"n":1}"#, r#"{"n":2}"#]);
    let mut channels: Vec<String> = messages.iter().map(|m| m.channel.clone()).collect();
    channels.sort();
    assert_eq!(channels, ["wildcard/alpha/events", "wildcard/beta/events"], "recorded channel is the concrete topic the broker delivered on");
    block(subscriber.close());
}

#[test]
fn orchestrator_should_publish_examples_to_live_mqtt_broker() {
    if !brokers::enabled("orchestrator_should_publish_examples_to_live_mqtt_broker") {
        return;
    }
    let broker = plain_broker();
    let topic = "test/orchestrator";
    let plain = PlainClient::connect(broker.port(MQTT_PORT), "test-orch-subscriber", Version::V3, None, None);
    plain.subscribe(topic);
    let spec = Spec::new("2.6.0", "MQTT Test", vec![Channel::new(topic, vec![serde_json::json!({"hello": "mqtt"})], None)]);
    let publisher = block(MqttPublisher::connect(&url(broker), "test-orch-publisher", 1, None, Version::V3)).unwrap();
    let publisher: Arc<dyn Publisher> = Arc::new(publisher);
    let orchestrator = Arc::new(Orchestrator::new(Arc::new(spec), publisher.clone(), Default::default()));
    block(orchestrator.publish_all()).unwrap();
    let (_, payload, _) = plain.receive().expect("orchestrator-published message should land on MQTT");
    assert_eq!(payload, br#"{"hello":"mqtt"}"#);
    block(publisher.close());
    plain.disconnect();
}

#[test]
fn should_round_trip_publish_and_subscribe_via_mock_server_adapters() {
    if !brokers::enabled("should_round_trip_publish_and_subscribe_via_mock_server_adapters") {
        return;
    }
    let broker = plain_broker();
    let topic = "test/roundtrip";
    let subscriber = Arc::new(block(MqttSubscriber::connect(&url(broker), "test-rt-subscriber", 1, 1000, None, Version::V3, Counters::default())).unwrap());
    block(subscriber.subscribe(topic)).unwrap();
    std::thread::sleep(Duration::from_millis(500));
    let publisher = Arc::new(block(MqttPublisher::connect(&url(broker), "test-rt-publisher", 1, None, Version::V3)).unwrap());
    block(publisher.publish_bytes(topic, br#"{"roundtrip":true}"#, &PublishOptions::none())).unwrap();
    let messages = poll_recorded(&subscriber, topic, 1);
    assert!(!messages.is_empty(), "round-trip message should be recorded");
    assert_eq!(messages[0].payload.as_deref(), Some(r#"{"roundtrip":true}"#));
    block(publisher.close());
    block(subscriber.close());
}

// ---- Mqtt5LiveBrokerIntegrationTest ----

#[test]
fn should_publish_and_receive_via_mqtt5() {
    if !brokers::enabled("should_publish_and_receive_via_mqtt5") {
        return;
    }
    let broker = plain_broker();
    let topic = "test5/publish-receive";
    let subscriber = Arc::new(block(MqttSubscriber::connect(&url(broker), "test5-recv-sub", 1, 1000, None, Version::V5, Counters::default())).unwrap());
    block(subscriber.subscribe(topic)).unwrap();
    std::thread::sleep(Duration::from_millis(500));
    let publisher = Arc::new(block(MqttPublisher::connect(&url(broker), "test5-publisher", 1, None, Version::V5)).unwrap());
    block(publisher.publish_bytes(topic, br#"{"orderId":42}"#, &PublishOptions::none())).unwrap();
    let messages = poll_recorded(&subscriber, topic, 1);
    assert!(!messages.is_empty(), "message should arrive over MQTT 5");
    assert_eq!(messages[0].payload.as_deref(), Some(r#"{"orderId":42}"#));
    block(publisher.close());
    block(subscriber.close());
}

#[test]
fn should_deliver_user_properties_via_mqtt5() {
    if !brokers::enabled("should_deliver_user_properties_via_mqtt5") {
        return;
    }
    let broker = plain_broker();
    let topic = "test5/user-properties";
    let subscriber = Arc::new(block(MqttSubscriber::connect(&url(broker), "test5-props-sub", 1, 1000, None, Version::V5, Counters::default())).unwrap());
    block(subscriber.subscribe(topic)).unwrap();
    std::thread::sleep(Duration::from_millis(500));
    let publisher = Arc::new(block(MqttPublisher::connect(&url(broker), "test5-props-pub", 1, None, Version::V5)).unwrap());
    block(publisher.publish_bytes(topic, br#"{"a":1}"#, &PublishOptions::with_headers(&[("correlationId", "corr-xyz")]))).unwrap();
    let messages = poll_recorded(&subscriber, topic, 1);
    assert!(!messages.is_empty(), "message with user property should arrive");
    assert_eq!(messages[0].header("correlationId"), Some("corr-xyz"));
    block(publisher.close());
    block(subscriber.close());
}

#[test]
fn subscriber_should_record_via_mqtt5() {
    if !brokers::enabled("subscriber_should_record_via_mqtt5") {
        return;
    }
    let broker = plain_broker();
    let topic = "test5/subscriber-record";
    let subscriber = Arc::new(block(MqttSubscriber::connect(&url(broker), "test5-ms-sub", 1, 1000, None, Version::V5, Counters::default())).unwrap());
    block(subscriber.subscribe(topic)).unwrap();
    std::thread::sleep(Duration::from_millis(500));
    let plain = PlainClient::connect(broker.port(MQTT_PORT), "test5-plain-pub", Version::V5, None, None);
    plain.publish(topic, br#"{"event":"created"}"#, &[("trace", "t-1")]);
    plain.disconnect();
    let messages = poll_recorded(&subscriber, topic, 1);
    assert!(!messages.is_empty(), "subscriber should record the message");
    assert_eq!(messages[0].payload.as_deref(), Some(r#"{"event":"created"}"#));
    assert_eq!(messages[0].header("trace"), Some("t-1"));
    block(subscriber.close());
}

#[test]
fn should_round_trip_via_mqtt5_adapters() {
    if !brokers::enabled("should_round_trip_via_mqtt5_adapters") {
        return;
    }
    let broker = plain_broker();
    let topic = "test5/roundtrip";
    let subscriber = Arc::new(block(MqttSubscriber::connect(&url(broker), "test5-rt-sub", 1, 1000, None, Version::V5, Counters::default())).unwrap());
    block(subscriber.subscribe(topic)).unwrap();
    std::thread::sleep(Duration::from_millis(500));
    let publisher = Arc::new(block(MqttPublisher::connect(&url(broker), "test5-rt-pub", 1, None, Version::V5)).unwrap());
    block(publisher.publish_bytes(topic, br#"{"roundtrip":true}"#, &PublishOptions::none())).unwrap();
    let messages = poll_recorded(&subscriber, topic, 1);
    assert!(!messages.is_empty(), "round-trip message should be recorded");
    assert_eq!(messages[0].payload.as_deref(), Some(r#"{"roundtrip":true}"#));
    block(publisher.close());
    block(subscriber.close());
}

// ---- MqttTlsLiveBrokerIntegrationTest (credential enforcement over plaintext) ----

const USERNAME: &str = "mockserver";
const PASSWORD: &str = "s3cr3t-pw";

fn secured_broker() -> &'static Container {
    static BROKER: OnceLock<Container> = OnceLock::new();
    BROKER.get_or_init(|| {
        let command = format!("mosquitto_passwd -c -b /mosquitto/config/pwfile {USERNAME} {PASSWORD} && exec mosquitto -c /mosquitto/config/mosquitto.conf");
        brokers::mosquitto(MQTT_PORT, "allow_anonymous false\npassword_file /mosquitto/config/pwfile\nuser root\n", Vec::new(), Some(&command))
    })
}

fn credentials(username: &str, password: &str) -> MqttSecurity {
    MqttSecurity { username: Some(username.into()), password: Some(password.into()), ssl_properties: Vec::new() }
}

#[test]
fn correct_credentials_should_authenticate_and_deliver_via_secured_broker() {
    if !brokers::enabled("correct_credentials_should_authenticate_and_deliver_via_secured_broker") {
        return;
    }
    let broker = secured_broker();
    let topic = "secure/publish-receive";
    let plain = PlainClient::connect(broker.port(MQTT_PORT), "authed-subscriber", Version::V3, Some((USERNAME, PASSWORD)), None);
    plain.subscribe(topic);
    let publisher = Arc::new(block(MqttPublisher::connect(&url(broker), "authed-publisher", 1, Some(&credentials(USERNAME, PASSWORD)), Version::V3)).unwrap());
    block(publisher.publish_bytes(topic, br#"{"secure":true}"#, &PublishOptions::none())).unwrap();
    let (_, payload, _) = plain.receive().expect("authenticated publish should be delivered through the secured broker");
    assert_eq!(payload, br#"{"secure":true}"#);
    block(publisher.close());
    plain.disconnect();
}

#[test]
fn wrong_password_should_be_rejected_by_secured_broker() {
    if !brokers::enabled("wrong_password_should_be_rejected_by_secured_broker") {
        return;
    }
    let broker = secured_broker();
    let result = block(MqttPublisher::connect(&url(broker), "wrong-password-publisher", 1, Some(&credentials(USERNAME, "not-the-password")), Version::V3));
    let error = result.err().expect("connecting with the wrong password must be rejected, not silently accepted");
    assert!(error.message.contains("Failed to connect to MQTT broker"), "{error:?}");
}

#[test]
fn anonymous_connection_should_be_rejected_by_secured_broker() {
    if !brokers::enabled("anonymous_connection_should_be_rejected_by_secured_broker") {
        return;
    }
    let broker = secured_broker();
    let error = block(MqttPublisher::connect(&url(broker), "anonymous-publisher", 1, None, Version::V3))
        .err()
        .expect("anonymous connection must be rejected when allow_anonymous is false");
    assert!(error.message.contains("Failed to connect to MQTT broker"), "{error:?}");
}

// ---- MqttTlsHandshakeLiveBrokerIntegrationTest ----

const TRUSTSTORE_PASSWORD: &str = "changeit";

struct TlsBroker {
    container: Container,
    broker_ca: Vec<u8>,
    unrelated_ca: Vec<u8>,
}

fn ca(common_name: &str) -> (rcgen::CertificateParams, rcgen::KeyPair, Vec<u8>) {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.distinguished_name.push(rcgen::DnType::CommonName, common_name);
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign, rcgen::KeyUsagePurpose::CrlSign, rcgen::KeyUsagePurpose::DigitalSignature];
    let cert = params.self_signed(&key).unwrap();
    let der = cert.der().to_vec();
    (params, key, der)
}

fn tls_broker() -> &'static TlsBroker {
    static BROKER: OnceLock<TlsBroker> = OnceLock::new();
    BROKER.get_or_init(|| {
        let (ca_params, ca_key, ca_der) = ca("MockServer Async Test CA");
        let ca_pem = pem("CERTIFICATE", &ca_der);
        let server_key = rcgen::KeyPair::generate().unwrap();
        let mut server = rcgen::CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()]).unwrap();
        server.distinguished_name.push(rcgen::DnType::CommonName, "localhost");
        server.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let issuer = rcgen::Issuer::new(ca_params, ca_key);
        let server_cert = server.signed_by(&server_key, &issuer).unwrap();
        let (_, _, unrelated) = ca("Unrelated Test CA");
        let config = "allow_anonymous true\ncafile /mosquitto/config/ca.crt\ncertfile /mosquitto/config/server.crt\nkeyfile \
            /mosquitto/config/server.key\nuser root\n";
        let files = vec![
            ("/mosquitto/config/ca.crt", ca_pem.into_bytes()),
            ("/mosquitto/config/server.crt", server_cert.pem().into_bytes()),
            ("/mosquitto/config/server.key", server_key.serialize_pem().into_bytes()),
        ];
        TlsBroker { container: brokers::mosquitto(MQTT_TLS_PORT, config, files, None), broker_ca: ca_der, unrelated_ca: unrelated }
    })
}

fn pem(label: &str, der: &[u8]) -> String {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let lines: Vec<&str> = b64.as_bytes().chunks(64).map(|c| std::str::from_utf8(c).unwrap()).collect();
    format!("-----BEGIN {label}-----\n{}\n-----END {label}-----\n", lines.join("\n"))
}

/// A JKS trust store holding `certificate`, and the Paho SSL properties naming it.
fn trust_store_ssl_properties(alias: &str, certificate: &[u8]) -> Vec<(String, String)> {
    let path = std::env::temp_dir().join(format!("mqtt-tls-truststore-{}-{alias}.jks", std::process::id()));
    std::fs::write(&path, mock_server::asyncapi::tls::write_jks_truststore(&[(alias, certificate)], TRUSTSTORE_PASSWORD)).unwrap();
    vec![
        ("com.ibm.ssl.trustStore".into(), path.to_string_lossy().into_owned()),
        ("com.ibm.ssl.trustStorePassword".into(), TRUSTSTORE_PASSWORD.into()),
        ("com.ibm.ssl.trustStoreType".into(), "JKS".into()),
        ("com.ibm.ssl.protocol".into(), "TLSv1.2".into()),
    ]
}

#[test]
fn trusting_client_should_complete_tls_handshake_and_deliver_via_secured_broker() {
    if !brokers::enabled("trusting_client_should_complete_tls_handshake_and_deliver_via_secured_broker") {
        return;
    }
    let broker = tls_broker();
    let port = broker.container.port(MQTT_TLS_PORT);
    let topic = "secure/tls-publish-receive";
    let ssl_properties = trust_store_ssl_properties("broker-ca", &broker.broker_ca);
    let mut roots = rustls::RootCertStore::empty();
    roots.add(rustls::pki_types::CertificateDer::from(broker.broker_ca.clone())).unwrap();
    let plain_tls = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let plain = PlainClient::connect(port, "tls-subscriber", Version::V3, None, Some(Arc::new(plain_tls)));
    plain.subscribe(topic);
    let security = MqttSecurity { ssl_properties, ..MqttSecurity::default() };
    let publisher = Arc::new(block(MqttPublisher::connect(&format!("ssl://localhost:{port}"), "tls-publisher", 1, Some(&security), Version::V3)).unwrap());
    block(publisher.publish_bytes(topic, br#"{"secure":true}"#, &PublishOptions::none())).unwrap();
    let (_, payload, _) = plain.receive().expect("a TLS handshake with correct trust should complete and the message be delivered");
    assert_eq!(payload, br#"{"secure":true}"#);
    block(publisher.close());
    plain.disconnect();
}

/// The original asserts an `SSLException` whose message mentions PKIX; here the failure is a TLS certificate error
/// (rustls' `UnknownIssuer`) in the cause chain (`docs/divergences.md`).
#[test]
fn client_not_trusting_broker_cert_should_fail_tls_handshake() {
    if !brokers::enabled("client_not_trusting_broker_cert_should_fail_tls_handshake") {
        return;
    }
    let broker = tls_broker();
    let port = broker.container.port(MQTT_TLS_PORT);
    let security = MqttSecurity { ssl_properties: trust_store_ssl_properties("unrelated-ca", &broker.unrelated_ca), ..MqttSecurity::default() };
    let error = block(MqttPublisher::connect(&format!("ssl://localhost:{port}"), "untrusting-tls-publisher", 1, Some(&security), Version::V3))
        .err()
        .expect("a client that does not trust the broker certificate must fail, not silently connect");
    assert!(error.message.contains("Failed to connect to MQTT broker"), "{error:?}");
    let tls = error.find(ErrorKind::Tls).unwrap_or_else(|| panic!("the failure must be a TLS certificate-trust failure: {error:?}"));
    assert!(tls.message.contains("UnknownIssuer") || tls.message.contains("certificate"), "{tls:?}");
}

// ---- Paho's MQTT 3.1 fallback ----

/// A broker stand-in speaking MQTT 3.1 only: a 3.1.1 CONNECT gets CONNACK 1 (unacceptable protocol version) and the
/// connection closes; an `MQIsdp` CONNECT gets CONNACK 0, unless `refuse_all`, and then QoS 1 publishes get their
/// PUBACK. Reports each CONNECT's protocol name and level, and each publish's topic and payload.
fn mqtt31_only_broker(refuse_all: bool) -> (u16, mpsc::Receiver<String>) {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let tx = tx.clone();
            std::thread::spawn(move || {
                let read_packet = |stream: &mut std::net::TcpStream| -> Option<(u8, Vec<u8>)> {
                    let mut first = [0u8; 1];
                    stream.read_exact(&mut first).ok()?;
                    let (mut remaining, mut shift) = (0usize, 0);
                    loop {
                        let mut b = [0u8; 1];
                        stream.read_exact(&mut b).ok()?;
                        remaining |= ((b[0] & 0x7f) as usize) << shift;
                        shift += 7;
                        if b[0] & 0x80 == 0 {
                            break;
                        }
                    }
                    let mut body = vec![0u8; remaining];
                    stream.read_exact(&mut body).ok()?;
                    Some((first[0], body))
                };
                let Some((0x10, connect)) = read_packet(&mut stream) else { return };
                let name_length = u16::from_be_bytes([connect[0], connect[1]]) as usize;
                let name = String::from_utf8_lossy(&connect[2..2 + name_length]).into_owned();
                let level = connect[2 + name_length];
                let _ = tx.send(format!("CONNECT {name} {level}"));
                if name != "MQIsdp" || refuse_all {
                    let _ = stream.write_all(&[0x20, 0x02, 0x00, 0x01]);
                    return;
                }
                let _ = stream.write_all(&[0x20, 0x02, 0x00, 0x00]);
                while let Some((kind, body)) = read_packet(&mut stream) {
                    match kind >> 4 {
                        3 => {
                            let topic_length = u16::from_be_bytes([body[0], body[1]]) as usize;
                            let topic = String::from_utf8_lossy(&body[2..2 + topic_length]).into_owned();
                            let qos = (kind >> 1) & 3;
                            let payload_at = 2 + topic_length + if qos > 0 { 2 } else { 0 };
                            let _ = tx.send(format!("PUBLISH {topic} {}", String::from_utf8_lossy(&body[payload_at..])));
                            if qos == 1 {
                                let _ = stream.write_all(&[0x40, 0x02, body[2 + topic_length], body[3 + topic_length]]);
                            }
                        }
                        12 => {
                            let _ = stream.write_all(&[0xd0, 0x00]);
                        }
                        14 => return,
                        _ => {}
                    }
                }
            });
        }
    });
    (port, rx)
}

/// `ConnectActionListener.onFailure`: the 3.1.1 CONNECT is refused, the client connects again as MQTT 3.1 and
/// publishes over that connection.
#[test]
fn refused_mqtt311_connect_is_retried_as_mqtt31() {
    let (port, seen) = mqtt31_only_broker(false);
    let url = format!("tcp://127.0.0.1:{port}");
    let publisher = Arc::new(block(MqttPublisher::connect(&url, "mqtt31-client", 1, None, Version::V3)).expect("connects as MQTT 3.1"));
    block(publisher.publish("orders", r#"{"id":1}"#, &PublishOptions::default())).unwrap();
    block(publisher.close());
    let seen: Vec<String> = seen.try_iter().collect();
    assert_eq!(seen[..3], ["CONNECT MQTT 4", "CONNECT MQIsdp 3", r#"PUBLISH orders {"id":1}"#]);
}

/// Both attempts refused: one 3.1 retry only, and the connect fails as before.
#[test]
fn refused_mqtt31_connect_fails_after_one_retry() {
    let (port, seen) = mqtt31_only_broker(true);
    let url = format!("tcp://127.0.0.1:{port}");
    let error = block(MqttPublisher::connect(&url, "mqtt31-client", 1, None, Version::V3)).err().expect("both refused");
    assert_eq!(error.message, format!("Failed to connect to MQTT broker: {url}"));
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(seen.try_iter().collect::<Vec<_>>(), ["CONNECT MQTT 4", "CONNECT MQIsdp 3"]);
}

/// MQTT 5 has no fallback (`Mqtt5MessagePublisher` uses Paho's v5 client).
#[test]
fn refused_mqtt5_connect_is_not_retried() {
    let (port, seen) = mqtt31_only_broker(false);
    let url = format!("tcp://127.0.0.1:{port}");
    assert!(block(MqttPublisher::connect(&url, "mqtt5-client", 1, None, Version::V5)).is_err());
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(seen.try_iter().collect::<Vec<_>>(), ["CONNECT MQTT 5"]);
}
