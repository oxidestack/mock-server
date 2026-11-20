//! `AsyncApiControlPlaneSecurityTest`, `AsyncApiControlPlaneParityConfigTest` and
//! `AsyncApiControlPlaneConfigurationInstanceTest` (mockserver-async): `parseBrokerConfig`, which is
//! [`BrokerConfig::parse`] here, over the same `brokerConfig` nodes.
//!
//! Upstream reads the broker defaults from a `Configuration` instance (what `PUT /mockserver/configuration` sets)
//! falling back to the static `ConfigurationProperties` store, or from the static store alone when the control plane
//! has no instance. A server here always has its `Config`: its runtime values ([`Config::set_runtime`], what
//! `PUT /mockserver/configuration` and `Server::set_property` set) are the instance's, and the properties it started
//! with ([`Config::with_property`], the `mockserver.*` system properties) are the static store.

use mock_server::Config;
use mock_server::asyncapi::BrokerConfig;
use serde_json::{Value, json};

use crate::common::{self, send};

fn parse(node: &Value) -> Result<BrokerConfig, String> {
    BrokerConfig::parse(Some(node), &Config::for_tests())
}

fn parsed(node: Value) -> BrokerConfig {
    parse(&node).unwrap()
}

fn ssl_property<'a>(config: &'a BrokerConfig, name: &str) -> Option<&'a str> {
    config.mqtt_security.as_ref()?.ssl_properties.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
}

// ---- AsyncApiControlPlaneSecurityTest ----

/// 9.2.0 (#119): the class's control plane starts with `asyncKafkaBootstrapServers` `broker:9093`, the only brokers
/// a SASL request may name.
fn parsed_security(node: Value) -> BrokerConfig {
    BrokerConfig::parse(Some(&node), &Config::for_tests().with_property("asyncKafkaBootstrapServers", "broker:9093")).unwrap()
}

#[test]
fn should_parse_kafka_security_from_broker_config() {
    let config = parsed_security(json!({
        "kafkaBootstrapServers": "broker:9093",
        "kafkaSecurity": {
            "securityProtocol": "SASL_SSL",
            "saslMechanism": "PLAIN",
            "sslTruststoreLocation": "/t.jks",
            "sslTruststorePassword": "tpass",
            "sslKeystoreLocation": "/k.jks",
            "sslKeystorePassword": "kpass",
            "sslKeyPassword": "keypass"
        }
    }));
    assert_eq!(config.kafka_bootstrap_servers.as_deref(), Some("broker:9093"));
    let security = config.kafka_security.expect("kafkaSecurity");
    assert!(!security.is_empty());
    assert_eq!(security.security_protocol.as_deref(), Some("SASL_SSL"));
    assert_eq!(security.sasl_mechanism.as_deref(), Some("PLAIN"));
    // no startup JAAS configuration on this control plane, and a request can never supply one
    assert_eq!(security.sasl_jaas_config, None);
    assert_eq!(security.ssl_truststore_location.as_deref(), Some("/t.jks"));
    assert_eq!(security.ssl_truststore_password.as_deref(), Some("tpass"));
    assert_eq!(security.ssl_keystore_location.as_deref(), Some("/k.jks"));
    assert_eq!(security.ssl_keystore_password.as_deref(), Some("kpass"));
    assert_eq!(security.ssl_key_password.as_deref(), Some("keypass"));
}

#[test]
fn should_return_null_kafka_security_when_absent() {
    assert!(parsed(json!({"kafkaBootstrapServers": "broker:9092"})).kafka_security.is_none());
}

#[test]
fn should_return_null_kafka_security_when_empty_object() {
    assert!(parsed(json!({"kafkaBootstrapServers": "broker:9092", "kafkaSecurity": {}})).kafka_security.is_none());
}

#[test]
fn should_parse_partial_kafka_security() {
    let config = parsed(json!({"kafkaBootstrapServers": "broker:9093", "kafkaSecurity": {"securityProtocol": "SSL", "sslTruststoreLocation": "/ca.jks"}}));
    let security = config.kafka_security.expect("kafkaSecurity");
    assert_eq!(security.security_protocol.as_deref(), Some("SSL"));
    assert_eq!(security.ssl_truststore_location.as_deref(), Some("/ca.jks"));
    assert_eq!(security.sasl_mechanism, None);
    assert_eq!(security.sasl_jaas_config, None);
}

#[test]
fn should_parse_mqtt_security_from_broker_config() {
    let config = parsed(json!({
        "mqttBrokerUrl": "ssl://broker:8883",
        "mqttSecurity": {
            "username": "mqttuser",
            "password": "mqttpass",
            "sslProperties": {
                "com.ibm.ssl.trustStore": "/t.jks",
                "com.ibm.ssl.trustStorePassword": "tpass",
                "com.ibm.ssl.protocol": "TLSv1.2"
            }
        }
    }));
    assert_eq!(config.mqtt_broker_url.as_deref(), Some("ssl://broker:8883"));
    let security = config.mqtt_security.as_ref().expect("mqttSecurity");
    assert!(!security.is_empty());
    assert_eq!(security.username.as_deref(), Some("mqttuser"));
    assert_eq!(security.password.as_deref(), Some("mqttpass"));
    assert_eq!(ssl_property(&config, "com.ibm.ssl.trustStore"), Some("/t.jks"));
    assert_eq!(ssl_property(&config, "com.ibm.ssl.trustStorePassword"), Some("tpass"));
    assert_eq!(ssl_property(&config, "com.ibm.ssl.protocol"), Some("TLSv1.2"));
}

#[test]
fn should_return_null_mqtt_security_when_absent() {
    assert!(parsed(json!({"mqttBrokerUrl": "tcp://broker:1883"})).mqtt_security.is_none());
}

#[test]
fn should_return_null_mqtt_security_when_empty_object() {
    assert!(parsed(json!({"mqttBrokerUrl": "tcp://broker:1883", "mqttSecurity": {}})).mqtt_security.is_none());
}

#[test]
fn should_parse_mqtt_security_with_username_only() {
    let config = parsed(json!({"mqttBrokerUrl": "tcp://broker:1883", "mqttSecurity": {"username": "u"}}));
    let security = config.mqtt_security.expect("mqttSecurity");
    assert_eq!(security.username.as_deref(), Some("u"));
    assert_eq!(security.password, None);
    assert!(security.ssl_properties.is_empty());
}

#[test]
fn should_parse_mqtt_security_with_ssl_properties_only() {
    let config = parsed(json!({"mqttBrokerUrl": "ssl://broker:8883", "mqttSecurity": {"sslProperties": {"com.ibm.ssl.trustStore": "/t.jks"}}}));
    let security = config.mqtt_security.as_ref().expect("mqttSecurity");
    assert_eq!((security.username.as_deref(), security.password.as_deref()), (None, None));
    assert_eq!(ssl_property(&config, "com.ibm.ssl.trustStore"), Some("/t.jks"));
}

#[test]
fn should_handle_null_broker_config_node() {
    let config = BrokerConfig::parse(None, &Config::for_tests()).unwrap();
    assert!(config.kafka_security.is_none());
    assert!(config.mqtt_security.is_none());
}

#[test]
fn should_parse_both_kafka_and_mqtt_security() {
    let config = parsed_security(json!({
        "kafkaBootstrapServers": "broker:9093",
        "kafkaSecurity": {"securityProtocol": "SASL_SSL", "saslMechanism": "PLAIN"},
        "mqttBrokerUrl": "ssl://broker:8883",
        "mqttSecurity": {"username": "u", "password": "p"}
    }));
    let kafka = config.kafka_security.expect("kafkaSecurity");
    assert_eq!((kafka.security_protocol.as_deref(), kafka.sasl_mechanism.as_deref()), (Some("SASL_SSL"), Some("PLAIN")));
    let mqtt = config.mqtt_security.expect("mqttSecurity");
    assert_eq!((mqtt.username.as_deref(), mqtt.password.as_deref()), (Some("u"), Some("p")));
}

#[test]
fn should_ignore_non_object_kafka_security_node() {
    assert!(parsed(json!({"kafkaBootstrapServers": "b:9092", "kafkaSecurity": "invalid"})).kafka_security.is_none());
}

#[test]
fn should_ignore_non_object_mqtt_security_node() {
    assert!(parsed(json!({"mqttBrokerUrl": "tcp://b:1883", "mqttSecurity": 42})).mqtt_security.is_none());
}

#[test]
fn should_ignore_non_textual_ssl_property_values() {
    let config = parsed(json!({
        "mqttBrokerUrl": "ssl://broker:8883",
        "mqttSecurity": {"username": "u", "sslProperties": {"com.ibm.ssl.trustStore": "/t.jks", "numericValue": 42}}
    }));
    assert_eq!(config.mqtt_security.as_ref().unwrap().ssl_properties, [("com.ibm.ssl.trustStore".to_string(), "/t.jks".to_string())]);
}

#[test]
fn existing_broker_config_fields_should_still_parse_when_security_present() {
    let config = parsed_security(json!({
        "kafkaBootstrapServers": "broker:9093",
        "kafkaGroupId": "my-group",
        "mqttBrokerUrl": "ssl://broker:8883",
        "mqttClientId": "my-client",
        "publishOnLoad": false,
        "consume": true,
        "publishIntervalMillis": 5000,
        "mqttQos": 2,
        "kafkaSecurity": {"securityProtocol": "SASL_SSL"},
        "mqttSecurity": {"username": "u"}
    }));
    assert_eq!(config.kafka_bootstrap_servers.as_deref(), Some("broker:9093"));
    assert_eq!(config.kafka_group_id.as_deref(), Some("my-group"));
    assert_eq!(config.mqtt_broker_url.as_deref(), Some("ssl://broker:8883"));
    assert_eq!(config.mqtt_client_id.as_deref(), Some("my-client"));
    assert!(!config.publish_on_load);
    assert!(config.consume);
    assert_eq!(config.publish_interval_millis, 5000);
    assert_eq!(config.mqtt_qos, 2);
    assert!(config.kafka_security.is_some());
    assert!(config.mqtt_security.is_some());
}

// ---- AsyncApiControlPlaneParityConfigTest ----

#[test]
fn should_default_to_mqtt_v3() {
    assert_eq!(parsed(json!({"mqttBrokerUrl": "tcp://localhost:1883"})).mqtt_protocol_version, 3);
}

#[test]
fn should_parse_mqtt_protocol_version5() {
    assert_eq!(parsed(json!({"mqttBrokerUrl": "tcp://localhost:1883", "mqttProtocolVersion": 5})).mqtt_protocol_version, 5);
}

#[test]
fn should_default_to_json_value_format() {
    let config = parsed(json!({"kafkaBootstrapServers": "localhost:9092"}));
    assert_eq!(config.kafka_value_format, "json");
    assert_eq!(config.kafka_schema_registry_url, None);
    assert_eq!(config.avro_schema, None);
    assert_eq!(config.avro_schema_id, 1);
}

#[test]
fn should_parse_avro_value_format_with_registry_and_schema() {
    let config = parsed(json!({
        "kafkaBootstrapServers": "localhost:9092",
        "kafkaValueFormat": "AVRO",
        "kafkaSchemaRegistryUrl": "http://registry:8081",
        "avroSchemaId": 100005,
        "avroSchema": r#"{"type":"record","name":"M","fields":[]}"#
    }));
    assert_eq!(config.kafka_value_format, "avro");
    assert_eq!(config.kafka_schema_registry_url.as_deref(), Some("http://registry:8081"));
    assert_eq!(config.avro_schema_id, 100005);
    assert!(config.avro_schema.as_deref().unwrap().contains(r#""record""#));
}

#[test]
fn should_reject_unsupported_mqtt_protocol_version() {
    let error = parse(&json!({"mqttBrokerUrl": "tcp://localhost:1883", "mqttProtocolVersion": 4})).expect_err("rejected");
    assert!(error.contains("mqttProtocolVersion") && error.contains("3 or 5"), "{error}");
}

#[test]
fn should_reject_protobuf_kafka_value_format() {
    let error = parse(&json!({"kafkaBootstrapServers": "localhost:9092", "kafkaValueFormat": "protobuf"})).expect_err("rejected");
    assert!(error.contains("kafkaValueFormat") && error.contains("protobuf is not yet supported"), "{error}");
}

#[test]
fn should_reject_unknown_kafka_value_format() {
    let error = parse(&json!({"kafkaBootstrapServers": "localhost:9092", "kafkaValueFormat": "yaml"})).expect_err("rejected");
    assert!(error.contains("kafkaValueFormat") && error.contains("json or avro"), "{error}");
}

#[test]
fn should_accept_inline_avro_schema_object() {
    let config = parsed(json!({
        "kafkaBootstrapServers": "localhost:9092",
        "kafkaValueFormat": "avro",
        "avroSchema": {"type": "record", "name": "Order", "fields": []},
    }));
    let schema = config.avro_schema.expect("avroSchema");
    assert!(schema.contains(r#""Order""#), "{schema}");
    // The object comes back as JSON text.
    assert_eq!(serde_json::from_str::<Value>(&schema).unwrap()["name"], "Order");
}

// ---- AsyncApiControlPlaneConfigurationInstanceTest ----

/// A server's configuration with `name` set at runtime, as `PUT /mockserver/configuration` sets it.
fn instance(settings: &[(&str, &str)]) -> Config {
    let config = Config::for_tests();
    for (name, value) in settings {
        config.set_runtime(name, value.to_string());
    }
    config
}

fn consume_false(config: &Config) -> BrokerConfig {
    BrokerConfig::parse(Some(&json!({"consume": false})), config).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn should_use_kafka_bootstrap_servers_from_configuration_instance() {
    let config = consume_false(&instance(&[("asyncKafkaBootstrapServers", "instance-kafka:9092")]));
    assert_eq!(config.kafka_bootstrap_servers.as_deref(), Some("instance-kafka:9092"));

    // Over HTTP: since 9.2.0 (#119) `PUT /mockserver/configuration` leaves `asyncKafkaBootstrapServers` as it started
    // (the brokers every SASL credential goes to), so the next load has no default Kafka broker.
    let r = common::start(&[]).await;
    let update = send(r.port, "PUT", "/mockserver/configuration", r#"{"asyncKafkaBootstrapServers":"localhost:19999"}"#).await;
    assert_eq!(update.status, 200, "{}", update.body);
    assert_eq!(serde_json::from_str::<Value>(&update.body).unwrap()["asyncKafkaBootstrapServers"], "");
    let spec = json!({
        "asyncapi": "2.6.0",
        "info": {"title": "Instance", "version": "1.0.0"},
        "channels": {"test": {"publish": {"message": {"payload": {"type": "string"}}}}},
    });
    let body = json!({"spec": spec, "brokerConfig": {"consume": false, "publishOnLoad": false}});
    let loaded = send(r.port, "PUT", "/mockserver/asyncapi", &body.to_string()).await;
    assert_eq!(loaded.status, 201, "{}", loaded.body);
    assert_eq!(serde_json::from_str::<Value>(&loaded.body).unwrap()["publishers"], 0);

    // Set at startup, the server's configured default makes the Kafka publisher of the next load.
    let r = common::start(&[("asyncKafkaBootstrapServers", "localhost:19999")]).await;
    let loaded = send(r.port, "PUT", "/mockserver/asyncapi", &body.to_string()).await;
    assert_eq!(loaded.status, 201, "{}", loaded.body);
    assert_eq!(serde_json::from_str::<Value>(&loaded.body).unwrap()["publishers"], 1);
}

#[test]
fn should_use_mqtt_broker_url_from_configuration_instance() {
    let config = consume_false(&instance(&[("asyncMqttBrokerUrl", "tcp://instance-mqtt:1883")]));
    assert_eq!(config.mqtt_broker_url.as_deref(), Some("tcp://instance-mqtt:1883"));
}

#[test]
fn should_use_amqp_uri_from_configuration_instance() {
    let config = consume_false(&instance(&[("asyncAmqpUri", "amqp://instance-amqp:5672")]));
    assert_eq!(config.amqp_uri.as_deref(), Some("amqp://instance-amqp:5672"));
}

#[test]
fn should_use_recorded_message_max_entries_from_configuration_instance() {
    let config = instance(&[("asyncRecordedMessageMaxEntries", "4321")]);
    assert_eq!(mock_server::asyncapi::recorded_message_max_entries(&config), 4321);
}

#[test]
fn should_prefer_explicit_request_values_over_configuration_instance() {
    let config = instance(&[
        ("asyncKafkaBootstrapServers", "instance-kafka:9092"),
        ("asyncMqttBrokerUrl", "tcp://instance-mqtt:1883"),
        ("asyncAmqpUri", "amqp://instance-amqp:5672"),
    ]);
    let node = json!({"kafkaBootstrapServers": "request-kafka:9092", "mqttBrokerUrl": "tcp://request-mqtt:1883", "amqpUri": "amqp://request-amqp:5672"});
    let parsed = BrokerConfig::parse(Some(&node), &config).unwrap();
    assert_eq!(parsed.kafka_bootstrap_servers.as_deref(), Some("request-kafka:9092"));
    assert_eq!(parsed.mqtt_broker_url.as_deref(), Some("tcp://request-mqtt:1883"));
    assert_eq!(parsed.amqp_uri.as_deref(), Some("amqp://request-amqp:5672"));
}

/// Without a runtime value, the property the server started with.
#[test]
fn should_fall_back_to_static_store_when_no_configuration_instance() {
    let config = consume_false(&Config::for_tests().with_property("asyncKafkaBootstrapServers", "static-kafka:9092"));
    assert_eq!(config.kafka_bootstrap_servers.as_deref(), Some("static-kafka:9092"));
}

/// A configuration with runtime values of its own still sees the started-with properties for the rest.
#[test]
fn should_fall_back_through_configuration_instance_to_static_store() {
    let config = Config::for_tests().with_property("asyncMqttBrokerUrl", "tcp://static-mqtt:1883");
    config.set_runtime("asyncKafkaBootstrapServers", "instance-kafka:9092".into());
    let parsed = consume_false(&config);
    assert_eq!(parsed.mqtt_broker_url.as_deref(), Some("tcp://static-mqtt:1883"));
    assert_eq!(parsed.kafka_bootstrap_servers.as_deref(), Some("instance-kafka:9092"));
}
