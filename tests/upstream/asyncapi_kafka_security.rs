//! `KafkaSecurityPropertiesTest`, `KafkaMessagePublisherSecurityTest` and `KafkaMessageSubscriberSecurityTest`
//! (mockserver-async): the `KafkaSecurity` model and the client properties the producer and the consumer are built
//! from. The builder is a struct literal here, and the getters are its fields.

use mock_server::asyncapi::kafka::{ClientProperties, KafkaSecurity, apply_security, consumer_properties, producer_properties};

fn some(s: &str) -> Option<String> {
    Some(s.to_string())
}

const PLAIN_JAAS: &str = r#"org.apache.kafka.common.security.plain.PlainLoginModule required username="u" password="p";"#;

/// `SASL_SSL` with PLAIN and every SSL setting.
fn full_security() -> KafkaSecurity {
    KafkaSecurity {
        security_protocol: some("SASL_SSL"),
        sasl_mechanism: some("PLAIN"),
        sasl_jaas_config: some(PLAIN_JAAS),
        ssl_truststore_location: some("/truststore.jks"),
        ssl_truststore_password: some("tspass"),
        ssl_keystore_location: some("/keystore.jks"),
        ssl_keystore_password: some("kspass"),
        ssl_key_password: some("keypass"),
    }
}

/// `SSL` with a trust store only.
fn partial_security() -> KafkaSecurity {
    KafkaSecurity {
        security_protocol: some("SSL"),
        ssl_truststore_location: some("/truststore.jks"),
        ssl_truststore_password: some("tspass"),
        ..Default::default()
    }
}

fn existing(key: &str, value: &str) -> ClientProperties {
    let mut props = ClientProperties::default();
    props.put(key, value);
    props
}

// ---- KafkaSecurityPropertiesTest ----

#[test]
fn empty_security_should_be_empty() {
    assert!(KafkaSecurity::default().is_empty());
}

#[test]
fn security_with_any_field_should_not_be_empty() {
    assert!(!KafkaSecurity { security_protocol: some("SSL"), ..Default::default() }.is_empty());
    assert!(!KafkaSecurity { sasl_mechanism: some("PLAIN"), ..Default::default() }.is_empty());
    assert!(!KafkaSecurity { ssl_key_password: some("x"), ..Default::default() }.is_empty());
}

#[test]
fn security_with_blank_fields_should_be_empty() {
    assert!(KafkaSecurity { security_protocol: some(""), sasl_mechanism: some("  "), ..Default::default() }.is_empty());
}

#[test]
fn getters_should_return_configured_values() {
    let sec = KafkaSecurity {
        security_protocol: some("SASL_SSL"),
        sasl_mechanism: some("PLAIN"),
        sasl_jaas_config: some("jaas-config"),
        ssl_truststore_location: some("/t.jks"),
        ssl_truststore_password: some("tpass"),
        ssl_keystore_location: some("/k.jks"),
        ssl_keystore_password: some("kpass"),
        ssl_key_password: some("keypass"),
    };
    assert_eq!(sec.security_protocol.as_deref(), Some("SASL_SSL"));
    assert_eq!(sec.sasl_mechanism.as_deref(), Some("PLAIN"));
    assert_eq!(sec.sasl_jaas_config.as_deref(), Some("jaas-config"));
    assert_eq!(sec.ssl_truststore_location.as_deref(), Some("/t.jks"));
    assert_eq!(sec.ssl_truststore_password.as_deref(), Some("tpass"));
    assert_eq!(sec.ssl_keystore_location.as_deref(), Some("/k.jks"));
    assert_eq!(sec.ssl_keystore_password.as_deref(), Some("kpass"));
    assert_eq!(sec.ssl_key_password.as_deref(), Some("keypass"));
}

#[test]
fn should_apply_all_security_properties() {
    let mut props = ClientProperties::default();
    apply_security(&mut props, Some(&full_security()));
    assert_eq!(props.get("security.protocol"), Some("SASL_SSL"));
    assert_eq!(props.get("sasl.mechanism"), Some("PLAIN"));
    assert_eq!(props.get("sasl.jaas.config"), Some(PLAIN_JAAS));
    assert_eq!(props.get("ssl.truststore.location"), Some("/truststore.jks"));
    assert_eq!(props.get("ssl.truststore.password"), Some("tspass"));
    assert_eq!(props.get("ssl.keystore.location"), Some("/keystore.jks"));
    assert_eq!(props.get("ssl.keystore.password"), Some("kspass"));
    assert_eq!(props.get("ssl.key.password"), Some("keypass"));
}

#[test]
fn should_apply_partial_security() {
    let mut props = ClientProperties::default();
    apply_security(&mut props, Some(&partial_security()));
    assert_eq!(props.get("security.protocol"), Some("SSL"));
    assert_eq!(props.get("ssl.truststore.location"), Some("/truststore.jks"));
    assert_eq!(props.get("ssl.truststore.password"), Some("tspass"));
    // No SASL or key store settings.
    assert!(!props.contains_key("sasl.mechanism"));
    assert!(!props.contains_key("sasl.jaas.config"));
    assert!(!props.contains_key("ssl.keystore.location"));
}

#[test]
fn should_skip_blank_values() {
    let security = KafkaSecurity {
        security_protocol: some("SASL_PLAINTEXT"),
        sasl_mechanism: some("PLAIN"),
        ssl_truststore_location: some(""),
        ssl_truststore_password: None,
        ..Default::default()
    };
    let mut props = ClientProperties::default();
    apply_security(&mut props, Some(&security));
    assert_eq!(props.get("security.protocol"), Some("SASL_PLAINTEXT"));
    assert_eq!(props.get("sasl.mechanism"), Some("PLAIN"));
    assert!(!props.contains_key("ssl.truststore.location"), "blank: not added");
    assert!(!props.contains_key("ssl.truststore.password"), "missing: not added");
}

#[test]
fn should_be_no_op_with_null_security() {
    let mut props = existing("existing.key", "value");
    apply_security(&mut props, None);
    assert_eq!(props.len(), 1);
    assert_eq!(props.get("existing.key"), Some("value"));
}

#[test]
fn should_be_no_op_with_empty_security() {
    let mut props = existing("existing.key", "value");
    apply_security(&mut props, Some(&KafkaSecurity::default()));
    assert_eq!(props.len(), 1);
}

#[test]
fn should_not_override_existing_properties() {
    let mut props = existing("bootstrap.servers", "original:9092");
    props.put("key.serializer", "org.apache.kafka.common.serialization.StringSerializer");
    apply_security(&mut props, Some(&KafkaSecurity { security_protocol: some("SASL_SSL"), ..Default::default() }));
    assert_eq!(props.get("bootstrap.servers"), Some("original:9092"));
    assert_eq!(props.get("key.serializer"), Some("org.apache.kafka.common.serialization.StringSerializer"));
    assert_eq!(props.get("security.protocol"), Some("SASL_SSL"));
}

// ---- KafkaMessagePublisherSecurityTest ----

#[test]
fn should_build_producer_properties_with_sasl_ssl_security() {
    let props = producer_properties("broker:9093", Some(&full_security()));
    // The producer's own settings are still there.
    assert_eq!(props.get("bootstrap.servers"), Some("broker:9093"));
    assert!(props.contains_key("key.serializer"));
    assert!(props.contains_key("value.serializer"));
    assert_eq!(props.get("security.protocol"), Some("SASL_SSL"));
    assert_eq!(props.get("sasl.mechanism"), Some("PLAIN"));
    assert_eq!(props.get("sasl.jaas.config"), Some(PLAIN_JAAS));
    assert_eq!(props.get("ssl.truststore.location"), Some("/truststore.jks"));
    assert_eq!(props.get("ssl.truststore.password"), Some("tspass"));
    assert_eq!(props.get("ssl.keystore.location"), Some("/keystore.jks"));
    assert_eq!(props.get("ssl.keystore.password"), Some("kspass"));
    assert_eq!(props.get("ssl.key.password"), Some("keypass"));
}

#[test]
fn should_build_producer_properties_with_null_security() {
    let props = producer_properties("broker:9092", None);
    assert_eq!(props.get("bootstrap.servers"), Some("broker:9092"));
    for key in ["security.protocol", "sasl.mechanism", "sasl.jaas.config", "ssl.truststore.location"] {
        assert!(!props.contains_key(key), "{key}");
    }
}

#[test]
fn should_build_producer_properties_with_empty_security() {
    let props = producer_properties("broker:9092", Some(&KafkaSecurity::default()));
    assert_eq!(props.get("bootstrap.servers"), Some("broker:9092"));
    assert!(!props.contains_key("security.protocol"));
    assert!(!props.contains_key("sasl.mechanism"));
}

#[test]
fn should_build_producer_properties_with_partial_security() {
    let props = producer_properties("broker:9093", Some(&partial_security()));
    assert_eq!(props.get("security.protocol"), Some("SSL"));
    assert_eq!(props.get("ssl.truststore.location"), Some("/truststore.jks"));
    assert_eq!(props.get("ssl.truststore.password"), Some("tspass"));
    assert!(!props.contains_key("sasl.mechanism"));
    assert!(!props.contains_key("sasl.jaas.config"));
    assert!(!props.contains_key("ssl.keystore.location"));
}

// ---- KafkaMessageSubscriberSecurityTest ----

#[test]
fn should_build_consumer_properties_with_sasl_ssl_security() {
    let jaas = r#"org.apache.kafka.common.security.scram.ScramLoginModule required username="u" password="p";"#;
    let security = KafkaSecurity {
        security_protocol: some("SASL_SSL"),
        sasl_mechanism: some("SCRAM-SHA-256"),
        sasl_jaas_config: some(jaas),
        ssl_truststore_location: some("/ca.jks"),
        ssl_truststore_password: some("capass"),
        ..Default::default()
    };
    let props = consumer_properties("broker:9093", "my-group", Some(&security));
    // The consumer's own settings.
    assert_eq!(props.get("bootstrap.servers"), Some("broker:9093"));
    assert_eq!(props.get("group.id"), Some("my-group"));
    assert_eq!(props.get("auto.offset.reset"), Some("earliest"));
    assert_eq!(props.get("enable.auto.commit"), Some("true"));
    assert!(props.contains_key("key.deserializer"));
    assert!(props.contains_key("value.deserializer"));
    // Security.
    assert_eq!(props.get("security.protocol"), Some("SASL_SSL"));
    assert_eq!(props.get("sasl.mechanism"), Some("SCRAM-SHA-256"));
    assert_eq!(props.get("sasl.jaas.config"), Some(jaas));
    assert_eq!(props.get("ssl.truststore.location"), Some("/ca.jks"));
    assert_eq!(props.get("ssl.truststore.password"), Some("capass"));
}

#[test]
fn should_build_consumer_properties_with_null_security() {
    let props = consumer_properties("broker:9092", "group1", None);
    assert_eq!(props.get("bootstrap.servers"), Some("broker:9092"));
    assert_eq!(props.get("group.id"), Some("group1"));
    assert!(!props.contains_key("security.protocol"));
    assert!(!props.contains_key("sasl.mechanism"));
}

#[test]
fn should_build_consumer_properties_with_empty_security() {
    let props = consumer_properties("broker:9092", "group1", Some(&KafkaSecurity::default()));
    assert_eq!(props.get("bootstrap.servers"), Some("broker:9092"));
    assert!(!props.contains_key("security.protocol"));
}

#[test]
fn should_build_consumer_properties_with_sasl_plaintext() {
    let security = KafkaSecurity {
        security_protocol: some("SASL_PLAINTEXT"),
        sasl_mechanism: some("PLAIN"),
        sasl_jaas_config: some("org.apache.kafka.common.security.plain.PlainLoginModule required;"),
        ..Default::default()
    };
    let props = consumer_properties("broker:9092", "grp", Some(&security));
    assert_eq!(props.get("security.protocol"), Some("SASL_PLAINTEXT"));
    assert_eq!(props.get("sasl.mechanism"), Some("PLAIN"));
    assert_eq!(props.get("sasl.jaas.config"), Some("org.apache.kafka.common.security.plain.PlainLoginModule required;"));
    assert!(!props.contains_key("ssl.truststore.location"), "no SSL settings");
}
