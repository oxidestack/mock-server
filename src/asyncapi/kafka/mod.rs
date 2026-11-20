//! Kafka publishers and subscribers (`KafkaMessagePublisher`, `KafkaMessageSubscriber`, with `KafkaSecurity`), on
//! our own client over the `kafka-protocol` codecs (`wire.rs`), behaving as `kafka-clients` 4.3.1 does with the
//! configuration upstream gives it:
//!
//! - the producer is idempotent with `acks=all`; `publish` waits for the topic's metadata (auto-creating it) up to
//!   `max.block.ms` (60 s) and hands the record to a sender, `flush` waits for every send and reports the first
//!   failure; keyed records go to `murmur2(key) % partitions`;
//! - the consumer is a classic group member (`range` assignment, `auto.offset.reset=earliest`, offsets committed
//!   every 5 s and on close) polling on its own task;
//! - construction fails as `new KafkaProducer`/`new KafkaConsumer` does (`Failed to construct kafka producer`) for a
//!   bootstrap list with no resolvable address, a bad `security.protocol`, a missing JAAS configuration or an
//!   unreadable key store.

pub mod wire;
mod group;
mod range;
#[cfg(test)]
mod rack_tests;
mod sticky;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use kafka_protocol::messages::{InitProducerIdRequest, ProduceRequest, TopicName, produce_request::PartitionProduceData, produce_request::TopicProduceData};
use kafka_protocol::protocol::StrBytes;
use kafka_protocol::records::{Compression, Record, RecordBatchEncoder, RecordEncodeOptions, TimestampType};
use parking_lot::Mutex;
use serde_json::Value;

use super::broker::{BoxFuture, Counters, Error, ErrorKind, PublishOptions};
use super::store::{ConsumedMessage, ConsumedMessages};
use wire::{Cluster, Protocol, Sasl, Settings};

/// `max.block.ms`.
const MAX_BLOCK: Duration = Duration::from_secs(60);
/// `delivery.timeout.ms`.
const DELIVERY_TIMEOUT: Duration = Duration::from_secs(120);
/// `retry.backoff.ms` and `retry.backoff.max.ms`.
const RETRY_BACKOFF: Duration = Duration::from_millis(100);
const RETRY_BACKOFF_MAX: Duration = Duration::from_millis(1000);
/// `reconnect.backoff.ms` and `reconnect.backoff.max.ms`.
const RECONNECT_BACKOFF: Duration = Duration::from_millis(50);
const RECONNECT_BACKOFF_MAX: Duration = Duration::from_millis(1000);

/// `KafkaSecurity`: the eight client settings upstream passes through.
#[derive(Clone, Debug, Default)]
pub struct KafkaSecurity {
    pub security_protocol: Option<String>,
    pub sasl_mechanism: Option<String>,
    pub sasl_jaas_config: Option<String>,
    pub ssl_truststore_location: Option<String>,
    pub ssl_truststore_password: Option<String>,
    pub ssl_keystore_location: Option<String>,
    pub ssl_keystore_password: Option<String>,
    pub ssl_key_password: Option<String>,
}

fn present(s: &Option<String>) -> Option<&str> {
    s.as_deref().filter(|v| !v.trim().is_empty())
}

impl KafkaSecurity {
    pub fn is_empty(&self) -> bool {
        [
            &self.security_protocol,
            &self.sasl_mechanism,
            &self.sasl_jaas_config,
            &self.ssl_truststore_location,
            &self.ssl_truststore_password,
            &self.ssl_keystore_location,
            &self.ssl_keystore_password,
            &self.ssl_key_password,
        ]
        .iter()
        .all(|v| present(v).is_none())
    }

    /// `parseKafkaSecurity` (9.2.0, upstream #119): the textual fields of `kafkaSecurity`, nothing when all are
    /// blank. A `saslJaasConfig` or any other field outside [`KAFKA_SECURITY_FIELDS`] is refused (a JSON null is
    /// absent), `securityProtocol` is upper-cased and, like `saslMechanism`, limited to Kafka's own values. A `SASL_*`
    /// protocol takes the startup `asyncKafkaSaslJaasConfig` and may only use the startup
    /// `asyncKafkaBootstrapServers` (`requested_bootstrap` is the request's own, before the default applies). The
    /// error is upstream's `IllegalArgumentException` message.
    pub fn parse(node: Option<&Value>, requested_bootstrap: Option<&str>, config: &crate::config::Config) -> Result<Option<KafkaSecurity>, String> {
        let Some(node) = node.and_then(Value::as_object) else { return Ok(None) };
        for (name, value) in node {
            if value.is_null() || KAFKA_SECURITY_FIELDS.contains(&name.as_str()) {
                continue;
            }
            if name == "saslJaasConfig" {
                return Err(SASL_JAAS_CONFIG_STARTUP_ONLY.to_string());
            }
            let shown: String = name.chars().map(|c| if c.is_control() { '?' } else { c }).collect();
            return Err(format!(
                "unknown field '{shown}' in kafkaSecurity; valid fields are [{}] (Kafka client properties that load classes, such as sasl.jaas.config, \
                 sasl.login.class or interceptor.classes, cannot be set over the control plane)",
                KAFKA_SECURITY_FIELDS.join(", ")
            ));
        }
        let text = |k: &str| node.get(k).and_then(Value::as_str).map(str::to_string);
        let security_protocol = match text("securityProtocol") {
            Some(given) => {
                let upper = given.to_uppercase();
                if !KAFKA_SECURITY_PROTOCOLS.contains(&upper.as_str()) {
                    return Err(format!("Unsupported 'kafkaSecurity.securityProtocol' value '{given}' — allowed values are [{}]", KAFKA_SECURITY_PROTOCOLS.join(", ")));
                }
                Some(upper)
            }
            None => None,
        };
        let sasl_mechanism = text("saslMechanism");
        if let Some(mechanism) = &sasl_mechanism && !KAFKA_SASL_MECHANISMS.contains(&mechanism.as_str()) {
            return Err(format!("Unsupported 'kafkaSecurity.saslMechanism' value '{mechanism}' — allowed values are [{}]", KAFKA_SASL_MECHANISMS.join(", ")));
        }
        let mut sasl_jaas_config = None;
        if security_protocol.as_deref().is_some_and(|p| p.starts_with("SASL_")) {
            let startup = normalised_bootstrap_servers(&config.property("asyncKafkaBootstrapServers").unwrap_or_default());
            if startup.is_empty() {
                return Err(KAFKA_SASL_NEEDS_STARTUP_BOOTSTRAP_SERVERS.to_string());
            }
            if requested_bootstrap.is_some_and(|r| normalised_bootstrap_servers(r) != startup) {
                return Err(KAFKA_BOOTSTRAP_SERVERS_BOUND_TO_STARTUP.to_string());
            }
            sasl_jaas_config = config.property("asyncKafkaSaslJaasConfig").filter(|j| !j.trim().is_empty());
        }
        let security = KafkaSecurity {
            security_protocol,
            sasl_mechanism,
            sasl_jaas_config,
            ssl_truststore_location: text("sslTruststoreLocation"),
            ssl_truststore_password: text("sslTruststorePassword"),
            ssl_keystore_location: text("sslKeystoreLocation"),
            ssl_keystore_password: text("sslKeystorePassword"),
            ssl_key_password: text("sslKeyPassword"),
        };
        Ok((!security.is_empty()).then_some(security))
    }
}

/// `AsyncApiControlPlaneImpl.KAFKA_SECURITY_FIELDS`: the `kafkaSecurity` fields a request may set, none naming a
/// class the Kafka client loads.
pub const KAFKA_SECURITY_FIELDS: &[&str] =
    &["securityProtocol", "saslMechanism", "sslTruststoreLocation", "sslTruststorePassword", "sslKeystoreLocation", "sslKeystorePassword", "sslKeyPassword"];
const KAFKA_SECURITY_PROTOCOLS: &[&str] = &["PLAINTEXT", "SSL", "SASL_PLAINTEXT", "SASL_SSL"];
const KAFKA_SASL_MECHANISMS: &[&str] = &["GSSAPI", "PLAIN", "SCRAM-SHA-256", "SCRAM-SHA-512", "OAUTHBEARER"];

/// `SASL_JAAS_CONFIG_STARTUP_ONLY`: a request's `saslJaasConfig` (or any non-null `brokerConfig` field naming `jaas`).
pub const SASL_JAAS_CONFIG_STARTUP_ONLY: &str = "'kafkaSecurity.saslJaasConfig' cannot be set over the control plane: a JAAS configuration chooses which \
    login module class the Kafka client loads, so it must be set at startup. Set the mockserver.asyncKafkaSaslJaasConfig property (or the \
    MOCKSERVER_ASYNC_KAFKA_SASL_JAAS_CONFIG environment variable) before the server starts, and keep securityProtocol and saslMechanism in kafkaSecurity";
const KAFKA_BOOTSTRAP_SERVERS_BOUND_TO_STARTUP: &str = "'kafkaBootstrapServers' must be omitted or match the startup mockserver.asyncKafkaBootstrapServers \
    when a SASL securityProtocol is used: every SASL credential (mockserver.asyncKafkaSaslJaasConfig or the JVM's JAAS login configuration) is held by the \
    server, so it is sent only to the Kafka brokers chosen when the server starts";
const KAFKA_SASL_NEEDS_STARTUP_BOOTSTRAP_SERVERS: &str = "a SASL securityProtocol needs mockserver.asyncKafkaBootstrapServers (or the \
    MOCKSERVER_ASYNC_KAFKA_BOOTSTRAP_SERVERS environment variable) to be set before the server starts: every SASL credential is held by the server, so it \
    is sent only to the Kafka brokers chosen at startup";

/// `normalisedBootstrapServers`: the set of trimmed, lower-cased, non-empty `host:port` entries.
fn normalised_bootstrap_servers(servers: &str) -> std::collections::HashSet<String> {
    servers.split(',').map(|s| s.trim().to_lowercase()).filter(|s| !s.is_empty()).collect()
}

const BOOTSTRAP_SERVERS: &str = "bootstrap.servers";
const SECURITY_PROTOCOL: &str = "security.protocol";
const SASL_MECHANISM: &str = "sasl.mechanism";
const SASL_JAAS_CONFIG: &str = "sasl.jaas.config";
const SSL_TRUSTSTORE_LOCATION: &str = "ssl.truststore.location";
const SSL_TRUSTSTORE_PASSWORD: &str = "ssl.truststore.password";
const SSL_KEYSTORE_LOCATION: &str = "ssl.keystore.location";
const SSL_KEYSTORE_PASSWORD: &str = "ssl.keystore.password";
const SSL_KEY_PASSWORD: &str = "ssl.key.password";

/// A Kafka client's configuration (`Properties`), which the producer and the consumer are built from.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ClientProperties(Vec<(String, String)>);

impl ClientProperties {
    /// `put`: a key set again keeps its place and takes the new value.
    pub fn put(&mut self, key: &str, value: &str) {
        match self.0.iter_mut().find(|(k, _)| k == key) {
            Some(entry) => entry.1 = value.to_string(),
            None => self.0.push((key.to_string(), value.to_string())),
        }
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.0.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }

    pub fn contains_key(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The SASL client configuration: the mechanism and the JAAS login module's options. The login module must be
    /// one of Kafka's under the oracle image's relocated package (`shaded_package.org.apache.kafka…`); any other
    /// class, Kafka's own name included, fails to load and so fails construction.
    fn sasl(&self) -> Result<Option<Sasl>, Error> {
        let mechanism = self.get(SASL_MECHANISM).unwrap_or("GSSAPI").to_string();
        let Some(jaas) = self.get(SASL_JAAS_CONFIG) else {
            return Err(Error::new("Could not find a 'KafkaClient' entry in the JAAS configuration. System property 'java.security.auth.login.config' is not \
                set"));
        };
        let (module, options) = parse_jaas(jaas)?;
        // `JaasContext.throwIfLoginModuleIsNotAllowed` (kafka-clients 4.x: no `org.apache.kafka.allowed.login.modules`
        // set, so the deprecated deny-list's default applies), before any class loads; since 9.2.0 the image no
        // longer relocates `com.sun.*`, so that default matches (#109)
        let trimmed = module.trim();
        if DISALLOWED_LOGIN_MODULES.contains(&trimmed) {
            return Err(Error::new(format!(
                "{trimmed} is not allowed. The system property 'org.apache.kafka.disallowed.login.modules' is deprecated. Use the \
                 org.apache.kafka.allowed.login.modules to allow this module. e.g.,-Dorg.apache.kafka.allowed.login.modules={trimmed}"
            )));
        }
        // `KerberosLogin.configure` (the mechanism named exactly `GSSAPI`) needs `serviceName` before the login
        // module loads; `sasl.kerberos.service.name` is not among the settings `kafkaSecurity` carries. Kerberos
        // itself never runs: the oracle image's runtime has no `jdk.security.auth`, so `Krb5LoginModule` is not
        // found below, and no GSSAPI SaslClient provider (`jdk.security.jgss`) either.
        // Both fail inside `SaslChannelBuilder.configure`, which wraps what it catches (`new KafkaException(e)`).
        if mechanism == "GSSAPI" && !options.iter().any(|(n, _)| n == "serviceName") {
            return Err(Error::wrapping("java.lang.IllegalArgumentException", Error::new("No serviceName defined in either JAAS or Kafka config")));
        }
        if !LOGIN_MODULES.contains(&module.as_str()) {
            return Err(Error::wrapping("javax.security.auth.login.LoginException", Error::new(format!("No LoginModule found for {module}"))));
        }
        let option = |k: &str| options.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
        Ok(Some(match mechanism.to_ascii_uppercase().as_str() {
            "PLAIN" | "SCRAM-SHA-256" | "SCRAM-SHA-512" => match (option("username"), option("password")) {
                (Some(username), Some(password)) if mechanism.eq_ignore_ascii_case("PLAIN") => Sasl::Plain { mechanism, username, password },
                (Some(username), Some(password)) => Sasl::Scram { sha512: mechanism.eq_ignore_ascii_case("SCRAM-SHA-512"), mechanism, username, password },
                _ => Sasl::Unusable { mechanism },
            },
            "OAUTHBEARER" if module.ends_with("OAuthBearerLoginModule") => {
                let now = chrono::Utc::now().timestamp_millis() as f64 / 1000.0;
                let lifetime = option("unsecuredLoginLifetimeSeconds").and_then(|s| s.parse::<f64>().ok()).unwrap_or(3600.0);
                let mut claims = serde_json::Map::new();
                claims.insert("iat".into(), serde_json::json!(now));
                claims.insert("exp".into(), serde_json::json!(now + lifetime));
                for (k, v) in &options {
                    if let Some(claim) = k.strip_prefix("unsecuredLoginStringClaim_") {
                        claims.insert(claim.into(), Value::String(v.clone()));
                    }
                }
                claims.entry("sub").or_insert_with(|| Value::String(option("unsecuredLoginPrincipalClaimName").unwrap_or_default()));
                use base64::Engine;
                let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
                let token = format!("{}.{}.", b64.encode(r#"{"alg":"none"}"#), b64.encode(Value::Object(claims).to_string()));
                Sasl::OAuthBearer { token }
            }
            // No SASL client for it (`Failed to create SaslClient`): every connection attempt fails.
            _ => Sasl::Unusable { mechanism },
        }))
    }

    /// `ProducerConfig`'s own validation, which fails before (and outside) the producer's construction.
    fn validate(&self) -> Result<(), Error> {
        let bootstrap = self.get(BOOTSTRAP_SERVERS).unwrap_or_default();
        let entries: Vec<&str> = bootstrap.split(',').map(str::trim).collect();
        if bootstrap.trim().is_empty() {
            return Err(Error::new("Configuration 'bootstrap.servers' must not be empty. Valid values include: any non-empty value"));
        }
        if entries.iter().any(|e| e.is_empty()) {
            return Err(Error::new("Configuration 'bootstrap.servers' values must not be empty."));
        }
        if let Some(p) = self.get(SECURITY_PROTOCOL) && !["PLAINTEXT", "SSL", "SASL_PLAINTEXT", "SASL_SSL"].contains(&p.to_uppercase().as_str()) {
            return Err(Error::new(format!("Invalid value {p} for configuration security.protocol: String must be one of (case insensitive): SASL_SSL, \
                PLAINTEXT, SSL, SASL_PLAINTEXT")));
        }
        Ok(())
    }

    /// The client settings `new KafkaProducer(props)` would build, or why construction fails: the bootstrap
    /// addresses first, then the channel builder (`ClientUtils.createNetworkClient`, whose failures come wrapped in
    /// `Failed to create new NetworkClient`).
    async fn settings(&self, client_id: String) -> Result<Settings, Error> {
        let bootstrap = bootstrap_servers(self.get(BOOTSTRAP_SERVERS).unwrap_or_default())?;
        let (protocol, sasl, tls) = self.channel().await.map_err(|e| Error::caused("Failed to create new NetworkClient", e))?;
        Ok(Settings { bootstrap, protocol, sasl, tls, client_id, correlation: Default::default() })
    }

    /// `ChannelBuilders.clientChannelBuilder`: the security protocol, the SASL client (`SaslChannelBuilder`, which
    /// also builds the TLS context under `SASL_SSL` and wraps its failures as `new KafkaException(e)`) and the TLS
    /// context (`SslChannelBuilder`).
    async fn channel(&self) -> Result<(Protocol, Option<Sasl>, Option<Arc<rustls::ClientConfig>>), Error> {
        let protocol = match self.get(SECURITY_PROTOCOL).map(|p| p.to_uppercase()) {
            None => Protocol::Plaintext,
            Some(p) => match p.as_str() {
                "PLAINTEXT" => Protocol::Plaintext,
                "SSL" => Protocol::Ssl,
                "SASL_PLAINTEXT" => Protocol::SaslPlaintext,
                "SASL_SSL" => Protocol::SaslSsl,
                _ => unreachable!("checked by `validate`"),
            },
        };
        let sasl = if matches!(protocol, Protocol::SaslPlaintext | Protocol::SaslSsl) { self.sasl()? } else { None };
        let tls = if matches!(protocol, Protocol::Ssl | Protocol::SaslSsl) {
            let tls = self.tls().await;
            Some(if protocol == Protocol::SaslSsl { tls.map_err(|(class, e)| Error::wrapping(class, e))? } else { tls.map_err(|(_, e)| e)? })
        } else {
            None
        };
        Ok((protocol, sasl, tls))
    }

    /// `SslFactory.configure` over `DefaultSslEngineFactory`: the key store (`createKeystore`: a location and a
    /// password, or neither), the trust store (`createTruststore`: no password without a location), each loaded by
    /// `FileBasedStore.load` (which fails as `Failed to load SSL keystore <path> of type JKS`), then `createSSLContext`,
    /// whose `SunX509` key manager recovers every key with `ssl.key.password`, else the store password, and whose
    /// failures come as `new KafkaException(e)`. A failure comes with the class it is thrown as, for `SASL_SSL`'s
    /// wrapper.
    async fn tls(&self) -> Result<Arc<rustls::ClientConfig>, (&'static str, Error)> {
        let load = |path: &str, password: Option<&str>, key_password: Option<&str>| {
            let (path, password, key_password) = (path.to_string(), password.map(str::to_string), key_password.map(str::to_string));
            async move {
                let failed = |cause: Error| (KAFKA_EXCEPTION, Error::caused(format!("Failed to load SSL keystore {path} of type JKS"), cause));
                // `Files.newInputStream`: a missing file is a `NoSuchFileException` naming it.
                let data = match tokio::fs::read(&path).await {
                    Ok(data) => data,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(failed(Error::new(path.as_str()).with_field("file", path.as_str()))),
                    Err(e) => return Err(failed(Error::new(format!("{path}: {e}")))),
                };
                // `KeyStore.getInstance("JKS")` reads JKS and PKCS#12 (`keystore.type.compat`), not JCEKS.
                if !super::tls::StoreType::Dual.reads(&data) {
                    return Err(failed(Error::new("Invalid keystore format")));
                }
                super::tls::parse_keystore_with_key_password(&data, password.as_deref(), key_password.as_deref()).map_err(failed)
            }
        };
        // An `ApiException`: thrown without a stack trace.
        let invalid = |message: &str| (INVALID_CONFIGURATION_EXCEPTION, Error::new(message).stackless());
        let keystore = match (self.get(SSL_KEYSTORE_LOCATION), self.get(SSL_KEYSTORE_PASSWORD)) {
            (None, Some(_)) => return Err(invalid("SSL key store is not specified, but key store password is specified.")),
            (Some(_), None) => return Err(invalid("SSL key store is specified, but key store password is not specified.")),
            (Some(path), Some(password)) => Some(load(path, Some(password), Some(self.get(SSL_KEY_PASSWORD).unwrap_or(password))).await?),
            (None, None) => None,
        };
        let mut tls = super::tls::ClientTls::default();
        match (self.get(SSL_TRUSTSTORE_LOCATION), self.get(SSL_TRUSTSTORE_PASSWORD)) {
            (None, Some(_)) => return Err(invalid("SSL trust store is not specified, but trust store password is specified.")),
            // Without a password the store loads without its integrity check.
            (Some(path), password) => tls.trust = Some(load(path, password, password).await?.certificates),
            (None, None) => {}
        }
        if let Some(store) = keystore {
            if store.unrecoverable_keys > 0 {
                let cause = if store.pkcs12 {
                    let padding = "Given final block not properly padded. Such issues can arise if a bad key is used during decryption.";
                    Error::caused(format!("Get Key failed: {padding}"), Error::new(padding))
                } else {
                    Error::new("Cannot recover key")
                };
                return Err((KAFKA_EXCEPTION, Error::wrapping("java.security.UnrecoverableKeyException", cause)));
            }
            // `KeyManagerFactory.getDefaultAlgorithm()` (`ssl.keymanager.algorithm`, which `kafkaSecurity` does not
            // reach): `SunX509`, choosing a key in each handshake from what the broker's `CertificateRequest` names.
            tls.key_manager = Some(super::tls::KeyManager { kind: super::tls::KeyManagerKind::SunX509, entries: store.entries });
        }
        tls.config().map_err(|e| (KAFKA_EXCEPTION, e))
    }
}

/// `KafkaSecurityProperties.applySecurity`: each non-blank setting under its Kafka configuration key; nothing for no
/// or empty security.
pub fn apply_security(props: &mut ClientProperties, security: Option<&KafkaSecurity>) {
    let Some(security) = security.filter(|s| !s.is_empty()) else { return };
    let settings = [
        (SECURITY_PROTOCOL, &security.security_protocol),
        (SASL_MECHANISM, &security.sasl_mechanism),
        (SASL_JAAS_CONFIG, &security.sasl_jaas_config),
        (SSL_TRUSTSTORE_LOCATION, &security.ssl_truststore_location),
        (SSL_TRUSTSTORE_PASSWORD, &security.ssl_truststore_password),
        (SSL_KEYSTORE_LOCATION, &security.ssl_keystore_location),
        (SSL_KEYSTORE_PASSWORD, &security.ssl_keystore_password),
        (SSL_KEY_PASSWORD, &security.ssl_key_password),
    ];
    for (key, value) in settings {
        if let Some(value) = present(value) {
            props.put(key, value);
        }
    }
}

/// `KafkaMessagePublisher.buildProducerProperties`.
pub fn producer_properties(bootstrap: &str, security: Option<&KafkaSecurity>) -> ClientProperties {
    let mut props = ClientProperties::default();
    props.put(BOOTSTRAP_SERVERS, bootstrap);
    props.put("key.serializer", "org.apache.kafka.common.serialization.StringSerializer");
    props.put("value.serializer", "org.apache.kafka.common.serialization.StringSerializer");
    apply_security(&mut props, security);
    props
}

/// `KafkaMessageSubscriber.buildConsumerProperties` (`KafkaAvroMessageSubscriber`'s own takes the values as bytes).
pub fn consumer_properties(bootstrap: &str, group: &str, security: Option<&KafkaSecurity>) -> ClientProperties {
    let mut props = ClientProperties::default();
    props.put(BOOTSTRAP_SERVERS, bootstrap);
    props.put("group.id", group);
    props.put("key.deserializer", "org.apache.kafka.common.serialization.StringDeserializer");
    props.put("value.deserializer", "org.apache.kafka.common.serialization.StringDeserializer");
    props.put("auto.offset.reset", "earliest");
    props.put("enable.auto.commit", "true");
    apply_security(&mut props, security);
    props
}

/// `JaasContext.loadClientContext` over `new JaasConfig(…)`: the one login module of a `sasl.jaas.config`
/// (`<LoginModule class> <flag> key="value" …;`), its class and options, read with `java.io.StreamTokenizer` as
/// Kafka configures it.
fn parse_jaas(text: &str) -> Result<(String, Vec<(String, String)>), Error> {
    let mut tokens = JaasTokenizer { chars: text.chars().collect(), at: 0 };
    let mut entries = Vec::new();
    loop {
        let module = match tokens.next() {
            JaasToken::Eof => break,
            token => token.sval(),
        };
        let flag = tokens.next();
        if flag == JaasToken::Eof {
            return Err(Error::new("Login module control flag not specified in JAAS config"));
        }
        match flag.sval() {
            None => return Err(Error::new("Login module control flag is not available in the JAAS config")),
            Some(flag) if !matches!(flag.to_uppercase().as_str(), "REQUIRED" | "REQUISITE" | "SUFFICIENT" | "OPTIONAL") => {
                return Err(Error::new(format!("Invalid login module control flag '{flag}' in JAAS config")));
            }
            Some(_) => {}
        }
        let mut options = Vec::new();
        let mut last = tokens.next();
        while last != JaasToken::Eof && last != JaasToken::Ordinary(';') {
            let key = last.sval();
            let value = match tokens.next() {
                JaasToken::Ordinary('=') => tokens.next().sval(),
                _ => None,
            };
            let Some(value) = value else {
                return Err(Error::new(format!("Value not specified for key '{}' in JAAS config", key.as_deref().unwrap_or("null"))));
            };
            // a `HashMap`: a key given again takes the new value
            match options.iter_mut().find(|(k, _): &&mut (String, String)| Some(k) == key.as_ref()) {
                Some(entry) => entry.1 = value,
                None => options.push((key.unwrap_or_else(|| "null".into()), value)),
            }
            last = tokens.next();
        }
        if last != JaasToken::Ordinary(';') {
            return Err(Error::new("JAAS config entry not terminated by semi-colon"));
        }
        // `new AppConfigurationEntry(…)` refuses a missing or empty class name (`new IllegalArgumentException()`)
        match module {
            Some(module) if !module.is_empty() => entries.push((module, options)),
            _ => return Err(Error::without_message()),
        }
    }
    match entries.len() {
        0 => Err(Error::new("Login module not specified in JAAS config")),
        1 => Ok(entries.remove(0)),
        n => Err(Error::new(format!("JAAS config property contains {n} login modules, should be 1 module"))),
    }
}

/// A `StreamTokenizer` token: a word or a quoted string (both with an `sval`), a number or an ordinary character
/// (without one).
#[derive(Debug, PartialEq)]
enum JaasToken {
    Word(String),
    Quoted(String),
    Number,
    Ordinary(char),
    Eof,
}

impl JaasToken {
    fn sval(self) -> Option<String> {
        match self {
            JaasToken::Word(s) | JaasToken::Quoted(s) => Some(s),
            _ => None,
        }
    }
}

/// `java.io.StreamTokenizer` with its default syntax (word characters `a-zA-Z` and U+00A0–U+00FF and beyond,
/// whitespace up to the space, `/` a comment character, `"` and `'` quotes, numbers parsed), plus what
/// `JaasConfig` sets: `//` and `/* */` comments and `-`, `_`, `$` as word characters.
struct JaasTokenizer {
    chars: Vec<char>,
    at: usize,
}

impl JaasTokenizer {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.at).copied()
    }

    fn alpha(c: char) -> bool {
        c.is_ascii_alphabetic() || matches!(c, '-' | '_' | '$') || c as u32 >= 0xA0
    }

    fn digit(c: char) -> bool {
        c.is_ascii_digit() || matches!(c, '.' | '-')
    }

    fn skip_line(&mut self) {
        while let Some(c) = self.peek() {
            self.at += 1;
            if c == '\n' || c == '\r' {
                break;
            }
        }
    }

    fn next(&mut self) -> JaasToken {
        loop {
            while self.peek().is_some_and(|c| c as u32 <= 0x20) {
                self.at += 1;
            }
            let Some(c) = self.peek() else { return JaasToken::Eof };
            self.at += 1;
            if Self::digit(c) {
                let mut c = Some(c);
                if c == Some('-') {
                    if !self.peek().is_some_and(|n| n == '.' || n.is_ascii_digit()) {
                        return JaasToken::Ordinary('-');
                    }
                    c = self.peek();
                    self.at += 1;
                }
                let mut dot = false;
                while let Some(d) = c {
                    if d == '.' && !dot {
                        dot = true;
                    } else if !d.is_ascii_digit() {
                        break;
                    }
                    c = self.peek();
                    if c.is_some() {
                        self.at += 1;
                    }
                }
                if c.is_some() {
                    self.at -= 1;
                }
                return JaasToken::Number;
            }
            if Self::alpha(c) {
                let mut word = c.to_string();
                while let Some(n) = self.peek().filter(|&n| Self::alpha(n) || Self::digit(n) || n.is_ascii_digit()) {
                    word.push(n);
                    self.at += 1;
                }
                return JaasToken::Word(word);
            }
            if c == '"' || c == '\'' {
                return JaasToken::Quoted(self.quoted(c));
            }
            if c == '/' {
                match self.peek() {
                    Some('*') => {
                        self.at += 1;
                        loop {
                            match self.peek() {
                                None => return JaasToken::Eof,
                                Some('*') if self.chars.get(self.at + 1) == Some(&'/') => {
                                    self.at += 2;
                                    break;
                                }
                                Some(_) => self.at += 1,
                            }
                        }
                    }
                    // `//`, or `/` alone, the default comment character: to the end of the line
                    _ => self.skip_line(),
                }
                continue;
            }
            return JaasToken::Ordinary(c);
        }
    }

    /// A quoted string up to its closing quote, a line end or the end, with Java's escapes (`\n`, octal, …).
    fn quoted(&mut self, quote: char) -> String {
        let mut out = String::new();
        while let Some(c) = self.peek() {
            if c == quote || c == '\n' || c == '\r' {
                if c == quote {
                    self.at += 1;
                }
                break;
            }
            self.at += 1;
            if c != '\\' {
                out.push(c);
                continue;
            }
            let Some(e) = self.peek() else { break };
            self.at += 1;
            match e {
                '0'..='7' => {
                    let mut value = e as u32 - '0' as u32;
                    let longest = if e <= '3' { 2 } else { 1 };
                    for _ in 0..longest {
                        match self.peek() {
                            Some(d @ '0'..='7') => {
                                value = value * 8 + (d as u32 - '0' as u32);
                                self.at += 1;
                            }
                            _ => break,
                        }
                    }
                    out.extend(char::from_u32(value));
                }
                'a' => out.push('\u{7}'),
                'b' => out.push('\u{8}'),
                'f' => out.push('\u{c}'),
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                'v' => out.push('\u{b}'),
                other => out.push(other),
            }
        }
        out
    }
}

/// `ClientUtils.parseAndValidateAddresses` with `use_all_dns_ips`: `host:port` entries, at least one resolvable.
fn bootstrap_servers(list: &str) -> Result<Vec<(String, u16)>, Error> {
    let mut out = Vec::new();
    for url in list.split(',').map(str::trim).filter(|u| !u.is_empty()) {
        let parsed = url.rsplit_once(':').and_then(|(host, port)| {
            let host = host.trim_start_matches('[').trim_end_matches(']');
            let port = port.parse::<u32>().ok().filter(|_| port.chars().all(|c| c.is_ascii_digit()))?;
            (!host.is_empty()).then(|| (host.to_string(), port))
        });
        let Some((host, port)) = parsed else {
            return Err(Error::new(format!("Invalid url in bootstrap.servers: {url}")));
        };
        let Ok(port) = u16::try_from(port) else {
            return Err(Error::new(format!("Invalid port in bootstrap.servers: {url}")));
        };
        if crate::inet_address::lookup_blocking(&host, port).is_ok_and(|a| !a.is_empty()) {
            out.push((host, port));
        }
    }
    if out.is_empty() {
        return Err(Error::new("No resolvable bootstrap urls given in bootstrap.servers"));
    }
    Ok(out)
}

/// `KafkaException` as the oracle image relocates it.
const KAFKA_EXCEPTION: &str = "shaded_package.org.apache.kafka.common.KafkaException";
const INVALID_CONFIGURATION_EXCEPTION: &str = "shaded_package.org.apache.kafka.common.errors.InvalidConfigurationException";

/// Kafka's JAAS login modules as the oracle image relocates them. Their own names (`org.apache.kafka…`, as upstream's
/// tests and the unshaded mockserver-netty jar write them) are not on the image's class path: they fail to load
/// (scenario `asyncapi_kafka_unshaded_login_module`).
/// `JaasContext.DISALLOWED_LOGIN_MODULES_DEFAULT`.
const DISALLOWED_LOGIN_MODULES: &[&str] = &["com.sun.security.auth.module.JndiLoginModule", "com.sun.security.auth.module.LdapLoginModule"];

const LOGIN_MODULES: &[&str] = &[
    "shaded_package.org.apache.kafka.common.security.plain.PlainLoginModule",
    "shaded_package.org.apache.kafka.common.security.scram.ScramLoginModule",
    "shaded_package.org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule",
];

static PRODUCER_IDS: AtomicUsize = AtomicUsize::new(1);
static CONSUMER_IDS: AtomicUsize = AtomicUsize::new(1);

/// `KafkaAvroMessagePublisher`'s value side: the JSON payload as Avro binary in the Confluent wire format, framed
/// with the id the registry gives for `<topic>-value` (or the fixed id without a registry).
pub struct AvroWriter {
    schema: Arc<super::avro::Schema>,
    schema_json: String,
    registry: Option<Arc<super::registry::SchemaRegistryClient>>,
    fixed_id: i32,
}

impl AvroWriter {
    pub fn new(schema_json: Option<&str>, registry: Option<Arc<super::registry::SchemaRegistryClient>>, fixed_id: i32) -> Result<Self, Error> {
        let Some(schema_json) = schema_json.filter(|s| !s.trim().is_empty()) else {
            return Err(Error::illegal("an Avro schema is required to publish Avro messages"));
        };
        let schema = super::avro::parse_schema(schema_json)?;
        Ok(AvroWriter { schema, schema_json: schema_json.to_string(), registry, fixed_id })
    }

    /// `encode(channel, payload)`: the Confluent-framed Avro value.
    pub async fn encode(&self, channel: &str, payload: &str) -> Result<Vec<u8>, Error> {
        let failed = |m: String| Error::new(format!("Failed to Avro-encode payload for Kafka topic '{channel}': {m}"));
        let binary = super::avro::json_to_avro(&self.schema, payload).map_err(|e| failed(e.message))?;
        let id = match &self.registry {
            Some(registry) => registry.register(&format!("{channel}-value"), &self.schema_json).await.map_err(|e| failed(e.message))?,
            None => self.fixed_id,
        };
        Ok(super::avro::frame(id, &binary))
    }
}

/// `KafkaAvroMessageSubscriber.decodeToJson`: a framed value decoded with the registry's schema for its id (or the
/// inline schema when the id is the configured one); anything else recorded as the raw bytes' UTF-8.
pub struct AvroReader {
    registry: Option<Arc<super::registry::SchemaRegistryClient>>,
    inline: Option<Arc<super::avro::Schema>>,
    expected_id: i32,
    cache: Mutex<HashMap<i32, Arc<super::avro::Schema>>>,
}

impl AvroReader {
    pub fn new(registry: Option<Arc<super::registry::SchemaRegistryClient>>, inline_schema: Option<&str>, expected_id: i32) -> Result<Self, Error> {
        let inline = inline_schema.map(super::avro::parse_schema).transpose()?;
        Ok(AvroReader { registry, inline, expected_id, cache: Mutex::new(HashMap::new()) })
    }

    pub async fn decode(&self, value: &[u8]) -> String {
        let raw = || String::from_utf8_lossy(value).into_owned();
        let Ok((id, payload)) = super::avro::unframe(value) else { return raw() };
        let schema = match &self.registry {
            None if id == self.expected_id => self.inline.clone(),
            None => None,
            Some(registry) => {
                let cached = self.cache.lock().get(&id).cloned();
                match cached {
                    Some(s) => Some(s),
                    None => match registry.schema_by_id(id).await.ok().and_then(|json| super::avro::parse_schema(&json).ok()) {
                        Some(s) => {
                            self.cache.lock().insert(id, s.clone());
                            Some(s)
                        }
                        None => None,
                    },
                }
            }
        };
        match schema {
            Some(schema) => super::avro::avro_to_json(&schema, payload).unwrap_or_else(|_| raw()),
            None => raw(),
        }
    }
}

/// `ProducerRecord`: what one publish hands the producer.
#[derive(Clone, Debug, PartialEq)]
pub struct ProducerRecord {
    pub topic: String,
    pub key: Option<String>,
    pub value: Bytes,
    /// The options' headers as UTF-8, in order.
    pub headers: Vec<(String, Bytes)>,
}

/// The record `publish(channel, payload, options)` sends: the options' key and headers (Kafka has no use for their QoS
/// and retain flag) and the payload, Avro-encoded and framed when the publisher writes Avro.
pub async fn producer_record(avro: Option<&AvroWriter>, channel: &str, payload: &str, options: &PublishOptions) -> Result<ProducerRecord, Error> {
    let value = match avro {
        Some(avro) => Bytes::from(avro.encode(channel, payload).await?),
        None => Bytes::from(payload.as_bytes().to_vec()),
    };
    let headers = options.headers.iter().map(|(k, v)| (k.clone(), Bytes::from(v.clone().into_bytes()))).collect();
    Ok(ProducerRecord { topic: channel.to_string(), key: options.key.clone(), value, headers })
}

struct Pending {
    record: ProducerRecord,
    partition: i32,
    timestamp: i64,
    enqueued: Instant,
}

/// `batch.size`.
const BATCH_SIZE: usize = 16384;
/// `linger.ms` (5 since Kafka 4.0).
const LINGER: Duration = Duration::from_millis(5);
/// `DefaultRecordBatch.RECORD_BATCH_OVERHEAD`.
const BATCH_OVERHEAD: usize = 61;
/// `DefaultRecord.MAX_RECORD_OVERHEAD`.
const MAX_RECORD_OVERHEAD: usize = 21;

/// `ByteUtils.sizeOfVarint` (`sizeOfVarlong` for a long), of the zig-zag encoding.
fn varint_size(value: i64) -> usize {
    let mut v = ((value << 1) ^ (value >> 63)) as u64;
    let mut bytes = 1;
    while v >= 0x80 {
        v >>= 7;
        bytes += 1;
    }
    bytes
}

/// The key, value and headers part of `DefaultRecord.sizeInBytes` (`sizeOf(keySize, valueSize, headers)`).
fn fields_size(record: &ProducerRecord) -> usize {
    let bytes = |b: Option<&[u8]>| b.map_or(varint_size(-1), |b| varint_size(b.len() as i64) + b.len());
    let mut size = bytes(record.key.as_deref().map(str::as_bytes)) + bytes(Some(&record.value)) + varint_size(record.headers.len() as i64);
    for (k, v) in &record.headers {
        size += bytes(Some(k.as_bytes())) + bytes(Some(v));
    }
    size
}

/// `DefaultRecord.sizeInBytes(offsetDelta, timestampDelta, key, value, headers)`.
fn record_size(offset_delta: i32, timestamp_delta: i64, record: &ProducerRecord) -> usize {
    let body = 1 + varint_size(timestamp_delta) + varint_size(offset_delta as i64) + fields_size(record);
    varint_size(body as i64) + body
}

/// `ThreadLocalRandom.nextInt` made positive (`Utils.toPositive`).
fn random_int() -> u32 {
    use rand_core::RngCore;
    rand_core::OsRng.next_u32() & 0x7fffffff
}

/// A `ProducerBatch` still in its partition's deque: its `MemoryRecordsBuilder`'s size estimate.
struct OpenBatch {
    created: Instant,
    base_timestamp: i64,
    records: i32,
    bytes: usize,
    write_limit: usize,
}

impl OpenBatch {
    /// `MemoryRecordsBuilder.isFull`.
    fn full(&self) -> bool {
        self.records > 0 && self.write_limit <= self.bytes
    }
}

/// `BuiltInPartitioner.StickyPartitionInfo`.
struct Sticky {
    partition: i32,
    produced: usize,
}

/// What `RecordAccumulator.append` and the `BuiltInPartitioner` decide a record's partition from: each partition's
/// batch still open for appends (until it is full, or the sender drained it after `linger.ms` or a flush) and each
/// topic's sticky partition with the bytes produced to it. Records go out one per produce request regardless;
/// the batches are kept only for the partitioner's switching rule.
#[derive(Default)]
pub(crate) struct Accumulator {
    open: HashMap<(String, i32), OpenBatch>,
    sticky: HashMap<String, Sticky>,
}

impl Accumulator {
    /// The partition of `record`: the key's (`partitionForKey`), else the topic's sticky partition, which
    /// `updatePartitionInfo` moves on to a random available one once a full batch's worth (`batch.size`) went to it
    /// and the partition's last batch is full, or twice that whatever the batches.
    pub(crate) fn append(&mut self, record: &ProducerRecord, timestamp: i64, available: &[i32], partitions: usize, now: Instant, random: fn() -> u32) -> i32 {
        let next = |random: fn() -> u32| match available.len() {
            0 => (random() as usize % partitions.max(1)) as i32,
            n => available[random() as usize % n],
        };
        let keyed = record.key.as_ref().map(|k| wire::partition_for_key(k.as_bytes(), partitions));
        let partition = match keyed {
            Some(p) => p,
            None => self.sticky.entry(record.topic.clone()).or_insert_with(|| Sticky { partition: next(random), produced: 0 }).partition,
        };
        let key = (record.topic.clone(), partition);
        self.open.retain(|_, b| now.duration_since(b.created) < LINGER && !b.full());
        let appended = match self.open.get_mut(&key) {
            Some(batch) if batch.bytes + record_size(batch.records, timestamp - batch.base_timestamp, record) <= batch.write_limit => {
                let size = record_size(batch.records, timestamp - batch.base_timestamp, record);
                batch.bytes += size;
                batch.records += 1;
                size
            }
            _ => {
                // `ProducerBatch` on a buffer of `max(batch.size, estimateSizeInBytesUpperBound)`.
                let write_limit = BATCH_SIZE.max(BATCH_OVERHEAD + MAX_RECORD_OVERHEAD + fields_size(record));
                let bytes = BATCH_OVERHEAD + record_size(0, 0, record);
                self.open.insert(key.clone(), OpenBatch { created: now, base_timestamp: timestamp, records: 1, bytes, write_limit });
                bytes
            }
        };
        if keyed.is_none() {
            let enable_switch = self.open.get(&key).is_none_or(OpenBatch::full);
            if let Some(sticky) = self.sticky.get_mut(&record.topic) {
                sticky.produced += appended;
                if (sticky.produced >= BATCH_SIZE && enable_switch) || sticky.produced >= BATCH_SIZE * 2 {
                    *sticky = Sticky { partition: next(random), produced: 0 };
                }
            }
        }
        partition
    }

    /// `flush`: every batch is sent.
    pub(crate) fn drained(&mut self) {
        self.open.clear();
    }
}

/// `DeliveryFailure`: the first failed send since the last flush.
struct Failure {
    channel: String,
    cause: Error,
}

/// What `flush` waits for and reports: the sends in flight, and the first one that failed since the last flush (the
/// send callback's `DeliveryFailure`).
#[derive(Default)]
pub struct Deliveries {
    in_flight: AtomicUsize,
    done: tokio::sync::Notify,
    failure: Mutex<Option<Failure>>,
}

impl Deliveries {
    /// A record went to the sender.
    pub fn started(&self) {
        self.in_flight.fetch_add(1, Ordering::SeqCst);
    }

    /// The send callback of a record that went to the sender.
    pub fn completed(&self, channel: &str, outcome: Result<(), Error>) {
        if let Err(cause) = outcome {
            self.failed(channel, cause);
        }
        self.in_flight.fetch_sub(1, Ordering::SeqCst);
        self.done.notify_waiters();
    }

    /// The send callback with an exception: kept unless an earlier failure still waits to be reported.
    pub fn failed(&self, channel: &str, cause: Error) {
        let mut failure = self.failure.lock();
        if failure.is_none() {
            *failure = Some(Failure { channel: channel.to_string(), cause });
        }
    }

    /// Waits until no send is in flight; with a limit, each wait for the next completion is bounded by it.
    async fn drain(&self, limit: Option<Duration>) {
        loop {
            let notified = self.done.notified();
            if self.in_flight.load(Ordering::SeqCst) == 0 {
                return;
            }
            match limit {
                None => notified.await,
                Some(limit) => {
                    if tokio::time::timeout(limit, notified).await.is_err() {
                        return;
                    }
                }
            }
        }
    }

    /// `flush`: waits for every send in flight, then reports the first failure once (`Failed to deliver
    /// <description> to Kafka topic '<channel>': <cause>`).
    pub async fn flush(&self, description: &str) -> Result<(), Error> {
        self.drain(None).await;
        match self.failure.lock().take() {
            Some(f) => Err(Error::caused(format!("Failed to deliver {description} to Kafka topic '{}': {}", f.channel, f.cause.message), f.cause)),
            None => Ok(()),
        }
    }
}

/// `KafkaProducer.throwIfProducerClosed`'s message.
const PRODUCER_CLOSED: &str = "Cannot perform operation after producer has been closed";

/// `KafkaMessagePublisher` (JSON values) or, with a value encoder, `KafkaAvroMessagePublisher`.
pub struct KafkaPublisher {
    cluster: Arc<Cluster>,
    avro: Option<Arc<AvroWriter>>,
    queue: tokio::sync::mpsc::UnboundedSender<Pending>,
    accumulator: Mutex<Accumulator>,
    deliveries: Arc<Deliveries>,
    closed: AtomicBool,
    sender: Mutex<Option<tokio::task::JoinHandle<()>>>,
    bootstrap: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl KafkaPublisher {
    /// `new KafkaMessagePublisher(bootstrapServers, security)`.
    pub async fn new(bootstrap: &str, security: Option<&KafkaSecurity>, avro: Option<AvroWriter>) -> Result<Self, Error> {
        let props = producer_properties(bootstrap, security);
        props.validate()?;
        let client_id = format!("producer-{}", PRODUCER_IDS.fetch_add(1, Ordering::SeqCst));
        let settings = props.settings(client_id).await.map_err(|e| Error::caused("Failed to construct kafka producer", e))?;
        let cluster = Arc::new(Cluster::new(settings));
        let (queue, receiver) = tokio::sync::mpsc::unbounded_channel();
        let deliveries = Arc::new(Deliveries::default());
        let producer = Producer::default();
        let sender = super::broker::spawn(send_loop(cluster.clone(), receiver, deliveries.clone(), producer.clone()));
        let bootstrap = super::broker::spawn(bootstrap_metadata(cluster.clone(), producer));
        Ok(KafkaPublisher {
            cluster,
            avro: avro.map(Arc::new),
            queue,
            accumulator: Mutex::default(),
            deliveries,
            closed: AtomicBool::new(false),
            sender: Mutex::new(Some(sender)),
            bootstrap: Mutex::new(Some(bootstrap)),
        })
    }

    fn description(&self) -> &'static str {
        if self.avro.is_some() { "Avro message" } else { "message" }
    }

    /// `publish(channel, payload, options)`: the record goes to the sender; a failure to deliver it is reported by
    /// the next `flush`. A closed producer refuses the record at once.
    async fn publish_record(&self, channel: &str, payload: &str, options: &PublishOptions) -> Result<(), Error> {
        let record = producer_record(self.avro.as_deref(), channel, payload, options).await?;
        if self.closed.load(Ordering::SeqCst) {
            return Err(Error::new(PRODUCER_CLOSED));
        }
        self.send(record).await;
        Ok(())
    }

    /// `KafkaProducer.send`: waits for the topic's partitions (`max.block.ms`), picks the partition (the key's, else
    /// the sticky one), queues.
    async fn send(&self, record: ProducerRecord) {
        let partitions = match self.await_partitions(&record.topic).await {
            Ok(p) => p,
            Err(e) => return self.deliveries.failed(&record.topic, e),
        };
        let available: Vec<i32> = self
            .cluster
            .partitions(&record.topic)
            .map(|(_, p)| p.iter().filter(|m| m.leader >= 0).map(|m| m.partition).collect())
            .unwrap_or_default();
        let timestamp = chrono::Utc::now().timestamp_millis();
        let partition = self.accumulator.lock().append(&record, timestamp, &available, partitions, Instant::now(), random_int);
        self.deliveries.started();
        let topic = record.topic.clone();
        let pending = Pending { record, partition, timestamp, enqueued: Instant::now() };
        if self.queue.send(pending).is_err() {
            self.deliveries.completed(&topic, Err(Error::new(PRODUCER_CLOSED)));
        }
    }

    /// `waitOnMetadata`: the topic's partition count once every partition has a leader.
    async fn await_partitions(&self, topic: &str) -> Result<usize, Error> {
        let deadline = Instant::now() + MAX_BLOCK;
        let mut backoff = RETRY_BACKOFF;
        loop {
            let refreshed = self.cluster.refresh(&[topic.to_string()]).await;
            if let Some(fatal) = self.cluster.fatal() {
                return Err(fatal);
            }
            if refreshed.is_ok() {
                match self.cluster.partitions(topic) {
                    Some((0, partitions)) if !partitions.is_empty() => return Ok(partitions.len()),
                    Some((17, _)) => return Err(Error::new(format!("Invalid topics: [{topic}]"))),
                    Some((29, _)) => return Err(Error::new(format!("Not authorized to access topics: [{topic}]"))),
                    _ => {}
                }
            }
            if Instant::now() + backoff >= deadline {
                tokio::time::sleep_until(deadline.into()).await;
                return Err(Error::new(format!("Topic {topic} not present in metadata after {} ms.", MAX_BLOCK.as_millis())));
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(RETRY_BACKOFF_MAX);
        }
    }

    /// `flush`: waits for every queued send, then reports the first failure (`Failed to deliver …`).
    async fn flush_sends(&self) -> Result<(), Error> {
        self.accumulator.lock().drained();
        self.deliveries.flush(self.description()).await
    }

    /// `close`: waits for the queued sends to finish (each bounded by `delivery.timeout.ms`); later publishes are
    /// refused.
    async fn close_producer(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.deliveries.drain(Some(DELIVERY_TIMEOUT)).await;
        if let Some(task) = self.sender.lock().take() {
            task.abort();
        }
        if let Some(task) = self.bootstrap.lock().take() {
            task.abort();
        }
        self.cluster.forget_connections();
    }

}

impl super::broker::Publisher for KafkaPublisher {
    fn publish<'a>(&'a self, channel: &'a str, payload: &'a str, options: &'a PublishOptions) -> BoxFuture<'a, Result<(), Error>> {
        Box::pin(self.publish_record(channel, payload, options))
    }

    fn flush(&self) -> BoxFuture<'_, Result<(), Error>> {
        Box::pin(self.flush_sends())
    }

    fn close(&self) -> BoxFuture<'_, ()> {
        Box::pin(self.close_producer())
    }
}

/// The sender's first metadata fetch: `KafkaProducer` bootstraps a `Metadata` that needs a full update, so its
/// `Sender` dials a bootstrap server at construction (ApiVersions, then Metadata for the topics it knows, none yet)
/// instead of waiting for a first record, retrying with `reconnect.backoff.ms` until it is answered or a failure is
/// fatal (authentication, TLS: kept for the next send).
async fn bootstrap_metadata(cluster: Arc<Cluster>, producer: Producer) {
    let mut backoff = RECONNECT_BACKOFF;
    while cluster.fatal().is_none() && cluster.refresh(&[]).await.is_err() {
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(RECONNECT_BACKOFF_MAX);
    }
    // The idempotent `Sender` asks for its producer id as soon as it has metadata (`bumpIdempotentEpochAndResetIdIfNeeded`),
    // not at the first record.
    let mut backoff = RETRY_BACKOFF;
    while cluster.fatal().is_none() && !init_producer(&cluster, &producer).await {
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(RETRY_BACKOFF_MAX);
    }
}

/// The idempotent producer's id and epoch, once known (`InitProducerId`); `(-1, -1)` after a refusal that is not retried.
type Producer = Arc<tokio::sync::Mutex<Option<(i64, i16)>>>;

/// Asks for the producer id unless it is known; false when the request failed in a way the sender retries.
async fn init_producer(cluster: &Cluster, producer: &Producer) -> bool {
    let mut state = producer.lock().await;
    if state.is_some() {
        return true;
    }
    let request = InitProducerIdRequest::default().with_transaction_timeout_ms(60000).with_producer_id((-1).into()).with_producer_epoch(-1);
    match cluster.send_any(request).await {
        Ok((_, r)) if r.error_code == 0 => *state = Some((r.producer_id.0, r.producer_epoch)),
        Ok((_, r)) if !wire::retriable(r.error_code) => *state = Some((-1, -1)),
        Ok(_) | Err(_) => return false,
    }
    true
}

/// The sender: produces queued records in order, idempotently, retrying retriable errors until
/// `delivery.timeout.ms`.
async fn send_loop(
    cluster: Arc<Cluster>,
    mut receiver: tokio::sync::mpsc::UnboundedReceiver<Pending>,
    deliveries: Arc<Deliveries>,
    producer: Producer,
) {
    let mut sequences: HashMap<(String, i32), i32> = HashMap::new();
    while let Some(pending) = receiver.recv().await {
        let outcome = produce(&cluster, &producer, &mut sequences, &pending).await;
        deliveries.completed(&pending.record.topic, outcome);
    }
}

async fn produce(cluster: &Cluster, producer: &Producer, sequences: &mut HashMap<(String, i32), i32>, pending: &Pending) -> Result<(), Error> {
    let (record, partition, deadline) = (&pending.record, pending.partition, pending.enqueued + DELIVERY_TIMEOUT);
    let mut backoff = RETRY_BACKOFF;
    let expired = format!("Expiring 1 record(s) for {}-{partition}:{} ms has passed since batch creation", record.topic, DELIVERY_TIMEOUT.as_millis());
    let mut last = Error::new(expired);
    while Instant::now() < deadline {
        if let Some(fatal) = cluster.fatal() {
            return Err(fatal);
        }
        if !init_producer(cluster, producer).await {
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(RETRY_BACKOFF_MAX);
            continue;
        }
        let Some(leader) = cluster
            .partitions(&record.topic)
            .and_then(|(_, p)| p.iter().find(|m| m.partition == partition).map(|m| m.leader))
            .filter(|l| *l >= 0) else {
            let _ = cluster.refresh(std::slice::from_ref(&record.topic)).await;
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(RETRY_BACKOFF_MAX);
            continue;
        };
        let (producer_id, producer_epoch) = (*producer.lock().await).unwrap_or((-1, -1));
        let key = (record.topic.clone(), partition);
        let sequence = if producer_id >= 0 { *sequences.get(&key).unwrap_or(&0) } else { -1 };
        let batch = Record {
            transactional: false,
            control: false,
            delete_horizon: false,
            partition_leader_epoch: -1,
            producer_id,
            producer_epoch,
            timestamp_type: TimestampType::Creation,
            offset: 0,
            sequence,
            timestamp: pending.timestamp,
            key: record.key.as_ref().map(|k| Bytes::from(k.clone().into_bytes())),
            value: Some(record.value.clone()),
            headers: record.headers.iter().map(|(k, v)| (StrBytes::from_string(k.clone()), Some(v.clone()))).collect(),
        };
        let mut encoded = bytes::BytesMut::new();
        RecordBatchEncoder::encode(
            &mut encoded,
            [&batch],
            &RecordEncodeOptions { version: 2, compression: Compression::None },
        ).map_err(|e| Error::new(e.to_string()))?;
        let topic = record.topic.clone();
        let id = cluster.topic_id(&topic);
        let encoded = encoded.freeze();
        let build = |v: i16| {
            let data = TopicProduceData::default()
                .with_partition_data(vec![PartitionProduceData::default().with_index(partition).with_records(Some(encoded.clone()))]);
            // v13+ names the topic by its id.
            let data = if v >= 13 { data.with_topic_id(id) } else { data.with_name(TopicName(StrBytes::from_string(topic.clone()))) };
            ProduceRequest::default().with_acks(-1).with_timeout_ms(30000).with_topic_data(vec![data])
        };
        match cluster.send_with(leader, &build).await {
            Ok(response) => {
                let result = response.responses.first().and_then(|t| t.partition_responses.first());
                match result.map(|p| (p.error_code, p.error_message.as_ref().map(|m| m.to_string()))) {
                    Some((0, _)) | Some((46, _)) => {
                        if producer_id >= 0 {
                            sequences.insert(key, sequence.wrapping_add(1));
                        }
                        return Ok(());
                    }
                    Some((code, message)) if wire::retriable(code) => {
                        last = Error::new(message.unwrap_or_else(|| wire::error_message(code)));
                        let _ = cluster.refresh(std::slice::from_ref(&record.topic)).await;
                    }
                    Some((code, message)) => return Err(Error::new(message.unwrap_or_else(|| wire::error_message(code)))),
                    None => last = Error::new("empty produce response"),
                }
            }
            Err(e) => {
                if e.has_kind(ErrorKind::Authentication) {
                    return Err(e);
                }
                last = e;
                let _ = cluster.refresh(std::slice::from_ref(&record.topic)).await;
            }
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(RETRY_BACKOFF_MAX);
    }
    Err(last)
}

/// A record as `KafkaConsumer.poll` hands it over (`ConsumerRecord`): its topic, and its key, value and headers
/// as bytes.
#[derive(Clone, Debug, Default)]
pub struct ConsumerRecord {
    pub topic: String,
    pub key: Option<Bytes>,
    pub value: Option<Bytes>,
    pub headers: Vec<(String, Option<Bytes>)>,
}

/// What the poll loop does with each record: the consumed messages per topic, and the count.
pub(crate) struct Recording {
    recorder: Arc<ConsumedMessages>,
    counters: Counters,
    decoder: Option<Arc<AvroReader>>,
}

impl Recording {
    /// The record as a consumed message: key and value as UTF-8 (the value decoded, with a decoder), headers as
    /// UTF-8 or null.
    pub(crate) async fn record(&self, record: ConsumerRecord) {
        let utf8 = |b: &Bytes| String::from_utf8_lossy(b).into_owned();
        let payload = match (&record.value, &self.decoder) {
            (Some(v), Some(d)) => Some(d.decode(v).await),
            (Some(v), None) => Some(utf8(v)),
            (None, _) => None,
        };
        let headers = record.headers.iter().map(|(k, v)| (k.clone(), v.as_ref().map(utf8))).collect();
        self.recorder.record(ConsumedMessage::new(&record.topic, record.key.as_ref().map(utf8), payload, headers));
        self.counters.consumed(&record.topic);
    }
}

/// `KafkaMessageSubscriber` (UTF-8 values) or, with a value decoder, `KafkaAvroMessageSubscriber`.
pub struct KafkaSubscriber {
    cluster: Arc<Cluster>,
    group: String,
    topics: Arc<Mutex<Vec<String>>>,
    changed: Arc<tokio::sync::Notify>,
    recording: Arc<Recording>,
    running: Arc<AtomicBool>,
    failed: Arc<AtomicBool>,
    stop: tokio::sync::watch::Sender<bool>,
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

/// The Avro side of a subscriber: the schema registry (if any), the inline schema and its id.
type AvroSubscription<'a> = (Option<Arc<super::registry::SchemaRegistryClient>>, Option<&'a str>, i32);

impl KafkaSubscriber {
    /// `new KafkaMessageSubscriber(bootstrapServers, groupId, maxRecordedMessages, security)`.
    /// With `avro` (a registry, the inline schema and its id), `KafkaAvroMessageSubscriber`: the consumer is built
    /// first, then the inline schema parsed.
    pub async fn new(
        bootstrap: &str,
        group: &str,
        max_recorded: i64,
        security: Option<&KafkaSecurity>,
        avro: Option<AvroSubscription<'_>>,
        counters: Counters,
    ) -> Result<Self, Error> {
        let mut props = consumer_properties(bootstrap, group, security);
        if avro.is_some() {
            props.put("value.deserializer", "org.apache.kafka.common.serialization.ByteArrayDeserializer");
        }
        props.validate()?;
        let client_id = format!("consumer-{group}-{}", CONSUMER_IDS.fetch_add(1, Ordering::SeqCst));
        let settings = props.settings(client_id).await.map_err(|e| Error::caused("Failed to construct kafka consumer", e))?;
        let decoder = match avro {
            Some((registry, inline, id)) => Some(Arc::new(AvroReader::new(registry, inline, id)?)),
            None => None,
        };
        Ok(KafkaSubscriber {
            cluster: Arc::new(Cluster::new(settings)),
            group: group.to_string(),
            topics: Arc::new(Mutex::new(Vec::new())),
            changed: Arc::new(tokio::sync::Notify::new()),
            recording: Arc::new(Recording { recorder: Arc::new(ConsumedMessages::new(max_recorded)), counters, decoder }),
            running: Arc::new(AtomicBool::new(false)),
            failed: Arc::new(AtomicBool::new(false)),
            stop: tokio::sync::watch::channel(false).0,
            task: Mutex::new(None),
        })
    }

    /// `subscribe(channel)`: the topic joins the subscription (a rebalance) and the poll loop starts.
    fn join(&self, channel: &str) -> Result<(), Error> {
        self.recording.recorder.ensure(channel).map_err(Error::new)?;
        {
            let mut topics = self.topics.lock();
            if !topics.iter().any(|t| t == channel) {
                topics.push(channel.to_string());
            }
        }
        self.changed.notify_one();
        if !self.running.swap(true, Ordering::SeqCst) {
            let poll = group::PollLoop {
                cluster: self.cluster.clone(),
                group: self.group.clone(),
                topics: self.topics.clone(),
                changed: self.changed.clone(),
                recording: self.recording.clone(),
                failed: self.failed.clone(),
                stop: self.stop.subscribe(),
            };
            *self.task.lock() = Some(super::broker::spawn(poll.run()));
        }
        Ok(())
    }

    pub fn is_healthy(&self) -> bool {
        !self.failed.load(Ordering::SeqCst)
    }

    /// The topics the poll loop keeps the consumer subscribed to, in the order they were subscribed.
    pub fn subscription(&self) -> Vec<String> {
        self.topics.lock().clone()
    }

    /// Records a polled record as the poll loop does.
    pub async fn record(&self, record: ConsumerRecord) {
        self.recording.record(record).await;
    }
}

impl super::broker::Subscriber for KafkaSubscriber {
    fn subscribe<'a>(&'a self, channel: &'a str) -> BoxFuture<'a, Result<(), Error>> {
        Box::pin(async move { self.join(channel) })
    }

    fn recorded(&self, channel: &str) -> Vec<ConsumedMessage> {
        self.recording.recorder.exact(channel)
    }

    fn all_recorded(&self) -> Vec<ConsumedMessage> {
        self.recording.recorder.all()
    }

    /// `close`: stops the poll loop, which commits and leaves the group (up to 5 s).
    fn close(&self) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            let _ = self.stop.send(true);
            self.changed.notify_one();
            let task = self.task.lock().take();
            super::broker::join_or_abort(task, Duration::from_secs(5)).await;
            self.running.store(false, Ordering::SeqCst);
            self.recording.recorder.clear();
            self.topics.lock().clear();
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    thread_local! {
        static NEXT: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
    }

    /// A "random" int counting up from 0 on each test's thread.
    fn counting() -> u32 {
        NEXT.with(|n| n.replace(n.get() + 1))
    }

    /// The partitions keyless 1000-byte records go to, appended `spacing` apart, with `random` returning 0, 1, 2, …
    fn sticky_partitions(count: usize, spacing: Duration) -> Vec<i32> {
        let record = ProducerRecord { topic: "t".into(), key: None, value: Bytes::from(vec![b'x'; 1000]), headers: Vec::new() };
        let mut accumulator = Accumulator::default();
        let start = Instant::now();
        (0..count).map(|i| accumulator.append(&record, 1, &[0, 1, 2], 3, start + spacing * i as u32, counting)).collect()
    }

    /// `BuiltInPartitioner.updatePartitionInfo`: a record of 1009 bytes (`DefaultRecord.sizeInBytes`) leaves 16 to a
    /// batch (61 + 16 × 1009 = 16205, never `isFull`), so switching waits for twice `batch.size`: the 33rd record
    /// opens a third batch and brings the produced bytes to 33480.
    #[test]
    fn keyless_records_stick_to_a_partition_until_twice_the_batch_size_without_a_full_batch() {
        let partitions = sticky_partitions(40, Duration::ZERO);
        assert_eq!(partitions[..33], [0; 33]);
        assert_eq!(partitions[33..], [1; 7]);
    }

    /// Records `linger.ms` apart each open a batch of their own (61 + 1009 bytes): 31 of them make 33170 bytes.
    #[test]
    fn keyless_records_each_in_a_drained_batch_switch_after_twice_the_batch_size() {
        let partitions = sticky_partitions(33, LINGER);
        assert_eq!(partitions[..31], [0; 31]);
        assert_eq!(partitions[31..], [1; 2]);
    }

    /// A record filling its batch (`isFull`) once a batch's worth was produced switches at once.
    #[test]
    fn a_full_batch_switches_after_one_batch_size() {
        let mut accumulator = Accumulator::default();
        let now = Instant::now();
        // Three records of 5441 bytes fill a batch exactly (61 + 3 × 5441 = 16384).
        let record = ProducerRecord { topic: "t".into(), key: None, value: Bytes::from(vec![b'x'; 5432]), headers: Vec::new() };
        assert_eq!(record_size(0, 0, &record), 5441);
        let partitions: Vec<i32> = (0..4).map(|_| accumulator.append(&record, 1, &[0, 1], 2, now, counting)).collect();
        assert_eq!(partitions, [0, 0, 0, 1]);
        let keyed = ProducerRecord { key: Some("k".into()), ..record };
        assert_eq!(accumulator.append(&keyed, 1, &[0, 1], 2, now, counting), wire::partition_for_key(b"k", 2));
    }

    fn messages(e: Error) -> Vec<String> {
        e.chain().map(|e| e.message.clone()).collect()
    }

    /// `JaasConfig` over `StreamTokenizer`: the messages the oracle logs (scenario
    /// `asyncapi_kafka_construction_chain`).
    #[test]
    fn jaas_errors_are_kafkas() {
        let error = |jaas: &str| parse_jaas(jaas).unwrap_err().message;
        let plain = "org.apache.kafka.common.security.plain.PlainLoginModule";
        assert_eq!(error("garbage"), "Login module control flag not specified in JAAS config");
        assert_eq!(error(";"), "Login module control flag not specified in JAAS config");
        assert_eq!(error(&format!("{plain} bogus;")), "Invalid login module control flag 'bogus' in JAAS config");
        assert_eq!(error(&format!("{plain} required username=\"a\"")), "JAAS config entry not terminated by semi-colon");
        assert_eq!(error(&format!("{plain} required username=;")), "Value not specified for key 'username' in JAAS config");
        assert_eq!(error(&format!("{plain} required username=\"a\" b")), "Value not specified for key 'b' in JAAS config");
        assert_eq!(error(&format!("{plain} required username=1;")), "Value not specified for key 'username' in JAAS config");
        let one = format!("{plain} required username=\"a\" password=\"b\";");
        assert_eq!(error(&format!("{one} {one}")), "JAAS config property contains 2 login modules, should be 1 module");
        assert_eq!(error("// nothing"), "Login module not specified in JAAS config");
        assert_eq!(error("x 1;"), "Login module control flag is not available in the JAAS config");
        assert!(parse_jaas("; required;").unwrap_err().no_message);
        assert!(parse_jaas("'' required;").unwrap_err().no_message);
        assert_eq!(parse_jaas(&format!("/* c */ {plain} REQUIRED username=a password='b\\tc' // tail\n;")).unwrap().1, [
            ("username".to_string(), "a".to_string()),
            ("password".to_string(), "b\tc".to_string()),
        ]);
    }

    #[test]
    fn jaas_entries_are_parsed() {
        let jaas = r#"org.apache.kafka.common.security.plain.PlainLoginModule required username="alice" password="alice-secret";"#;
        let (module, options) = parse_jaas(jaas).unwrap();
        assert_eq!(module, "org.apache.kafka.common.security.plain.PlainLoginModule");
        assert_eq!(options, [("username".to_string(), "alice".to_string()), ("password".to_string(), "alice-secret".to_string())]);
        assert!(parse_jaas("org.x.Module required username=\"a\"").is_err());
    }

    #[test]
    fn bootstrap_lists_are_validated() {
        assert_eq!(bootstrap_servers("localhost:9092, 127.0.0.1:1").unwrap().len(), 2);
        assert_eq!(bootstrap_servers("localhost").unwrap_err().message, "Invalid url in bootstrap.servers: localhost");
        assert_eq!(bootstrap_servers("nohost.invalid:9092").unwrap_err().message, "No resolvable bootstrap urls given in bootstrap.servers");
        assert_eq!(bootstrap_servers("localhost:99999").unwrap_err().message, "Invalid port in bootstrap.servers: localhost:99999");
        assert_eq!(
            producer_properties("", None).validate().unwrap_err().message,
            "Configuration 'bootstrap.servers' must not be empty. Valid values include: any non-empty value",
        );
        assert_eq!(producer_properties("localhost:1,", None).validate().unwrap_err().message, "Configuration 'bootstrap.servers' values must not be empty.");
    }

    #[test]
    fn login_modules_load_only_by_their_relocated_names() {
        let with = |module: &str| KafkaSecurity {
            sasl_mechanism: Some("PLAIN".into()),
            sasl_jaas_config: Some(format!(r#"{module} required username="alice" password="secret";"#)),
            ..Default::default()
        };
        let relocated = "shaded_package.org.apache.kafka.common.security.plain.PlainLoginModule";
        assert!(matches!(producer_properties("localhost:1", Some(&with(relocated))).sasl(), Ok(Some(Sasl::Plain { .. }))));
        for module in ["org.apache.kafka.common.security.plain.PlainLoginModule", "org.example.PlainLoginModule"] {
            assert_eq!(
                messages(producer_properties("localhost:1", Some(&with(module))).sasl().unwrap_err()),
                [format!("javax.security.auth.login.LoginException: No LoginModule found for {module}"), format!("No LoginModule found for {module}")],
            );
        }
    }

    /// `KerberosLogin.configure` asks for the service name before the login module loads, for the mechanism named
    /// exactly `GSSAPI` (the default). The oracle image's runtime has no `jdk.security.auth`, so `Krb5LoginModule`
    /// never loads (scenario `asyncapi_kafka_gssapi`).
    #[test]
    fn gssapi_needs_a_service_name_before_its_login_module_loads() {
        let sasl = |mechanism: Option<&str>, jaas: &str| {
            let security = KafkaSecurity { sasl_mechanism: mechanism.map(str::to_string), sasl_jaas_config: Some(jaas.into()), ..Default::default() };
            producer_properties("localhost:1", Some(&security)).sasl()
        };
        let (krb5, plain) = ("com.sun.security.auth.module.Krb5LoginModule", "shaded_package.org.apache.kafka.common.security.plain.PlainLoginModule");
        let no_service = "No serviceName defined in either JAAS or Kafka config";
        for (mechanism, jaas) in [(Some("GSSAPI"), format!("{krb5} required;")), (None, format!(r#"{plain} required username="a" password="b";"#))] {
            assert_eq!(messages(sasl(mechanism, &jaas).unwrap_err()), [format!("java.lang.IllegalArgumentException: {no_service}"), no_service.into()], "{jaas}");
        }
        let no_module = format!("No LoginModule found for {krb5}");
        for service in ["kafka", ""] {
            assert_eq!(messages(sasl(Some("GSSAPI"), &format!(r#"{krb5} required serviceName="{service}";"#)).unwrap_err())[1], no_module);
        }
        let with_service = format!(r#"{plain} required username="a" password="b" serviceName="kafka";"#);
        assert!(matches!(sasl(Some("GSSAPI"), &with_service), Ok(Some(Sasl::Unusable { .. }))));
        let lower = format!(r#"{plain} required username="a" password="b";"#);
        assert!(matches!(sasl(Some("gssapi"), &lower), Ok(Some(Sasl::Unusable { .. }))));
    }
}
