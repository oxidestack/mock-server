//! The AsyncAPI control plane (`mockserver-async`'s `AsyncApiControlPlaneImpl`): `PUT /mockserver/asyncapi` loads
//! a spec (AsyncAPI 2.x or 3.x, JSON or YAML, bare or as `{spec, brokerConfig}`), `GET` reports it, `PUT
//! /mockserver/asyncapi/verify` checks the messages consumed on a channel, and `PUT /mockserver/asyncapi/http` turns
//! each channel into a `GET` expectation answering its example payload. Each server has its own ([`AsyncApi`]),
//! cleared by a reset and closed when the server stops.
//!
//! A `brokerConfig` (or the `asyncMqttBrokerUrl`, `asyncAmqpUri`, `asyncKafkaBootstrapServers` defaults, which only
//! a wrapped body consults) connects the spec to brokers: per broker one publisher with its orchestrator, which
//! publishes every channel's examples on load (`publishOnLoad`) and every `publishIntervalMillis`, and with
//! `consume` one subscriber per broker keeping what arrives on each channel. `status` lists these consumed messages
//! (validated against their channel's schema) and `verify` counts them. Connections, poll loops and schedules run
//! on the server's broker runtime (`broker::BrokerRuntime`), and a request waits for them as upstream's blocking
//! clients make it wait; `reset` stops and closes them all.
//!
//! - `spec`: the parser, example generator and schema validator;
//! - `orchestrator`: publish cycles and schedules;
//! - `mqtt`: MQTT 3.1.1 and 5 over `rumqttc`, and `mqtt31`: Paho's fallback to MQTT 3.1;
//! - `kafka`: Kafka on our own client over the `kafka-protocol` codecs (an idempotent producer, a classic group
//!   consumer);
//! - `amqp`: AMQP 0-9-1 over `lapin`, configured from a URI as `java.net.URI` reads it (`crate::java_uri`);
//! - `avro`, `registry`: Avro (schema parser, JSON and binary codecs, Confluent framing) and the Schema Registry
//!   client for `kafkaValueFormat: avro`;
//! - `store`: consumed messages and MQTT topic filters;
//! - `tls`: Java key stores and client TLS.

pub mod amqp;
pub mod avro;
pub mod broker;
pub mod kafka;
pub mod mqtt;
mod mqtt31;
pub mod orchestrator;
pub mod registry;
pub mod spec;
pub mod store;
pub mod tls;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use parking_lot::Mutex;
use serde_json::{Map, Value, json};

use broker::{Counters, Error, Publisher, Subscriber};
use orchestrator::Orchestrator;
use spec::{Spec, example, parse, validate};

/// `MAX_VALIDATION_ISSUES`.
const MAX_VALIDATION_ISSUES: usize = 1000;
/// How long closing a spec's connections may take (each connection bounds its own close, at most 5 s).
const CLOSE_LIMIT: Duration = Duration::from_secs(30);
const NOT_JSON: &str = "request body must contain an AsyncAPI spec (JSON/YAML) or {spec, brokerConfig}";

struct Issue {
    channel: String,
    context: String,
    errors: String,
}

#[derive(Default)]
struct Loaded {
    spec: Option<Arc<Spec>>,
    issues: Vec<Issue>,
    connections: Connections,
}

/// The active orchestrators, publishers and subscribers, in the order they were created.
#[derive(Default)]
struct Connections {
    orchestrators: Vec<Arc<Orchestrator>>,
    publishers: Vec<Arc<dyn Publisher>>,
    subscribers: Vec<Arc<dyn Subscriber>>,
}

impl Connections {
    /// `resetInternal`: stops the schedules, then closes the publishers and the subscribers.
    async fn close(self) {
        for o in &self.orchestrators {
            o.stop().await;
        }
        for p in &self.publishers {
            p.close().await;
        }
        for s in &self.subscribers {
            s.close().await;
        }
    }

    /// `putLastPublishFailure`: the first orchestrator's failure.
    fn last_publish_failure(&self) -> Option<String> {
        self.orchestrators.iter().find_map(|o| o.last_publish_failure())
    }
}

fn add_issue(issues: &mut Vec<Issue>, issue: Issue) {
    while issues.len() >= MAX_VALIDATION_ISSUES {
        issues.remove(0);
    }
    issues.push(issue);
}

fn issues_json(issues: &[Issue]) -> Value {
    Value::Array(issues.iter().map(|i| json!({"channel": i.channel, "context": i.context, "errors": i.errors})).collect())
}

/// `BrokerConfig`: the optional `brokerConfig` of a wrapped load body.
#[derive(Clone, Debug)]
pub struct BrokerConfig {
    pub kafka_bootstrap_servers: Option<String>,
    pub kafka_group_id: Option<String>,
    pub mqtt_broker_url: Option<String>,
    pub mqtt_client_id: Option<String>,
    pub amqp_uri: Option<String>,
    pub publish_on_load: bool,
    pub consume: bool,
    pub publish_interval_millis: i64,
    pub mqtt_qos: i32,
    pub mqtt_protocol_version: i32,
    pub mqtt_security: Option<mqtt::MqttSecurity>,
    pub kafka_security: Option<kafka::KafkaSecurity>,
    pub kafka_value_format: String,
    pub kafka_schema_registry_url: Option<String>,
    pub avro_schema: Option<String>,
    pub avro_schema_id: i32,
}

impl Default for BrokerConfig {
    fn default() -> Self {
        BrokerConfig {
            kafka_bootstrap_servers: None,
            kafka_group_id: None,
            mqtt_broker_url: None,
            mqtt_client_id: None,
            amqp_uri: None,
            publish_on_load: true,
            consume: false,
            publish_interval_millis: 0,
            mqtt_qos: 1,
            mqtt_protocol_version: 3,
            mqtt_security: None,
            kafka_security: None,
            kafka_value_format: "json".into(),
            kafka_schema_registry_url: None,
            avro_schema: None,
            avro_schema_id: 1,
        }
    }
}

/// Jackson's `asLong()` of a number node.
fn java_long(n: &serde_json::Number) -> i64 {
    n.as_i64().unwrap_or_else(|| n.as_f64().map(|f| f as i64).unwrap_or(0))
}

/// Jackson's `asInt()`: a `long` narrowed, a `double` truncated.
fn java_int(n: &serde_json::Number) -> i32 {
    match n.as_i64() {
        Some(i) => i as i32,
        None => n.as_f64().map(|f| f as i32).unwrap_or(0),
    }
}

/// Jackson's `asText()`: a container is `""`.
fn java_as_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(_) => crate::model::jackson_tree(v).to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => "null".into(),
        _ => String::new(),
    }
}

/// Jackson's `asInt()` of any node: text parsed (0 when it is not a number), `true` as 1.
fn java_as_int(v: &Value) -> i64 {
    match v {
        Value::Number(n) => java_int(n) as i64,
        Value::Bool(b) => *b as i64,
        Value::String(s) => {
            let s = s.trim();
            s.parse::<i32>().map(|i| i as i64).unwrap_or_else(|_| s.parse::<f64>().map(|f| f as i32 as i64).unwrap_or(0))
        }
        _ => 0,
    }
}

fn text_or_null(node: &Value, field: &str) -> Option<String> {
    node.get(field).and_then(Value::as_str).map(str::to_string)
}

impl BrokerConfig {
    /// `parseBrokerConfig`: the `brokerConfig` node (or none), then the configured defaults for the brokers the
    /// request leaves out, read from `config` as it is now (a `PUT /mockserver/configuration` value first, then the
    /// properties the server started with). The error is upstream's `IllegalArgumentException` message.
    pub fn parse(node: Option<&Value>, config: &crate::config::Config) -> Result<BrokerConfig, String> {
        let mut out = BrokerConfig::default();
        if let Some(node) = node {
            // a JAAS configuration misplaced outside `kafkaSecurity` is refused too, never silently dropped
            if node.as_object().is_some_and(|o| o.iter().any(|(name, value)| name.to_lowercase().contains("jaas") && !value.is_null())) {
                return Err(kafka::SASL_JAAS_CONFIG_STARTUP_ONLY.to_string());
            }
            let bool_or = |f: &str, d: bool| node.get(f).and_then(Value::as_bool).unwrap_or(d);
            let number = |f: &str| node.get(f).and_then(|v| if let Value::Number(n) = v { Some(n.clone()) } else { None });
            out.kafka_bootstrap_servers = text_or_null(node, "kafkaBootstrapServers");
            out.mqtt_broker_url = text_or_null(node, "mqttBrokerUrl");
            out.amqp_uri = text_or_null(node, "amqpUri");
            out.mqtt_client_id = text_or_null(node, "mqttClientId");
            out.kafka_group_id = text_or_null(node, "kafkaGroupId");
            out.publish_on_load = bool_or("publishOnLoad", true);
            out.consume = bool_or("consume", false);
            out.publish_interval_millis = number("publishIntervalMillis").map(|n| java_long(&n)).unwrap_or(0);
            out.mqtt_qos = number("mqttQos").map(|n| java_int(&n)).unwrap_or(1);
            out.mqtt_protocol_version = number("mqttProtocolVersion").map(|n| java_int(&n)).unwrap_or(3);
            if out.mqtt_protocol_version != 3 && out.mqtt_protocol_version != 5 {
                return Err(format!("Unsupported 'mqttProtocolVersion' value {} — allowed values are 3 or 5", out.mqtt_protocol_version));
            }
            out.kafka_security = kafka::KafkaSecurity::parse(node.get("kafkaSecurity"), out.kafka_bootstrap_servers.as_deref(), config)?;
            out.mqtt_security = mqtt_security(node.get("mqttSecurity"));
            if let Some(format) = text_or_null(node, "kafkaValueFormat") {
                let normalised = format.to_lowercase();
                if normalised == "protobuf" {
                    return Err(format!("Unsupported 'kafkaValueFormat' value '{format}' — protobuf is not yet supported; allowed values are json or avro"));
                }
                if normalised != "json" && normalised != "avro" {
                    return Err(format!("Unsupported 'kafkaValueFormat' value '{format}' — allowed values are json or avro"));
                }
                out.kafka_value_format = normalised;
            }
            out.kafka_schema_registry_url = text_or_null(node, "kafkaSchemaRegistryUrl");
            out.avro_schema = match node.get("avroSchema") {
                Some(Value::String(s)) if !s.trim().is_empty() => Some(s.clone()),
                Some(o @ Value::Object(_)) => Some(o.to_string()),
                _ => None,
            };
            out.avro_schema_id = number("avroSchemaId").map(|n| java_int(&n)).unwrap_or(1);
        }
        let default = |name: &str| config.property(name).filter(|v| !v.is_empty());
        if out.kafka_bootstrap_servers.is_none() {
            out.kafka_bootstrap_servers = default("asyncKafkaBootstrapServers");
        }
        if out.mqtt_broker_url.is_none() {
            out.mqtt_broker_url = default("asyncMqttBrokerUrl");
        }
        if out.amqp_uri.is_none() {
            out.amqp_uri = default("asyncAmqpUri");
        }
        Ok(out)
    }
}

/// `recordedMessageMaxEntries`: how many consumed messages a subscriber keeps per channel, read on each load.
pub fn recorded_message_max_entries(config: &crate::config::Config) -> i64 {
    config.int_property("asyncRecordedMessageMaxEntries", store::DEFAULT_MAX_RECORDED_MESSAGES as i64)
}

/// `parseMqttSecurity`: `username`, `password` and the textual `sslProperties`; nothing when all are blank.
fn mqtt_security(node: Option<&Value>) -> Option<mqtt::MqttSecurity> {
    let node = node.filter(|n| n.is_object())?;
    let ssl_properties = node
        .get("sslProperties")
        .and_then(Value::as_object)
        .map(|o| o.iter().filter_map(|(k, v)| v.as_str().map(|v| (k.clone(), v.to_string()))).collect())
        .unwrap_or_default();
    let security = mqtt::MqttSecurity { username: text_or_null(node, "username"), password: text_or_null(node, "password"), ssl_properties };
    (!security.is_empty()).then_some(security)
}

/// `createBrokerConnections`: Kafka, then AMQP, then MQTT. What was created is kept in `connections` whether or
/// not a later step fails, so the caller can close it.
async fn connect(
    spec: Arc<Spec>,
    config: BrokerConfig,
    max_recorded: i64,
    counters: Counters,
    connections: &mut Connections,
    issues: &mut Vec<Issue>,
) -> Result<(), Error> {
    if let Some(bootstrap) = config.kafka_bootstrap_servers.clone() {
        let avro = config.kafka_value_format == "avro";
        let registry = match (&config.kafka_schema_registry_url, avro) {
            (Some(url), true) => Some(Arc::new(registry::SchemaRegistryClient::new(url)?)),
            _ => None,
        };
        let writer = if avro { Some(kafka::AvroWriter::new(config.avro_schema.as_deref(), registry.clone(), config.avro_schema_id)?) } else { None };
        let publisher: Arc<dyn Publisher> = Arc::new(kafka::KafkaPublisher::new(&bootstrap, config.kafka_security.as_ref(), writer).await?);
        connections.publishers.push(publisher.clone());
        start_orchestrator(&spec, publisher, &config, &counters, connections, issues, "kafka").await;
        if config.consume {
            let group = config.kafka_group_id.clone().unwrap_or_else(|| "mockserver-async-consumer".into());
            let reader = avro.then(|| (registry.clone(), config.avro_schema.as_deref(), config.avro_schema_id));
            let subscriber: Arc<dyn Subscriber> =
                Arc::new(kafka::KafkaSubscriber::new(&bootstrap, &group, max_recorded, config.kafka_security.as_ref(), reader, counters.clone()).await?);
            connections.subscribers.push(subscriber.clone());
            for channel in &spec.channels {
                subscriber.subscribe(&channel.name).await?;
            }
        }
    }
    if let Some(uri) = config.amqp_uri.clone() {
        let publisher: Arc<dyn Publisher> = Arc::new(amqp::AmqpPublisher::connect(&uri, Some(&spec)).await?);
        connections.publishers.push(publisher.clone());
        start_orchestrator(&spec, publisher, &config, &counters, connections, issues, "amqp").await;
        if config.consume {
            let subscriber: Arc<dyn Subscriber> = Arc::new(amqp::AmqpSubscriber::connect(&uri, Some(&spec), max_recorded, counters.clone()).await?);
            connections.subscribers.push(subscriber.clone());
            for channel in &spec.channels {
                subscriber.subscribe(&channel.name).await?;
            }
        }
    }
    if let Some(url) = config.mqtt_broker_url.clone() {
        let publisher_id = config.mqtt_client_id.as_ref().map_or_else(|| "mockserver-mqtt-pub".to_string(), |id| format!("{id}-pub"));
        let qos = if config.mqtt_qos >= 0 { config.mqtt_qos } else { 1 };
        if qos > 2 {
            return Err(Error::illegal(format!("MQTT QoS must be 0, 1, or 2; got: {qos}")));
        }
        let version = if config.mqtt_protocol_version == 5 { mqtt::Version::V5 } else { mqtt::Version::V3 };
        let publisher = mqtt::MqttPublisher::connect(&url, &publisher_id, qos as u8, config.mqtt_security.as_ref(), version).await?;
        let publisher: Arc<dyn Publisher> = Arc::new(publisher);
        connections.publishers.push(publisher.clone());
        start_orchestrator(&spec, publisher, &config, &counters, connections, issues, "mqtt").await;
        if config.consume {
            let subscriber_id = config.mqtt_client_id.as_ref().map_or_else(|| "mockserver-mqtt-sub".to_string(), |id| format!("{id}-sub"));
            let subscriber = mqtt::MqttSubscriber::connect(
                &url,
                &subscriber_id,
                qos as u8,
                max_recorded,
                config.mqtt_security.as_ref(),
                version,
                counters.clone(),
            ).await?;
            let subscriber: Arc<dyn Subscriber> = Arc::new(subscriber);
            connections.subscribers.push(subscriber.clone());
            for channel in &spec.channels {
                subscriber.subscribe(&channel.name).await?;
            }
        }
    }
    Ok(())
}

/// A publisher's orchestrator: the load-time publish (a failure becomes a `publish_on_load` issue attributed to the
/// broker) and the schedule.
async fn start_orchestrator(
    spec: &Arc<Spec>,
    publisher: Arc<dyn Publisher>,
    config: &BrokerConfig,
    counters: &Counters,
    connections: &mut Connections,
    issues: &mut Vec<Issue>,
    broker: &str,
) {
    let orchestrator = Arc::new(Orchestrator::new(spec.clone(), publisher, counters.clone()));
    connections.orchestrators.push(orchestrator.clone());
    if config.publish_on_load && let Err(e) = orchestrator.publish_all().await {
        let detail = if e.message.trim().is_empty() { "RuntimeException".to_string() } else { e.message };
        add_issue(issues, Issue { channel: broker.into(), context: "publish_on_load".into(), errors: detail });
    }
    if config.publish_interval_millis > 0 {
        orchestrator.start_publishing(config.publish_interval_millis as u64);
    }
}

/// A server's AsyncAPI state (`AsyncApiControlPlaneImpl`'s): the loaded spec, its issues and its broker
/// connections, and the runtime they run on.
#[derive(Default)]
pub struct AsyncApi {
    runtime: broker::BrokerRuntime,
    loaded: Mutex<Loaded>,
    /// Serialises loads and resets; `status` and `verify` only take `loaded`, briefly.
    lifecycle: Mutex<()>,
    stopped: AtomicBool,
}

impl AsyncApi {
    /// `resetInternal`: takes what is loaded, then closes its connections (outside the lock, bounded).
    fn reset_internal(&self) {
        let connections = std::mem::take(&mut *self.loaded.lock()).connections;
        self.close(connections);
    }

    fn close(&self, connections: Connections) {
        let _ = self.runtime.block(async move { tokio::time::timeout(CLOSE_LIMIT, connections.close()).await });
    }

    /// `reset`.
    pub fn reset(&self) {
        let _lifecycle = self.lifecycle.lock();
        self.reset_internal();
    }

    /// The server is stopping: what is loaded is closed, and a load still connecting closes what it opened.
    pub async fn shutdown(&self) {
        self.stopped.store(true, Ordering::SeqCst);
        let connections = std::mem::take(&mut *self.loaded.lock()).connections;
        let _ = self.runtime.run(CLOSE_LIMIT, connections.close()).await;
    }

    /// `load`: replaces whatever was loaded; the load response, or upstream's `Failed to load AsyncAPI spec: …`.
    pub fn load(&self, body: &str, config: &crate::config::Config) -> Result<Value, String> {
        self.load_classified(body, config).map_err(|e| e.message)
    }

    /// [`AsyncApi::load`], its failure telling a client error (`IllegalArgumentException`: a spec or broker
    /// configuration the caller can correct) from a fault (`RuntimeException`: a broker connection that failed).
    pub fn load_classified(&self, body: &str, config: &crate::config::Config) -> Result<Value, LoadError> {
        let _lifecycle = self.lifecycle.lock();
        self.reset_internal();
        let failed = |e: String| LoadError { message: format!("Failed to load AsyncAPI spec: {e}"), client: true, cause: None };
        let wrapper = body.trim().starts_with('{').then(|| serde_json::from_str::<Value>(body.trim()).ok()).flatten();
        let (content, broker_config) = match wrapper.as_ref().filter(|w| w.get("spec").is_some()) {
            Some(w) => {
                let content = match &w["spec"] {
                    Value::String(s) => s.clone(),
                    spec => spec.to_string(),
                };
                (content, BrokerConfig::parse(w.get("brokerConfig"), config).map_err(failed)?)
            }
            None => (body.to_string(), BrokerConfig::default()),
        };
        let spec = Arc::new(parse(&content).map_err(failed)?);
        let mut issues = Vec::new();
        for channel in &spec.channels {
            if let Some(schema) = &channel.payload_schema && let Some(errors) = validate(Some(&channel.example()), Some(schema)) {
                add_issue(&mut issues, Issue { channel: channel.name.clone(), context: "generated_example".into(), errors });
            }
            // `validateFirstMessageExamples`.
            for message in channel.messages() {
                let (Some(schema), Some(first)) = (&message.payload_schema, message.examples.first()) else { continue };
                if let Some(errors) = validate(Some(&first.to_string()), Some(schema)) {
                    let context = message.name.as_ref().map_or_else(|| "first_message_example".to_string(), |n| format!("first_message_example:{n}"));
                    add_issue(&mut issues, Issue { channel: channel.name.clone(), context, errors });
                }
            }
        }
        let max_recorded = recorded_message_max_entries(config);
        let counters = Counters(crate::metrics::enabled(config).then(|| config.metrics.clone()));
        let connected = self.runtime.block({
            let spec = spec.clone();
            async move {
                let (mut connections, mut issues) = (Connections::default(), issues);
                let outcome = connect(spec, broker_config, max_recorded, counters, &mut connections, &mut issues).await;
                (connections, issues, outcome)
            }
        });
        let (connections, issues) = match connected {
            Ok((connections, issues, Ok(()))) if !self.stopped.load(Ordering::SeqCst) => (connections, issues),
            Ok((connections, _, outcome)) => {
                self.close(connections);
                // only input the caller can correct is a client error; a connection that failed is a fault
                let Some(e) = outcome.err() else { return Err(LoadError { client: false, ..failed("the server is stopping".into()) }) };
                let client = e.kind == broker::ErrorKind::IllegalArgument;
                return Err(LoadError { client, cause: Some(e.clone()), ..failed(e.message) });
            }
            Err(e) => return Err(LoadError { client: false, ..failed(e.message) }),
        };
        let mut result = json!({
            "loaded": true,
            "specTitle": spec.title,
            "specVersion": spec.version,
            "channelCount": spec.channels.len(),
            "channels": spec.channels.iter().map(|c| json!({"name": c.name, "hasSchema": c.payload_schema.is_some()})).collect::<Vec<_>>(),
            "publishers": connections.publishers.len(),
            "subscribers": connections.subscribers.len(),
        });
        if let Some(failure) = connections.last_publish_failure() {
            result["lastPublishFailure"] = Value::String(failure);
        }
        if !issues.is_empty() {
            result["validationIssues"] = issues_json(&issues);
        }
        *self.loaded.lock() = Loaded { spec: Some(spec), issues, connections };
        Ok(result)
    }

    /// `status`: what `GET /mockserver/asyncapi` answers.
    pub fn status(&self) -> Value {
        let state = self.loaded.lock();
        let Some(spec) = &state.spec else {
            return json!({"loaded": false, "channels": [], "publishers": 0, "subscribers": 0, "recordedMessages": []});
        };
        let mut result = json!({
            "loaded": true,
            "specTitle": spec.title,
            "specVersion": spec.version,
            "channels": spec.channels
                .iter()
                .map(|c| json!({"name": c.name, "hasSchema": c.payload_schema.is_some(), "exampleCount": c.examples.len()}))
                .collect::<Vec<_>>(),
            "publishers": state.connections.publishers.len(),
            "subscribers": state.connections.subscribers.len(),
        });
        if let Some(failure) = state.connections.last_publish_failure() {
            result["lastPublishFailure"] = Value::String(failure);
        }
        let recorded: Vec<Value> = state.connections.subscribers.iter().flat_map(|s| s.all_recorded()).map(|m| recorded_json(&m, spec)).collect();
        result["recordedMessages"] = Value::Array(recorded);
        if !state.issues.is_empty() {
            result["validationIssues"] = issues_json(&state.issues);
        }
        result
    }

    /// `addSubscriberForTesting`: `subscriber` joins the active subscribers, for `status` and `verify` to read and a
    /// reset or the server stopping to close, without a broker behind it.
    pub fn add_subscriber_for_testing(&self, subscriber: Arc<dyn Subscriber>) {
        self.loaded.lock().connections.subscribers.push(subscriber);
    }

    /// The messages the subscribers recorded on `channel`.
    fn recorded(&self, channel: &str) -> Vec<store::ConsumedMessage> {
        self.loaded.lock().connections.subscribers.iter().flat_map(|s| s.recorded(channel)).collect()
    }
}

/// A consumed message as `status` lists it (`recordedMessages`), validated against its channel's schema.
fn recorded_json(message: &store::ConsumedMessage, spec: &Spec) -> Value {
    let mut node = Map::new();
    node.insert("channel".into(), Value::String(message.channel.clone()));
    if let Some(key) = &message.key {
        node.insert("key".into(), Value::String(key.clone()));
    }
    node.insert("payload".into(), message.payload.clone().map_or(Value::Null, Value::String));
    if !message.headers.is_empty() {
        node.insert("headers".into(), Value::Object(message.headers.iter().map(|(k, v)| (k.clone(), v.clone().map_or(Value::Null, Value::String))).collect()));
    }
    node.insert("timestamp".into(), Value::String(message.timestamp_text()));
    if let Some(schema) = spec.channels.iter().find(|c| c.name == message.channel).and_then(|c| c.payload_schema.as_ref()) {
        let errors = validate(message.payload.as_deref(), Some(schema));
        node.insert("schemaValid".into(), Value::Bool(errors.is_none()));
        if let Some(errors) = errors {
            node.insert("schemaErrors".into(), Value::String(errors));
        }
    }
    Value::Object(node)
}

/// `extractJsonPath`: a dot-separated path into the payload; text as is, other values as JSON.
fn extract_json_path(payload: &str, path: &str) -> Option<String> {
    let mut node = serde_json::from_str::<Value>(payload).ok()?;
    for segment in path.split('.') {
        node = match node {
            Value::Object(mut o) => o.remove(segment)?,
            _ => return None,
        };
    }
    match node {
        Value::Null => None,
        Value::String(s) => Some(s),
        other => Some(crate::model::jackson_tree(&other).to_string()),
    }
}

/// `rejectUnknownFields`: a misplaced or misspelt field is refused rather than ignored, so a verification never
/// quietly checks the default "at least one message" instead of what was asked.
fn reject_unknown_fields(request: &Value) -> Result<(), String> {
    const VERIFY_FIELDS: [&str; 5] = ["channel", "payloadSubstring", "payloadJsonPath", "expectedValue", "count"];
    const COUNT_FIELDS: [&str; 3] = ["atLeast", "atMost", "exactly"];
    let Some(fields) = request.as_object() else { return Ok(()) };
    for name in fields.keys() {
        if COUNT_FIELDS.contains(&name.as_str()) {
            return Err(format!("'{name}' must be inside \"count\", e.g. {{\"channel\":\"orders\",\"count\":{{\"{name}\":1}}}}"));
        }
        if !VERIFY_FIELDS.contains(&name.as_str()) {
            return Err(format!("unknown field '{name}' in verification request; valid fields are [{}]", VERIFY_FIELDS.join(", ")));
        }
    }
    let count = match request.get("count") {
        None | Some(Value::Null) => return Ok(()),
        Some(Value::Object(count)) => count,
        Some(_) => return Err("\"count\" must be an object with atLeast, atMost or exactly".into()),
    };
    for (name, value) in count {
        if !COUNT_FIELDS.contains(&name.as_str()) {
            return Err(format!("unknown field '{name}' in \"count\"; valid fields are [{}]", COUNT_FIELDS.join(", ")));
        }
        // `isIntegralNumber() && canConvertToInt() && asInt() >= 0`
        if !value.as_i64().is_some_and(|n| (0..=i64::from(i32::MAX)).contains(&n)) {
            return Err(format!("\"count\".{name} must be a whole number of at least 0"));
        }
    }
    Ok(())
}

/// `verify`: the failure, or `None` when the consumed messages satisfy the count.
fn verify(body: &str, recorded: impl FnOnce(&str) -> Vec<store::ConsumedMessage>) -> Result<Option<String>, String> {
    if body.trim().is_empty() {
        return Err("verification request body must not be empty".into());
    }
    let request: Value = serde_json::from_str(body).map_err(|e| format!("invalid JSON in verification request: {e}"))?;
    let channel = request.get("channel").ok_or("verification request must contain a 'channel' field")?;
    reject_unknown_fields(&request)?;
    let channel = java_as_text(channel);
    let field = |k: &str| request.get(k).and_then(Value::as_str).map(str::to_string);
    let (substring, json_path, expected) = (field("payloadSubstring"), field("payloadJsonPath"), field("expectedValue"));
    let count = |k: &str| request.get("count").filter(|c| c.is_object()).and_then(|c| c.get(k)).map(java_as_int);
    let (mut at_least, at_most, exactly) = (count("atLeast").unwrap_or(-1), count("atMost").unwrap_or(-1), count("exactly").unwrap_or(-1));
    if at_least < 0 && at_most < 0 && exactly < 0 {
        at_least = 1;
    }
    let actual = recorded(&channel)
        .iter()
        .filter(|m| {
            let payload = m.payload.as_deref().unwrap_or("");
            if substring.as_ref().is_some_and(|s| !payload.contains(s.as_str())) {
                return false;
            }
            match (&json_path, &expected) {
                (Some(path), Some(expected)) => extract_json_path(payload, path).as_deref() == Some(expected.as_str()),
                _ => true,
            }
        })
        .count() as i64;
    let mut criteria = format!("channel '{channel}'");
    if let Some(s) = &substring {
        criteria.push_str(&format!(" with payload containing '{s}'"));
    }
    if let (Some(p), Some(e)) = (&json_path, &expected) {
        criteria.push_str(&format!(" with {p}='{e}'"));
    }
    if exactly >= 0 && actual != exactly {
        return Ok(Some(format!("expected exactly {exactly} message(s) matching {criteria} but found {actual}")));
    }
    if at_least >= 0 && actual < at_least {
        return Ok(Some(format!("expected at least {at_least} message(s) matching {criteria} but found {actual}")));
    }
    if at_most >= 0 && actual > at_most {
        return Ok(Some(format!("expected at most {at_most} message(s) matching {criteria} but found {actual}")));
    }
    Ok(None)
}

/// `AsyncApiHttpExpectationGenerator.generate`: a `GET` expectation per channel answering its example.
fn http_expectations(body: &str) -> Result<Vec<Value>, String> {
    if body.trim().is_empty() {
        return Err("request body must contain an AsyncAPI spec (JSON/YAML)".into());
    }
    let wrapper = body.trim().starts_with('{').then(|| serde_json::from_str::<Value>(body.trim()).ok()).flatten();
    let (content, prefix) = match wrapper.as_ref().filter(|w| w.get("spec").is_some()) {
        Some(w) => (
            match &w["spec"] {
                Value::String(s) => s.clone(),
                spec => spec.to_string(),
            },
            w.get("channelPathPrefix").and_then(Value::as_str).unwrap_or_default().to_string(),
        ),
        None => (body.to_string(), String::new()),
    };
    let spec = parse(&content).map_err(|e| format!("unable to parse AsyncAPI spec: {e}"))?;
    if spec.channels.is_empty() {
        return Err("AsyncAPI spec defined no channels".into());
    }
    let mut used: Vec<String> = Vec::new();
    Ok(spec
        .channels
        .iter()
        .map(|channel| {
            let path = channel_path(&prefix, &channel.name, &mut used);
            json!({
                "httpRequest": {"method": "GET", "path": path},
                "httpResponse": {
                    "statusCode": 200,
                    "body": {"type": "STRING", "string": example(&channel.examples, channel.payload_schema.as_ref()), "contentType": "application/json"},
                },
            })
        })
        .collect())
}

/// `toPath`: the channel name as a path (dots to slashes) under the prefix, made unique with `/2`, `/3`, ….
fn channel_path(prefix: &str, channel: &str, used: &mut Vec<String>) -> String {
    let name = channel.trim().replace('.', "/");
    let name = name.trim_start_matches('/');
    let mut path = String::new();
    let prefix = prefix.trim();
    if !prefix.is_empty() {
        if !prefix.starts_with('/') {
            path.push('/');
        }
        path.push_str(prefix.strip_suffix('/').unwrap_or(prefix));
    }
    path.push('/');
    path.push_str(if name.is_empty() { "channel" } else { name });
    let mut base = String::new();
    for c in path.chars() {
        if !(c == '/' && base.ends_with('/')) {
            base.push(c);
        }
    }
    let mut candidate = base.clone();
    let mut suffix = 2;
    while used.contains(&candidate) {
        candidate = format!("{base}/{suffix}");
        suffix += 1;
    }
    used.push(candidate.clone());
    candidate
}

/// Why a load failed: upstream's `Failed to load AsyncAPI spec: …` message, and whether it was a client error.
#[derive(Debug)]
pub struct LoadError {
    pub message: String,
    pub client: bool,
    /// What the message wraps (`new RuntimeException("Failed to load AsyncAPI spec: " + e.getMessage(), e)`).
    pub cause: Option<broker::Error>,
}

fn error(message: &str) -> crate::reply::Reply {
    crate::reply::Reply::api_body(400, "application/json", crate::json::compact(&serde_json::json!({"error": message})))
}

/// The `/asyncapi` routes.
pub(crate) fn route(state: &crate::state::State, request: &crate::request::HttpRequest, op: &str) -> Option<crate::reply::Reply> {
    use crate::reply::Reply;
    let body = request.body_str();
    Some(match (request.method.as_str(), op) {
        ("GET", "/asyncapi") => Reply::api_body(200, "application/json", crate::json::pretty(&state.asyncapi.status())),
        ("PUT", "/asyncapi") => {
            if body.trim().is_empty() {
                return Some(error(NOT_JSON));
            }
            match state.asyncapi.load_classified(&body, &state.config) {
                Ok(result) => Reply::api_body(201, "application/json", crate::json::pretty(&result)),
                Err(e) if e.client => error(&format!("failed to load AsyncAPI spec: {}", e.message)),
                // `HttpState.handleAsyncApiPut`: a fault is answered 500 (`unexpectedFailure`)
                Err(e) => {
                    let cause: Vec<(&str, Value)> = e.cause.iter().map(|c| ("cause", c.bean())).collect();
                    crate::control::unexpected_failure_json(state, request, &crate::recorded::Failure::of("java.lang.RuntimeException", e.message, cause, &[]))
                }
            }
        }
        ("PUT", "/asyncapi/verify") => match verify(&body, |channel| state.asyncapi.recorded(channel)) {
            Ok(None) => Reply::api(202),
            // `MediaType.create("text", "plain")`: no charset.
            Ok(Some(failure)) => {
                let mut reply = Reply::api(406);
                reply.headers.push(("content-type".into(), "text/plain".into()));
                reply.body = failure.into();
                reply
            }
            Err(e) => error(&e),
        },
        ("PUT", "/asyncapi/http") => {
            if body.trim().is_empty() {
                return Some(error("request body must contain an AsyncAPI spec (JSON/YAML) or {spec, channelPathPrefix}"));
            }
            match http_expectations(&body) {
                Ok(items) => Reply::api_body(201, "application/json", crate::json::pretty(&crate::control::add_generated(state, &items))),
                Err(e) => Reply::api_body(400, "application/json", json!({"error": e}).to_string()),
            }
        }
        _ => return None,
    })
}
