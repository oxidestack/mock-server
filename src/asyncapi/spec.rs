//! `AsyncApiParser` and the model it builds (`AsyncApiSpec`, `AsyncApiChannel`, `AsyncApiMessage`, `AmqpBinding`),
//! with `MessageExampleGenerator` and `AsyncApiSchemaValidator`.
//!
//! The document is read as Jackson reads it (floating-point numbers become `Double`s, `model::jackson_tree`), so a
//! published or served example prints its numbers as upstream's `writeValueAsString` does.

use serde_json::{Map, Value, json};

/// `AsyncApiMessage`.
#[derive(Clone, Debug, Default)]
pub struct Message {
    pub name: Option<String>,
    pub payload_schema: Option<Value>,
    pub examples: Vec<Value>,
    /// `bindings.kafka.key` when it is a literal (or a schema's `const`, `example`, `examples[0]`).
    pub kafka_key: Option<String>,
    /// `correlationId.location`, e.g. `$message.header#/correlationId` or `$message.payload#/meta/id`.
    pub correlation_id_location: Option<String>,
}

/// `AmqpBinding.ChannelType`: `is: routingKey` (the default) or `is: queue`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum AmqpChannelType {
    #[default]
    RoutingKey,
    Queue,
}

/// `AmqpBinding`: `channels.<name>.bindings.amqp`.
#[derive(Clone, Debug)]
pub struct AmqpBinding {
    pub channel_type: AmqpChannelType,
    pub exchange_name: Option<String>,
    pub exchange_type: Option<String>,
    pub exchange_durable: bool,
    pub queue_name: Option<String>,
    pub queue_durable: bool,
    pub routing_key: Option<String>,
}

impl AmqpBinding {
    pub fn new(
        channel_type: AmqpChannelType,
        exchange_name: Option<&str>,
        exchange_type: Option<&str>,
        exchange_durable: bool,
        queue_name: Option<&str>,
        queue_durable: bool,
        routing_key: Option<&str>,
    ) -> Self {
        let owned = |s: Option<&str>| s.map(str::to_string);
        AmqpBinding {
            channel_type,
            exchange_name: owned(exchange_name),
            exchange_type: owned(exchange_type),
            exchange_durable,
            queue_name: owned(queue_name),
            queue_durable,
            routing_key: owned(routing_key),
        }
    }
}

/// `AsyncApiChannel`: the first message's schema, examples, Kafka key and correlation id, every message when there
/// are several, and the channel's MQTT and AMQP bindings.
#[derive(Clone, Debug, Default)]
pub struct Channel {
    pub name: String,
    pub examples: Vec<Value>,
    pub payload_schema: Option<Value>,
    pub mqtt_qos: Option<u8>,
    pub mqtt_retain: Option<bool>,
    pub kafka_key: Option<String>,
    /// Only when the channel has more than one message.
    pub messages: Option<Vec<Message>>,
    pub correlation_id_location: Option<String>,
    pub amqp_binding: Option<AmqpBinding>,
}

impl Channel {
    /// `new AsyncApiChannel(name, examples, schema)`.
    pub fn new(name: &str, examples: Vec<Value>, payload_schema: Option<Value>) -> Self {
        Channel { name: name.to_string(), examples, payload_schema, ..Channel::default() }
    }

    /// `getMessages`: the explicit messages, else one built from the channel's own fields.
    pub fn messages(&self) -> Vec<Message> {
        self.messages.clone().unwrap_or_else(|| {
            vec![Message {
                name: None,
                payload_schema: self.payload_schema.clone(),
                examples: self.examples.clone(),
                kafka_key: self.kafka_key.clone(),
                correlation_id_location: self.correlation_id_location.clone(),
            }]
        })
    }

    /// `toPublishOptions`: the channel's Kafka key and MQTT bindings, `PublishOptions.none()` when it has none.
    pub fn to_publish_options(&self) -> super::broker::PublishOptions {
        super::broker::PublishOptions { key: self.kafka_key.clone(), qos: self.mqtt_qos, retain: self.mqtt_retain, headers: Vec::new() }
    }

    /// `MessageExampleGenerator.generateExample(channel)`: from the first message's examples and schema.
    pub fn example(&self) -> String {
        example(&self.examples, self.payload_schema.as_ref())
    }
}

impl Message {
    /// `MessageExampleGenerator.generateExample(message)`.
    pub fn example(&self) -> String {
        example(&self.examples, self.payload_schema.as_ref())
    }
}

/// `AsyncApiSpec`.
#[derive(Clone, Debug, Default)]
pub struct Spec {
    pub version: Option<String>,
    pub title: Option<String>,
    pub channels: Vec<Channel>,
}

impl Spec {
    pub fn new(version: &str, title: &str, channels: Vec<Channel>) -> Self {
        Spec { version: Some(version.to_string()), title: Some(title.to_string()), channels }
    }
}

fn text(node: &Value, key: &str) -> Option<String> {
    node.get(key).and_then(Value::as_str).map(str::to_string)
}

/// `AsyncApiParser.parse`: JSON when it starts with `{`, else YAML.
pub fn parse(document: &str) -> Result<Spec, String> {
    if document.trim().is_empty() {
        return Err("AsyncAPI document must not be null or blank".into());
    }
    let trimmed = document.trim();
    let node = if trimmed.starts_with('{') {
        // `new ObjectMapper().readTree`: no parser features, Jackson's message and location on failure, and only the
        // first value read (trailing content is ignored).
        let features = jackson::json::ReadFeatures { tree_member_values: true, ..Default::default() };
        jackson::json::read_tree(trimmed, features).map_err(|e| e.message)?
    } else {
        // `new ObjectMapper(new YAMLFactory()).readTree`: SnakeYAML's marked message and Jackson's location on failure.
        jackson::yaml::read_tree(trimmed, jackson::yaml::YamlReadFeatures::swagger_core()).map_err(|e| e.message)?
    };
    let root: Value = serde_json::from_str(&jackson::convert::node_to_json_string(&node, false, false)).map_err(|e| e.to_string())?;
    let root = crate::model::jackson_tree(&root);
    let version = text(&root, "asyncapi");
    let title = root.get("info").and_then(|i| text(i, "title"));
    let channels = if version.as_deref().is_some_and(|v| v.starts_with('3')) { v3_channels(&root) } else { v2_channels(&root) };
    Ok(Spec { version, title, channels })
}

/// `resolveRef`: a local `#/…` reference, else the node itself.
fn resolve<'a>(root: &'a Value, node: &'a Value) -> &'a Value {
    if let Some(path) = node.get("$ref").and_then(Value::as_str).and_then(|r| r.strip_prefix("#/")) {
        let mut resolved = Some(root);
        for part in path.split('/') {
            resolved = resolved.and_then(|r| r.get(part));
        }
        if let Some(r) = resolved {
            return r;
        }
    }
    node
}

/// Jackson's `JsonNode.asText()` for a value node.
fn as_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "null".into(),
        other => other.to_string(),
    }
}

/// `parseKafkaKeyFromMessage`.
fn kafka_key(message: &Value) -> Option<String> {
    let key = message.get("bindings")?.get("kafka")?.get("key")?;
    match key {
        Value::String(_) | Value::Number(_) => Some(as_text(key)),
        Value::Object(_) => {
            let value_node = |v: &&Value| !v.is_object() && !v.is_array();
            key.get("const")
                .filter(value_node)
                .or_else(|| key.get("example").filter(value_node))
                .or_else(|| key.get("examples").and_then(Value::as_array).and_then(|e| e.first()).filter(value_node))
                .map(as_text)
        }
        _ => None,
    }
}

/// `parseCorrelationIdLocation`.
fn correlation_id_location(root: &Value, message: &Value) -> Option<String> {
    let node = resolve(root, message.get("correlationId")?);
    node.get("location").and_then(Value::as_str).map(str::to_string)
}

/// Jackson's `asLong()` of a number node: a `long` as is, a `BigInteger`'s low 64 bits, a `double` truncated.
fn java_long(n: &Value) -> i64 {
    let Value::Number(n) = n else { return 0 };
    n.as_i64().or_else(|| n.as_u64().map(|u| u as i64)).unwrap_or_else(|| n.as_f64().map_or(0, |f| f as i64))
}

/// Jackson's `asInt()` of a number node: a `long` narrowed, a `double` truncated.
fn java_int(n: &Value) -> i32 {
    match n {
        Value::Number(number) if number.as_i64().is_some() || number.as_u64().is_some() => java_long(n) as i32,
        Value::Number(number) => number.as_f64().map_or(0, |f| f as i32),
        _ => 0,
    }
}

/// `parseMqttQos`: `bindings.mqtt.qos` as `asInt()` reads it, 0 to 2.
fn mqtt_qos(node: &Value) -> Option<u8> {
    let qos = node.get("bindings")?.get("mqtt")?.get("qos").filter(|q| q.is_number())?;
    let qos = java_int(qos);
    (0..=2).contains(&qos).then_some(qos as u8)
}

/// `parseMqttRetain`: `bindings.mqtt.retain`.
fn mqtt_retain(node: &Value) -> Option<bool> {
    node.get("bindings")?.get("mqtt")?.get("retain")?.as_bool()
}

/// `parseAmqpBinding`: `bindings.amqp` on the channel.
fn amqp_binding(channel: &Value) -> Option<AmqpBinding> {
    let amqp = channel.get("bindings")?.get("amqp").filter(|a| a.is_object())?;
    let channel_type = match amqp.get("is").and_then(Value::as_str) {
        Some(is) if is.eq_ignore_ascii_case("queue") => AmqpChannelType::Queue,
        _ => AmqpChannelType::RoutingKey,
    };
    let exchange = amqp.get("exchange").filter(|e| e.is_object());
    let queue = amqp.get("queue").filter(|q| q.is_object());
    let durable = |node: Option<&Value>| node.and_then(|n| n.get("durable")).and_then(Value::as_bool).unwrap_or(true);
    Some(AmqpBinding {
        channel_type,
        exchange_name: exchange.and_then(|e| text(e, "name")),
        exchange_type: exchange.and_then(|e| text(e, "type")),
        exchange_durable: durable(exchange),
        queue_name: queue.and_then(|q| text(q, "name")),
        queue_durable: durable(queue),
        routing_key: text(amqp, "routingKey"),
    })
}

/// A message's payload schema and examples (`payload.example` in 2.x, then each `examples[].payload`), Kafka key and
/// correlation id.
fn message(root: &Value, name: Option<String>, node: &Value, payload_example: bool) -> Message {
    let payload_schema = node.get("payload").cloned();
    let mut examples = Vec::new();
    if payload_example && let Some(example) = node.get("payload").and_then(|p| p.get("example")) {
        examples.push(example.clone());
    }
    for example in node.get("examples").and_then(Value::as_array).into_iter().flatten() {
        if let Some(payload) = example.get("payload") {
            examples.push(payload.clone());
        }
    }
    Message { name, payload_schema, examples, kafka_key: kafka_key(node), correlation_id_location: correlation_id_location(root, node) }
}

/// A channel from its messages: the first one's fields, and all of them when there are several.
fn channel_of(name: &str, messages: Vec<Message>, mqtt_qos: Option<u8>, mqtt_retain: Option<bool>, amqp: Option<AmqpBinding>) -> Channel {
    let first = messages.first().cloned().unwrap_or_default();
    Channel {
        name: name.to_string(),
        examples: first.examples,
        payload_schema: first.payload_schema,
        mqtt_qos,
        mqtt_retain,
        kafka_key: first.kafka_key,
        correlation_id_location: first.correlation_id_location,
        messages: (messages.len() > 1).then_some(messages),
        amqp_binding: amqp,
    }
}

fn v2_channels(root: &Value) -> Vec<Channel> {
    let Some(channels) = root.get("channels").and_then(Value::as_object) else { return Vec::new() };
    channels
        .iter()
        .map(|(name, definition)| {
            // `findV2Operation`: `publish`, then `subscribe`, whichever has a message.
            let operation = ["publish", "subscribe"].iter().filter_map(|k| definition.get(*k)).find(|o| o.get("message").is_some());
            let (Some(operation), Some(message_node)) = (operation, operation.and_then(|o| o.get("message"))) else {
                return Channel::new(name, Vec::new(), None);
            };
            let (qos, retain, amqp) = (mqtt_qos(operation), mqtt_retain(operation), amqp_binding(definition));
            match message_node.get("oneOf").and_then(Value::as_array) {
                Some(variants) if variants.len() > 1 => {
                    let messages: Vec<Message> = variants.iter().filter(|v| v.is_object()).map(|v| message(root, text(v, "name"), v, true)).collect();
                    if messages.is_empty() {
                        Channel { mqtt_qos: qos, mqtt_retain: retain, amqp_binding: amqp, ..Channel::new(name, Vec::new(), None) }
                    } else {
                        channel_of(name, messages, qos, retain, amqp)
                    }
                }
                Some(variants) if variants.len() == 1 && variants[0].is_object() => channel_of(
                    name,
                    vec![message(root, None, &variants[0], true)],
                    qos,
                    retain,
                    amqp,
                ),
                _ => channel_of(name, vec![message(root, None, message_node, true)], qos, retain, amqp),
            }
        })
        .collect()
}

fn v3_channels(root: &Value) -> Vec<Channel> {
    let Some(channels) = root.get("channels").and_then(Value::as_object) else { return Vec::new() };
    channels
        .iter()
        .map(|(name, definition)| match definition.get("messages").and_then(Value::as_object).filter(|m| !m.is_empty()) {
            None => Channel::new(name, Vec::new(), None),
            Some(messages) => channel_of(
                name,
                messages.iter().map(|(n, m)| message(root, Some(n.clone()), resolve(root, m), false)).collect(),
                mqtt_qos(definition),
                mqtt_retain(definition),
                amqp_binding(definition),
            ),
        })
        .collect()
}

/// `MessageExampleGenerator.generateExample`: the first example, else one synthesised from the schema, else `{}`.
pub fn example(examples: &[Value], schema: Option<&Value>) -> String {
    if let Some(first) = examples.first() {
        return first.to_string();
    }
    schema.and_then(synthesize).map_or_else(|| "{}".to_string(), |v| v.to_string())
}

/// `MessageExampleGenerator.generateExamples`: each channel's example by channel name, in channel order (a repeated
/// name keeps its first position and takes the later example, as a `LinkedHashMap` does).
pub fn examples(spec: &Spec) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for channel in &spec.channels {
        let generated = channel.example();
        match out.iter_mut().find(|(name, _)| *name == channel.name) {
            Some(entry) => entry.1 = generated,
            None => out.push((channel.name.clone(), generated)),
        }
    }
    out
}

/// `synthesizeFromSchema`.
fn synthesize(schema: &Value) -> Option<Value> {
    if let Some(default) = schema.get("default") {
        return Some(default.clone());
    }
    if let Some(first) = schema.get("enum").and_then(Value::as_array).and_then(|e| e.first()) {
        return Some(first.clone());
    }
    if let Some(constant) = schema.get("const") {
        return Some(constant.clone());
    }
    let kind = match schema.get("type").and_then(Value::as_str) {
        Some(t) => t,
        None if schema.get("properties").is_some() => "object",
        None => return Some(json!({})),
    };
    let number = |k: &str| schema.get(k).filter(|v| v.is_number());
    Some(match kind {
        "object" => {
            let mut out = Map::new();
            for (k, v) in schema.get("properties").and_then(Value::as_object).into_iter().flatten() {
                if let Some(value) = synthesize(v) {
                    out.insert(k.clone(), value);
                }
            }
            Value::Object(out)
        }
        "array" => {
            let items = schema.get("items");
            let mut out: Vec<Value> = items.and_then(synthesize).into_iter().collect();
            let min = number("minItems").map_or(0, java_int).max(0) as usize;
            while out.len() < min {
                match items.and_then(synthesize) {
                    Some(extra) => out.push(extra),
                    None => break,
                }
            }
            Value::Array(out)
        }
        "string" => Value::String(synthesize_string(schema)),
        // `asLong()` + 1, wrapping as a Java `long` does.
        "integer" => {
            let exclusive = schema.get("exclusiveMinimum");
            match number("minimum").map(java_long) {
                Some(min) => match exclusive {
                    Some(Value::Bool(true)) => json!(min.wrapping_add(1)),
                    Some(e) if e.is_number() => json!(java_long(e).wrapping_add(1)),
                    _ => json!(min),
                },
                None => match exclusive.filter(|e| e.is_number()) {
                    Some(e) => json!(java_long(e).wrapping_add(1)),
                    None => json!(0),
                },
            }
        }
        "number" => {
            let exclusive = schema.get("exclusiveMinimum");
            let double = |d: f64| crate::model::number(&java_compat::double_to_string(d));
            match number("minimum").and_then(Value::as_f64) {
                Some(min) => match exclusive {
                    Some(Value::Bool(true)) => double(min + 0.1),
                    Some(e) if e.is_number() => double(e.as_f64().unwrap_or(0.0) + 0.1),
                    _ => double(min),
                },
                None => match exclusive.filter(|e| e.is_number()) {
                    Some(e) => double(e.as_f64().unwrap_or(0.0) + 0.1),
                    None => double(0.0),
                },
            }
        }
        "boolean" => Value::Bool(false),
        "null" => Value::Null,
        _ => json!({}),
    })
}

fn synthesize_string(schema: &Value) -> String {
    if let Some(pattern) = schema.get("pattern").and_then(Value::as_str) {
        if pattern.contains('@') {
            return "user@example.com".into();
        }
        // `pattern.matches(".*\\^\\[0-9\\].*")`: `.` stops at a line terminator.
        let one_line = !pattern.contains(['\n', '\r', '\u{85}', '\u{2028}', '\u{2029}']);
        if (one_line && pattern.contains("^[0-9]")) || pattern.contains("\\d") {
            return "12345".into();
        }
    }
    let formatted = match schema.get("format").and_then(Value::as_str) {
        Some("date-time") => Some("2024-01-01T00:00:00Z"),
        Some("date") => Some("2024-01-01"),
        Some("time") => Some("00:00:00Z"),
        Some("email") => Some("user@example.com"),
        Some("uri" | "url") => Some("https://example.com"),
        Some("uuid") => Some("00000000-0000-0000-0000-000000000000"),
        Some("ipv4") => Some("127.0.0.1"),
        Some("ipv6") => Some("::1"),
        _ => None,
    };
    if let Some(f) = formatted {
        return f.into();
    }
    match schema.get("minLength").filter(|m| m.is_number()).map(java_int) {
        Some(min) if min > "string".len() as i32 => "s".repeat(min as usize),
        _ => "string".into(),
    }
}

/// `AsyncApiSchemaValidator.validate`: the report, or `None` when the payload conforms or there is no schema.
pub fn validate(payload: Option<&str>, schema: Option<&Value>) -> Option<String> {
    let schema = schema?;
    let Some(payload) = payload.filter(|p| !p.trim().is_empty()) else {
        return Some("payload is null or blank".into());
    };
    let validator = match crate::matcher::string::validator(schema) {
        Ok(v) => v,
        Err(e) => return Some(format!("schema validation error: {e}")),
    };
    let instance = serde_json::from_str::<Value>(payload).unwrap_or_else(|_| Value::String(payload.to_string()));
    let report = crate::schema::value_report(Some(&validator), schema, &instance);
    (!report.is_empty()).then_some(report)
}
