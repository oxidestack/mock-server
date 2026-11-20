//! Example values for OpenAPI schemas: `org.mockserver.openapi.examples` (`ExampleBuilder`, the `Example` models,
//! `JsonNodeExampleSerializer`, `JsonExampleDeserializer`, `XmlExampleSerializer`), over swagger-parser's model so
//! the Java class tests (`instanceof EmailSchema`, …) and the typed example / default / enum values carry over.
//!
//! With realistic values on (`generateRealisticExampleValues` or `__generationOptions__.realisticValues`) the values
//! come from a fresh seeded `SampleDataGenerator` per example ([`sample_data`]); `pattern` and `format: time`
//! strings come from the process-wide one even when they are off, as upstream's JVM-wide generator.

mod sample_data;

pub use sample_data::{GenerationOptions, SampleDataGenerator};

use std::collections::{HashMap, HashSet};

use jackson::json::{JsonWriter, WriteFeatures};
use jackson::{BigDecimal, JavaObject, JsonGenerator};
use swagger_parser::java::JMap;
use swagger_parser::models::{AdditionalProperties, Schema, SchemaKind};

pub const SAMPLE_EMAIL: &str = "some_email@mockserver.com";
pub const SAMPLE_UUID: &str = "3fa85f64-5717-4562-b3fc-2c963f66afa6";
pub const SAMPLE_STRING: &str = "some_string_value";
pub const SAMPLE_BYTE: &str = "c29tZV9ieXRlX3ZhbHVl";
pub const SAMPLE_DATE: &str = "2018-11-13";
pub const SAMPLE_DATE_TIME: &str = "2018-11-13T20:20:39+00:00";

const ARRAY_ITEM_CAP: i32 = 5;
const PROPERTY_CAP: i32 = 10;

/// `ExampleBuilder.Direction`: which of `readOnly` / `writeOnly` properties are left out.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Request,
    Response,
}

#[derive(Clone, Debug)]
pub enum Value {
    /// `ObjectExample`: entries in insertion order; a `None` value serialises as nothing.
    Object(Vec<(String, Option<Example>)>),
    Array(Vec<Example>),
    String(String),
    Integer(i32),
    Long(i64),
    BigInteger(String),
    Float(f32),
    Double(f64),
    Decimal(BigDecimal),
    Boolean(bool),
}

/// `AbstractExample`: a value plus its XML naming.
#[derive(Clone, Debug)]
pub struct Example {
    pub value: Value,
    pub name: Option<String>,
    pub namespace: Option<String>,
    pub prefix: Option<String>,
    pub attribute: bool,
    pub wrapped: bool,
    pub wrapped_name: Option<String>,
}

impl Example {
    fn new(value: Value) -> Example {
        Example { value, name: None, namespace: None, prefix: None, attribute: false, wrapped: false, wrapped_name: None }
    }

    fn string(s: impl Into<String>) -> Example {
        Example::new(Value::String(s.into()))
    }

    fn object() -> Example {
        Example::new(Value::Object(Vec::new()))
    }

    /// `ObjectExample.put`: replaces an existing key in place.
    fn put(&mut self, key: &str, value: Option<Example>) {
        if let Value::Object(entries) = &mut self.value {
            match entries.iter_mut().find(|(k, _)| k == key) {
                Some(entry) => entry.1 = value,
                None => entries.push((key.to_string(), value)),
            }
        }
    }

    fn has_key(&self, key: &str) -> bool {
        matches!(&self.value, Value::Object(entries) if entries.iter().any(|(k, _)| k == key))
    }

    fn key_count(&self) -> i32 {
        match &self.value {
            Value::Object(entries) => entries.len() as i32,
            _ => 0,
        }
    }

    /// `getTypeName()`
    fn type_name(&self) -> &'static str {
        match &self.value {
            Value::Object(_) => "object",
            Value::Array(_) => "array",
            Value::String(_) => "string",
            Value::Integer(_) => "integer",
            Value::Long(_) => "long",
            Value::BigInteger(_) => "biginteger",
            Value::Float(_) => "float",
            Value::Double(_) => "double",
            Value::Decimal(_) => "decimal",
            Value::Boolean(_) => "boolean",
        }
    }

    /// `asString()` of a scalar.
    fn as_string(&self) -> String {
        match &self.value {
            Value::String(s) | Value::BigInteger(s) => s.clone(),
            Value::Integer(v) => v.to_string(),
            Value::Long(v) => v.to_string(),
            Value::Float(v) => java_compat::float_to_string(*v),
            Value::Double(v) => java_compat::double_to_string(*v),
            Value::Decimal(v) => v.to_java_string(),
            Value::Boolean(v) => v.to_string(),
            Value::Array(items) => items.iter().map(Example::as_string).collect::<Vec<_>>().join(","),
            Value::Object(_) => String::new(),
        }
    }
}

thread_local! {
    static STATIC_REALISTIC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Runs `f` with `realistic` as the static store's `generateRealisticExampleValues`
/// (`ConfigurationProperties.generateRealisticExampleValues()`), which [`synthesize_response`] reads: it is called
/// where no configuration is passed down (`Action::compile`).
pub fn with_static_realistic<R>(realistic: bool, f: impl FnOnce() -> R) -> R {
    let previous = STATIC_REALISTIC.with(|c| c.replace(realistic));
    let result = f();
    STATIC_REALISTIC.with(|c| c.set(previous));
    result
}

/// `ExampleBuilder.fromSchema(schema, definitions, generationOptions, direction, configuration)`: realistic values
/// when the options ask for them, else when `realistic_default` (the configuration's
/// `generateRealisticExampleValues`) is on, from a generator seeded with the options' seed or 42.
pub fn from_schema_with(
    schema: &Schema,
    definitions: Option<&JMap<Schema>>,
    options: Option<&GenerationOptions>,
    direction: Direction,
    realistic_default: bool,
) -> Option<Example> {
    let realistic = options.and_then(|o| o.realistic_values).unwrap_or(realistic_default);
    let generator = realistic.then(|| SampleDataGenerator::new(options.and_then(|o| o.seed).unwrap_or(42)));
    Builder { definitions, processed: HashMap::new(), started: HashSet::new(), direction, generator: generator.as_ref(), options }
        .example_from_property(None, Some(schema))
}

struct Builder<'a> {
    definitions: Option<&'a JMap<Schema>>,
    /// `processedModels` by `$ref` short name.
    processed: HashMap<String, Option<Example>>,
    /// `modelsStartedProcessing`
    started: HashSet<String>,
    direction: Direction,
    /// Realistic values on: the run's generator.
    generator: Option<&'a SampleDataGenerator>,
    options: Option<&'a GenerationOptions>,
}

impl Builder<'_> {
    fn example_from_property(&mut self, name: Option<String>, property: Option<&Schema>) -> Option<Example> {
        let property = property?;
        // a per-field override by leaf property name; an author-declared example still wins
        if let Some(value) = self.options.filter(|_| property.get_example().is_none()).and_then(|o| o.override_for(name.as_deref())) && let Some(mut example) = override_to_example(value) {
            if name.is_some() {
                example.name = name.clone();
            }
            return Some(example);
        }
        let mut name = name;
        let (mut namespace, mut prefix, mut attribute, mut wrapped) = (None, None, false, false);
        let mut has_xml = false;
        if let Some(xml) = property.read().xml.clone() {
            has_xml = true;
            name = xml.get_name();
            namespace = xml.get_namespace();
            prefix = xml.get_prefix();
            attribute = xml.get_attribute().unwrap_or(false);
            wrapped = xml.get_wrapped().unwrap_or(false);
        }
        let _ = has_xml;
        let example = property.get_example().map(|e| normalize_flattened_example(e, property));
        let kind = property.kind();
        let mut output: Option<Example> = if let Some(reference) = property.get_ref() {
            let short = reference.rsplit('/').next().unwrap_or(&reference).to_string();
            if self.started.contains(&short) && !self.processed.contains_key(&short) {
                return None;
            }
            self.started.insert(short.clone());
            if let Some(done) = self.processed.get(&short) {
                done.clone().or_else(|| self.already_processed(&short))
            } else if let Some(model) = self.definitions.and_then(|d| d.get(&short)) {
                let out = self.example_from_property(name.clone(), Some(&model));
                self.processed.insert(short, out.clone());
                out
            } else {
                None
            }
        } else {
            match kind {
                SchemaKind::Email => Some(Example::string(example_text(&example).unwrap_or_else(|| {
                    default_or_first_enum(property).unwrap_or_else(|| self.generator.map_or_else(|| SAMPLE_EMAIL.to_string(), |g| g.email()))
                }))),
                SchemaKind::Uuid => Some(Example::string(example_text(&example).unwrap_or_else(|| {
                    default_or_first_enum(property).unwrap_or_else(|| self.generator.map_or_else(|| SAMPLE_UUID.to_string(), |g| g.uuid()))
                }))),
                SchemaKind::ByteArray => Some(Example::string(
                    example_text(&example).unwrap_or_else(|| self.generator.map_or_else(|| SAMPLE_BYTE.to_string(), |g| g.byte_string())),
                )),
                SchemaKind::String => Some(match example_text(&example).or_else(|| default_or_first_enum(property)) {
                    Some(text) => Example::string(text),
                    None => self.constrained_string(property).unwrap_or_else(|| {
                        Example::string(match self.generator {
                            Some(g) => match property.read().format.as_deref() {
                                Some("uri" | "url") => g.uri(),
                                Some("hostname") => g.hostname(),
                                Some("ipv4") => g.ipv4(),
                                Some("ipv6") => g.ipv6(),
                                _ => g.string_with_constraints(property.read().min_length, property.read().max_length),
                            },
                            None => SAMPLE_STRING.to_string(),
                        })
                    }),
                }),
                SchemaKind::Password => Some(Example::string(example_text(&example).unwrap_or_else(|| {
                    default_or_first_enum(property).unwrap_or_else(|| self.generator.map_or_else(|| SAMPLE_STRING.to_string(), |g| g.password()))
                }))),
                SchemaKind::Integer => Some(integer_example(property, &example, self.generator)),
                SchemaKind::Number => Some(number_example(property, &example, self.generator)),
                SchemaKind::Boolean => Some(Example::new(Value::Boolean(match &example {
                    Some(e) => e.to_java_string() == "true",
                    None => match property.get_default() {
                        Some(JavaObject::Boolean(b)) => b,
                        _ => self.generator.is_none_or(|g| g.boolean()),
                    },
                }))),
                SchemaKind::Date => Some(Example::string(match &example {
                    Some(e) => date_text(e),
                    None => property
                        .get_enum()
                        .and_then(|e| e.get(0))
                        .map(|e| date_text(&e))
                        .unwrap_or_else(|| self.generator.map_or_else(|| SAMPLE_DATE.to_string(), |g| g.date_string())),
                })),
                SchemaKind::DateTime => Some(Example::string(match &example {
                    Some(e) => e.to_java_string(),
                    None => property
                        .get_enum()
                        .and_then(|e| e.get(0))
                        .map(|e| e.to_java_string())
                        .unwrap_or_else(|| self.generator.map_or_else(|| SAMPLE_DATE_TIME.to_string(), |g| g.date_time_string())),
                })),
                SchemaKind::Object => match &example {
                    Some(e) => Some(example_from_json(&e.to_java_string()).unwrap_or_else(Example::object)),
                    None => {
                        let mut out = Example::object();
                        out.name = property.read().name.clone();
                        match property.read().properties.clone() {
                            Some(properties) => {
                                for (key, inner) in properties.entries() {
                                    if self.excluded(&inner) {
                                        continue;
                                    }
                                    let value = self.example_from_property(Some(key.clone()), Some(&inner));
                                    out.put(&key, value);
                                }
                                Some(out)
                            }
                            None => None,
                        }
                    }
                },
                SchemaKind::Array => match &example {
                    Some(e) => Some(example_from_json(&e.to_java_string()).unwrap_or_else(|| Example::new(Value::Array(Vec::new())))),
                    None => self.array_items(property),
                },
                SchemaKind::Composed => self.composed(property),
                _ => {
                    let types: Vec<String> = property.get_types().map(|t| t.items()).unwrap_or_default();
                    if !types.is_empty() {
                        types.iter().find(|t| *t != "null").and_then(|t| self.for_type(t, property, &example))
                    } else if let Some(properties) = property.read().properties.clone() {
                        match &example {
                            Some(e) => Some(example_from_json(&e.to_java_string()).unwrap_or_else(Example::object)),
                            None => {
                                let mut out = Example::object();
                                for (key, inner) in properties.entries() {
                                    if self.excluded(&inner) {
                                        continue;
                                    }
                                    let value = self.example_from_property(Some(key.clone()), Some(&inner));
                                    out.put(&key, value);
                                }
                                Some(out)
                            }
                        }
                    } else {
                        None
                    }
                }
            }
        };
        match property.get_additional_properties() {
            Some(AdditionalProperties::Schema(inner)) => {
                let mut count = 3;
                if let Some(min) = property.read().min_properties {
                    let present = output.as_ref().map(Example::key_count).unwrap_or(0);
                    let needed = min - present;
                    if needed > count {
                        count = needed.min(PROPERTY_CAP);
                    }
                }
                for i in 1..=count {
                    if let Some(mut inner_example) = self.example_from_property(inner.get_type(), Some(&inner)) {
                        let out = output.get_or_insert_with(Example::object);
                        let key = format!("additionalProp{i}");
                        if inner_example.name.is_none() {
                            inner_example.name = Some(key.clone());
                        }
                        if matches!(out.value, Value::Object(_)) && !out.has_key(&key) {
                            out.put(&key, Some(inner_example));
                        }
                    }
                }
            }
            Some(AdditionalProperties::Bool(_)) if output.is_none() => output = Some(Example::object()),
            _ => {}
        }
        if let Some(out) = output.as_mut() {
            out.attribute = attribute;
            if wrapped {
                if name.is_some() {
                    out.wrapped_name = name.clone();
                }
            } else if name.is_some() {
                out.name = name.clone();
            }
            out.namespace = namespace.take();
            out.prefix = prefix.take();
            out.wrapped = wrapped;
        }
        output
    }

    /// `constrainedStringExample`: a `pattern` (when RgxGen can generate it), else the `time` format, from the run's
    /// generator or the process-wide one.
    fn constrained_string(&self, property: &Schema) -> Option<Example> {
        let generator = self.generator.unwrap_or_else(|| &*sample_data::STATIC_GENERATOR);
        let (pattern, format) = {
            let d = property.read();
            (d.pattern.clone(), d.format.clone())
        };
        if let Some(generated) = pattern.filter(|p| !p.trim().is_empty()).and_then(|p| generator.regexify(&p)) {
            return Some(Example::string(generated));
        }
        (format.as_deref() == Some("time")).then(|| Example::string(generator.time_string()))
    }

    fn excluded(&self, property: &Schema) -> bool {
        match self.direction {
            Direction::Request => property.read().read_only == Some(true),
            Direction::Response => property.read().write_only == Some(true),
        }
    }

    /// `alreadyProcessedRefExample`
    fn already_processed(&self, name: &str) -> Option<Example> {
        let model = self.definitions.and_then(|d| d.get(name))?;
        let resolved = model.get_type().or_else(|| model.get_types().and_then(|t| t.items().into_iter().find(|t| t != "null")));
        match resolved.as_deref() {
            Some("object") => Some(Example::object()),
            Some("string") => Some(Example::string("")),
            Some("integer") => Some(Example::new(Value::Integer(0))),
            _ => None,
        }
    }

    fn array_items(&mut self, property: &Schema) -> Option<Example> {
        let inner = property.read().items.clone()?;
        let count = array_item_count(property);
        let mut items = Vec::new();
        let mut built = count == 0;
        for _ in 0..count {
            if let Some(item) = self.example_from_property(None, Some(&inner)) {
                items.push(item);
                built = true;
            }
        }
        built.then(|| {
            let mut out = Example::new(Value::Array(items));
            out.name = property.read().name.clone();
            out
        })
    }

    fn composed(&mut self, property: &Schema) -> Option<Example> {
        let mut output = None;
        let d = property.read();
        let (all_of, any_of, one_of, own) = (d.all_of.clone(), d.any_of.clone(), d.one_of.clone(), d.properties.clone());
        drop(d);
        if let Some(all_of) = all_of {
            let inner: Vec<Example> = all_of.to_vec().iter().filter_map(|m| self.example_from_property(m.get_type(), Some(m))).collect();
            let has_own = own.as_ref().is_some_and(|p| !p.is_empty());
            let any_object = inner.iter().any(|e| matches!(e.value, Value::Object(_)));
            if !inner.is_empty() && !has_own && !any_object {
                output = inner.into_iter().next();
            } else {
                let mut out = Example::object();
                if let Some(own) = own {
                    for (key, value) in own.entries() {
                        if self.excluded(&value) {
                            continue;
                        }
                        if let Some(example) = self.example_from_property(Some(key.clone()), Some(&value)) {
                            out.put(&key, Some(example));
                        }
                    }
                }
                for example in inner {
                    if let Value::Object(entries) = example.value {
                        for (k, v) in entries {
                            out.put(&k, v);
                        }
                    }
                }
                output = Some(out);
            }
        }
        for members in [any_of, one_of].into_iter().flatten() {
            let members = members.to_vec();
            output = self.discriminated(property, &members).or_else(|| {
                members.iter().find_map(|m| self.example_from_property(property.get_type(), Some(m)))
            });
        }
        output
    }

    /// `discriminatedExample`
    fn discriminated(&mut self, property: &Schema, members: &[Schema]) -> Option<Example> {
        let discriminator = property.get_discriminator()?;
        let name = discriminator.get_property_name()?;
        if members.is_empty() {
            return None;
        }
        let (chosen, value) = match discriminator.get_mapping().filter(|m| !m.is_empty()) {
            Some(mapping) => {
                let (value, reference) = mapping.entries().into_iter().next()?;
                let schema = Schema::new();
                schema.set_ref(reference);
                (schema, Some(value))
            }
            None => (members[0].clone(), members[0].get_ref().map(|r| r.rsplit('/').next().unwrap_or(&r).to_string())),
        };
        let mut inner = self.example_from_property(None, Some(&chosen));
        if let (Some(example), Some(value)) = (inner.as_mut(), value) && matches!(example.value, Value::Object(_)) {
            example.put(&name, Some(Example::string(value)));
        }
        inner
    }

    /// `generateExampleForType` (OpenAPI 3.1 `type` arrays).
    fn for_type(&mut self, t: &str, property: &Schema, example: &Option<JavaObject>) -> Option<Example> {
        match t {
            "string" => Some(match example_text(example).or_else(|| default_or_first_enum(property)) {
                Some(text) => Example::string(text),
                None => self.constrained_string(property).unwrap_or_else(|| {
                    let format = property.read().format.clone();
                    Example::string(match (self.generator, format.as_deref()) {
                        (None, Some("date")) => SAMPLE_DATE.to_string(),
                        (None, Some("date-time")) => SAMPLE_DATE_TIME.to_string(),
                        (None, Some("email")) => SAMPLE_EMAIL.to_string(),
                        (None, Some("uuid")) => SAMPLE_UUID.to_string(),
                        (None, Some("byte")) => SAMPLE_BYTE.to_string(),
                        (None, _) => SAMPLE_STRING.to_string(),
                        (Some(g), Some("date")) => g.date_string(),
                        (Some(g), Some("date-time")) => g.date_time_string(),
                        (Some(g), Some("email")) => g.email(),
                        (Some(g), Some("uuid")) => g.uuid(),
                        (Some(g), Some("byte")) => g.byte_string(),
                        (Some(g), Some("uri" | "url")) => g.uri(),
                        (Some(g), Some("password")) => g.password(),
                        (Some(g), _) => g.string_with_constraints(property.read().min_length, property.read().max_length),
                    })
                }),
            }),
            "integer" => Some(integer_example(property, example, self.generator)),
            "number" => Some(number_example(property, example, self.generator)),
            "boolean" => Some(Example::new(Value::Boolean(match example {
                Some(e) => e.to_java_string() == "true",
                None => match property.get_default() {
                    Some(JavaObject::Boolean(b)) => b,
                    _ => self.generator.is_none_or(|g| g.boolean()),
                },
            }))),
            "object" => match example {
                Some(e) => Some(example_from_json(&e.to_java_string()).unwrap_or_else(Example::object)),
                None => {
                    let mut out = Example::object();
                    out.name = property.read().name.clone();
                    if let Some(properties) = property.read().properties.clone() {
                        for (key, inner) in properties.entries() {
                            if self.excluded(&inner) {
                                continue;
                            }
                            let value = self.example_from_property(Some(key.clone()), Some(&inner));
                            out.put(&key, value);
                        }
                    }
                    Some(out)
                }
            },
            "array" => match example {
                Some(e) => Some(example_from_json(&e.to_java_string()).unwrap_or_else(|| Example::new(Value::Array(Vec::new())))),
                None => self.array_items(property).or_else(|| Some(Example::new(Value::Array(Vec::new())))),
            },
            _ => None,
        }
    }
}

/// `normalizeFlattenedExample`: a one-element collection example of a scalar schema is unwrapped.
pub fn normalize_flattened_example(example: JavaObject, schema: &Schema) -> JavaObject {
    let scalar = schema
        .get_type()
        .or_else(|| schema.get_types().and_then(|t| t.items().into_iter().find(|t| t != "null")))
        .is_some_and(|t| matches!(t.as_str(), "string" | "integer" | "number" | "boolean"));
    match &example {
        JavaObject::List(items) | JavaObject::Set(items) if items.len() == 1 && scalar => items[0].clone(),
        _ => example,
    }
}

fn example_text(example: &Option<JavaObject>) -> Option<String> {
    example.as_ref().map(JavaObject::to_java_string)
}

fn default_or_first_enum(property: &Schema) -> Option<String> {
    property
        .get_default()
        .filter(|d| !d.is_null())
        .or_else(|| property.get_enum().and_then(|e| e.get(0)))
        .map(|v| v.to_java_string())
}

/// `new SimpleDateFormat("yyyy-MM-dd")` in UTC of a `Date` example (other values as written).
fn date_text(value: &JavaObject) -> String {
    match value {
        JavaObject::Date(ms) => {
            let days = ms.div_euclid(86_400_000);
            let date = chrono::NaiveDate::from_ymd_opt(1970, 1, 1).expect("epoch") + chrono::Duration::days(days);
            date.format("%Y-%m-%d").to_string()
        }
        other => other.to_java_string(),
    }
}

fn integer_example(property: &Schema, example: &Option<JavaObject>, generator: Option<&SampleDataGenerator>) -> Example {
    let format = property.read().format.clone();
    if let Some(text) = example_text(example) {
        let parsed = match format.as_deref() {
            Some("int32") => text.parse::<i32>().ok().map(Value::Integer),
            Some("int64") => text.parse::<i64>().ok().map(Value::Long),
            _ => text
                .parse::<i32>()
                .map(Value::Integer)
                .or_else(|_| text.parse::<i64>().map(Value::Long))
                .ok()
                .or_else(|| text.parse::<num_bigint_lite::Big>().ok().map(|b| Value::BigInteger(b.0))),
        };
        if let Some(v) = parsed {
            return Example::new(v);
        }
    }
    let default = property.get_default().filter(|d| !d.is_null()).or_else(|| property.get_enum().and_then(|e| e.get(0)));
    let default_long = default.as_ref().and_then(java_number_long);
    let (min, max) = (effective_minimum(property, 1.0), effective_maximum(property, 1.0));
    match (format.as_deref(), generator) {
        (Some("int64"), Some(g)) => Example::new(Value::Long(default_long.unwrap_or_else(|| g.long_value(min, max)))),
        (Some("int64"), None) => Example::new(Value::Long(default_long.unwrap_or_else(|| clamp_long(0, min, max)))),
        (_, Some(g)) => Example::new(Value::Integer(default_long.map(|v| v as i32).unwrap_or_else(|| g.integer(min, max)))),
        (_, None) => Example::new(Value::Integer(
            default_long.map(|v| v as i32).unwrap_or_else(|| clamp_long(0, min, max).clamp(i32::MIN as i64, i32::MAX as i64) as i32),
        )),
    }
}

fn number_example(property: &Schema, example: &Option<JavaObject>, generator: Option<&SampleDataGenerator>) -> Example {
    let format = property.read().format.clone();
    if let Some(text) = example_text(example) {
        let parsed = match format.as_deref() {
            Some("double") => text.parse::<f64>().ok().map(Value::Double),
            Some("float") => text.parse::<f32>().ok().map(Value::Float),
            _ => BigDecimal::parse(&text).ok().map(Value::Decimal),
        };
        if let Some(v) = parsed {
            return Example::new(v);
        }
    }
    let default = property.get_default().filter(|d| !d.is_null()).or_else(|| property.get_enum().and_then(|e| e.get(0)));
    let default_decimal = default.as_ref().and_then(|d| BigDecimal::parse(&d.to_java_string()).ok());
    let (min, max) = (effective_minimum(property, 0.01), effective_maximum(property, 0.01));
    let clamp = |fallback: f64| -> f64 {
        let mut v = fallback;
        if let Some(min) = min.filter(|m| v < *m) {
            v = min;
        }
        if let Some(max) = max.filter(|m| v > *m) {
            v = max;
        }
        v
    };
    if let (Some(g), None) = (generator, &default_decimal) {
        return match format.as_deref() {
            Some("double") => Example::new(Value::Double(g.double_value(min, max))),
            Some("float") => Example::new(Value::Float(g.float_value(min, max))),
            _ => Example::new(Value::Decimal(g.decimal(min, max))),
        };
    }
    match format.as_deref() {
        Some("double") => Example::new(Value::Double(default_decimal.map(|d| d.to_f64()).unwrap_or_else(|| clamp(1.1)))),
        Some("float") => Example::new(Value::Float(default_decimal.map(|d| d.to_f64() as f32).unwrap_or_else(|| clamp(1.1_f32 as f64) as f32))),
        _ => Example::new(Value::Decimal(default_decimal.unwrap_or_else(|| {
            let v = clamp(1.5);
            if v == 1.5 { BigDecimal::parse("1.5").expect("literal") } else { BigDecimal::value_of_f64(v) }
        }))),
    }
}

fn java_number_long(v: &JavaObject) -> Option<i64> {
    match v {
        JavaObject::Short(n) => Some(*n as i64),
        JavaObject::Integer(n) => Some(*n as i64),
        JavaObject::Long(n) => Some(*n),
        JavaObject::BigDecimal(d) => Some(d.to_i64_wrapping()),
        other => other.to_java_string().parse().ok(),
    }
}

/// `effectiveMinimum`: `minimum`, moved up by `step` when exclusive (3.0 flag or 3.1 value).
fn effective_minimum(property: &Schema, step: f64) -> Option<f64> {
    let d = property.read();
    if let Some(v) = &d.exclusive_minimum_value {
        return Some(v.to_f64() + step);
    }
    let min = d.minimum.as_ref().map(BigDecimal::to_f64)?;
    Some(if d.exclusive_minimum == Some(true) { min + step } else { min })
}

fn effective_maximum(property: &Schema, step: f64) -> Option<f64> {
    let d = property.read();
    if let Some(v) = &d.exclusive_maximum_value {
        return Some(v.to_f64() - step);
    }
    let max = d.maximum.as_ref().map(BigDecimal::to_f64)?;
    Some(if d.exclusive_maximum == Some(true) { max - step } else { max })
}

fn clamp_long(fallback: i64, min: Option<f64>, max: Option<f64>) -> i64 {
    let mut v = fallback;
    if let Some(min) = min.map(|m| m.max(i64::MIN as f64).min(i64::MAX as f64) as i64).filter(|m| v < *m) {
        v = min;
    }
    if let Some(max) = max.map(|m| m.max(i64::MIN as f64).min(i64::MAX as f64) as i64).filter(|m| v > *m) {
        v = max;
    }
    v
}

/// `arrayItemCount`: `minItems` (capped), at most `maxItems`, else 1.
fn array_item_count(property: &Schema) -> i32 {
    let d = property.read();
    let mut count = 1;
    if let Some(min) = d.min_items.filter(|m| *m > 1) {
        count = min.min(ARRAY_ITEM_CAP);
    }
    if let Some(max) = d.max_items.filter(|m| *m < count) {
        count = max.max(0);
    }
    count
}

/// `overrideToExample`: a `fieldOverrides` value as Jackson read it into a `Map<String, Object>` (an `Integer`,
/// `Long`, `BigInteger` or `Double` number), as the example of the matching type; anything else as its `toString()`.
fn override_to_example(value: &serde_json::Value) -> Option<Example> {
    use serde_json::Value as J;
    Some(Example::new(match value {
        J::Null => return None,
        J::Bool(b) => Value::Boolean(*b),
        J::Number(n) => match n.as_i64() {
            Some(v) if i32::try_from(v).is_ok() => Value::Integer(v as i32),
            Some(v) => Value::Long(v),
            None => Value::Double(n.as_f64().unwrap_or_else(|| n.to_string().parse().unwrap_or(f64::NAN))),
        },
        J::String(s) => Value::String(s.clone()),
        other => Value::String(java_map_string(other)),
    }))
}

/// `Object.toString()` of what Jackson built for an override: a `LinkedHashMap`, an `Object[]` or a scalar.
fn java_map_string(value: &serde_json::Value) -> String {
    use serde_json::Value as J;
    match value {
        J::Null => "null".into(),
        J::String(s) => s.clone(),
        J::Number(n) => match n.as_i64() {
            Some(v) => v.to_string(),
            None => java_compat::double_to_string(n.as_f64().unwrap_or(f64::NAN)),
        },
        J::Bool(b) => b.to_string(),
        // an `Object[]`: its identity hash is the JVM's own
        J::Array(items) => format!("[Ljava.lang.Object;@{:x}", items as *const _ as usize as u32),
        J::Object(map) => format!("{{{}}}", map.iter().map(|(k, v)| format!("{k}={}", java_map_string(v))).collect::<Vec<_>>().join(", ")),
    }
}

/// Minimal big-integer text holder: `new BigInteger(text)` accepts an optional sign and digits.
mod num_bigint_lite {
    pub struct Big(pub String);

    impl std::str::FromStr for Big {
        type Err = ();
        fn from_str(s: &str) -> Result<Big, ()> {
            let digits = s.strip_prefix(['-', '+']).unwrap_or(s);
            if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
                return Err(());
            }
            let sign = if s.starts_with('-') { "-" } else { "" };
            let trimmed = digits.trim_start_matches('0');
            Ok(Big(format!("{sign}{}", if trimmed.is_empty() { "0" } else { trimmed })))
        }
    }
}

/// `Json.mapper().readValue(text, ObjectExample.class)` through `JsonExampleDeserializer`; `None` when `text` is
/// not JSON (a `Map` example's `toString()`), which upstream turns into an empty example.
fn example_from_json(text: &str) -> Option<Example> {
    let node = jackson::json::read_tree(text, Default::default()).ok()?;
    Some(from_node(&node))
}

fn from_node(node: &jackson::JsonNode) -> Example {
    use jackson::JsonNode;
    match node {
        JsonNode::Object(fields) => {
            let mut out = Example::object();
            for (k, v) in fields.iter() {
                out.put(k, Some(from_node(v)));
            }
            out
        }
        JsonNode::Array(items) => Example::new(Value::Array(items.iter().map(from_node).collect())),
        JsonNode::Double(v) => Example::new(Value::Double(*v)),
        JsonNode::Int(v) => Example::new(Value::Integer(*v)),
        JsonNode::Short(v) => Example::new(Value::Integer(*v as i32)),
        JsonNode::Float(v) => Example::new(Value::Float(*v)),
        JsonNode::BigInteger(v) => Example::new(Value::BigInteger(v.to_string())),
        JsonNode::Decimal(v) => Example::new(Value::Decimal((**v).clone())),
        JsonNode::Long(v) => Example::new(Value::Long(*v)),
        JsonNode::Boolean(v) => Example::new(Value::Boolean(*v)),
        other => Example::string(other.as_text()),
    }
}

/// `JsonSchemaResponseSynthesizer.synthesizeResponse`: an inline JSON schema mounted as the component
/// `GeneratedResponse` of a minimal OpenAPI 3.0 document, parsed like a spec, and its `RESPONSE` example written
/// compactly (a string example as a JSON string); realistic per the static store ([`with_static_realistic`]). `None` for a blank schema or no example; `Err` when the schema
/// cannot be read or parsed (upstream logs a warning and leaves the body unset).
pub fn synthesize_response(json_schema: &str) -> Result<Option<String>, String> {
    if json_schema.trim().is_empty() {
        return Ok(None);
    }
    let schema = crate::json::parse_lenient(json_schema.as_bytes()).map_err(|e| e.to_string())?;
    let document = serde_json::json!({
        "openapi": "3.0.0",
        "info": {"title": "inline json schema response generation", "version": "1.0.0"},
        "paths": {},
        "components": {"schemas": {"GeneratedResponse": schema}},
    });
    // 9.1.0: parsed as an inline JSON Schema, whose problems are a DEBUG, not a spec's WARN.
    let model = crate::openapi::load_spec_as(&document.to_string(), true)?.openapi;
    let Some(schemas) = model.get_components().and_then(|c| c.get_schemas()) else { return Ok(None) };
    let Some(root) = schemas.get("GeneratedResponse") else { return Ok(None) };
    let realistic = STATIC_REALISTIC.with(std::cell::Cell::get);
    let Some(example) = from_schema_with(&root, Some(&schemas), None, Direction::Response, realistic) else { return Ok(None) };
    let mut g = JsonWriter::new(WriteFeatures::default());
    let _ = match &example.value {
        Value::String(s) => g.write_string(s),
        _ => serialize(&mut g, &example),
    };
    Ok(Some(g.into_string()))
}

/// `OBJECT_WRITER.writeValueAsString(example)`: `JsonNodeExampleSerializer` with the default pretty printer.
pub fn to_json(example: &Example) -> String {
    let mut g = JsonWriter::new(WriteFeatures { pretty: true, ..WriteFeatures::default() });
    let _ = serialize(&mut g, example);
    g.into_string()
}

/// A plain Java value (a spec's own example) the same way.
pub fn java_object_to_json(value: &JavaObject) -> String {
    let mut g = JsonWriter::new(WriteFeatures { pretty: true, ..WriteFeatures::default() });
    let _ = jackson::convert::write_object(&mut g, value, &jackson::convert::SerConfig::internal_node_mapper());
    g.into_string()
}

type R = Result<(), jackson::JacksonError>;

fn serialize(g: &mut dyn JsonGenerator, value: &Example) -> R {
    match &value.value {
        Value::Object(_) => {
            g.write_start_object()?;
            write_to(g, value)?;
            g.write_end_object()
        }
        Value::Array(items) => {
            g.write_start_array()?;
            for item in items {
                let object = matches!(item.value, Value::Object(_));
                if object {
                    g.write_start_object()?;
                }
                write_to(g, item)?;
                if object {
                    g.write_end_object()?;
                }
            }
            g.write_end_array()
        }
        _ => write_to(g, value),
    }
}

fn write_to(g: &mut dyn JsonGenerator, value: &Example) -> R {
    match &value.value {
        Value::Object(entries) => {
            for (key, v) in entries {
                if let Some(v) = v {
                    write_value(g, Some(key), v)?;
                }
            }
            Ok(())
        }
        Value::Array(items) => {
            g.write_start_array()?;
            for item in items {
                serialize(g, item)?;
            }
            g.write_end_array()
        }
        _ => write_value(g, None, value),
    }
}

fn write_value(g: &mut dyn JsonGenerator, field: Option<&str>, value: &Example) -> R {
    if let Value::Array(items) = &value.value {
        if let Some(f) = field {
            g.write_field_name(f)?;
        }
        g.write_start_array()?;
        for item in items {
            if matches!(item.value, Value::Object(_)) {
                g.write_start_object()?;
                write_to(g, item)?;
                g.write_end_object()?;
            } else {
                write_to(g, item)?;
            }
        }
        return g.write_end_array();
    }
    if let Value::Object(_) = &value.value {
        return match field {
            Some(f) => {
                g.write_field_name(f)?;
                serialize(g, value)
            }
            None => Ok(()),
        };
    }
    if let Some(f) = field {
        g.write_field_name(f)?;
    }
    match &value.value {
        Value::Boolean(v) => g.write_boolean(*v),
        Value::Decimal(v) => g.write_number_big_decimal(v),
        Value::BigInteger(v) => match v.parse::<num_bigint::BigInt>() {
            Ok(b) => g.write_number_big_integer(&b),
            Err(_) => g.write_string(v),
        },
        Value::Double(v) => g.write_number_f64(*v),
        Value::Float(v) => g.write_number_f32(*v),
        Value::Integer(v) => g.write_number_i32(*v),
        Value::Long(v) => g.write_number_i64(*v),
        Value::String(s) => g.write_string(s),
        Value::Object(_) | Value::Array(_) => Ok(()),
    }
}

/// `XmlExampleSerializer.serialize`: a StAX document without whitespace.
pub fn to_xml(example: &Example) -> String {
    let mut out = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
    let mut example = example.clone();
    write_xml(&mut out, &mut example, 1);
    out
}

fn write_xml(out: &mut String, o: &mut Example, depth: usize) {
    match &mut o.value {
        Value::Object(entries) => {
            let name = o.name.clone().or_else(|| (depth == 1).then(|| "object".to_string())).unwrap_or_else(|| "AnonymousModel".to_string());
            let tag = start_element(out, o.prefix.as_deref(), &name, o.namespace.as_deref());
            // attributes first (still inside the start tag), then child elements
            let mut attributes = String::new();
            let mut children = String::new();
            for (key, value) in entries.iter_mut() {
                let Some(example) = value.as_mut() else { continue };
                let saved = example.name.clone();
                if saved.is_none() {
                    example.name = Some(key.clone());
                }
                if example.attribute {
                    let value = strip_illegal(&example.as_string());
                    attributes.push_str(&format!(" {}=\"{}\"", sanitize_name(example.name.as_deref().unwrap_or(key)), escape(&value, true)));
                } else {
                    write_xml(&mut children, example, depth + 1);
                }
                example.name = saved;
            }
            out.push_str(&attributes);
            out.push('>');
            out.push_str(&children);
            out.push_str(&format!("</{tag}>"));
        }
        Value::Array(items) => {
            let wrapper = if o.wrapped { o.wrapped_name.clone().or_else(|| o.name.clone()) } else { None };
            let mut tag = None;
            if let Some(w) = &wrapper {
                tag = Some(start_element(out, o.prefix.as_deref(), w, o.namespace.as_deref()));
                out.push('>');
            }
            let (name, ns, prefix) = (o.name.clone(), o.namespace.clone(), o.prefix.clone());
            for item in items.iter_mut() {
                let applied = item.name.is_none();
                let (saved_ns, saved_prefix) = (item.namespace.clone(), item.prefix.clone());
                if applied {
                    item.name = Some(name.clone().unwrap_or_else(|| item.type_name().to_string()));
                    if item.namespace.is_none() {
                        item.namespace = ns.clone();
                    }
                    if item.prefix.is_none() {
                        item.prefix = prefix.clone();
                    }
                }
                write_xml(out, item, depth + 1);
                if applied {
                    item.name = None;
                    item.namespace = saved_ns;
                    item.prefix = saved_prefix;
                }
            }
            if let Some(tag) = tag {
                out.push_str(&format!("</{tag}>"));
            }
        }
        _ => {
            let name = o.name.clone().or_else(|| (depth == 1).then(|| o.type_name().to_string()));
            let text = escape(&strip_illegal(&o.as_string()), false);
            match name {
                None => out.push_str(&text),
                Some(name) => {
                    let tag = start_element(out, o.prefix.as_deref(), &name, o.namespace.as_deref());
                    out.push('>');
                    out.push_str(&text);
                    out.push_str(&format!("</{tag}>"));
                }
            }
        }
    }
}

/// Writes `<name` (with its namespace declaration), leaving the tag open; returns the qualified name.
fn start_element(out: &mut String, prefix: Option<&str>, name: &str, namespace: Option<&str>) -> String {
    let name = sanitize_name(name);
    match (namespace, prefix.filter(|p| !p.is_empty())) {
        (None, _) => {
            out.push_str(&format!("<{name}"));
            name
        }
        (Some(ns), Some(p)) => {
            out.push_str(&format!("<{p}:{name} xmlns:{p}=\"{}\"", escape(ns, true)));
            format!("{p}:{name}")
        }
        (Some(ns), None) => {
            out.push_str(&format!("<{name} xmlns=\"{}\"", escape(ns, true)));
            name
        }
    }
}

fn escape(s: &str, attribute: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' if attribute => out.push_str("&quot;"),
            c => out.push(c),
        }
    }
    out
}

/// `stripIllegalXmlChars`
fn strip_illegal(s: &str) -> String {
    s.chars()
        .filter(|c| {
            let c = *c as u32;
            c == 0x9 || c == 0xA || c == 0xD || (0x20..=0xD7FF).contains(&c) || (0xE000..=0xFFFD).contains(&c) || (0x10000..=0x10FFFF).contains(&c)
        })
        .collect()
}

/// `sanitiseXmlName`
fn sanitize_name(name: &str) -> String {
    fn start(c: char) -> bool {
        let u = c as u32;
        c == '_'
            || c.is_ascii_alphabetic()
            || (0xC0..=0xD6).contains(&u)
            || (0xD8..=0xF6).contains(&u)
            || (0xF8..=0x2FF).contains(&u)
            || (0x370..=0x37D).contains(&u)
            || (0x37F..=0x1FFF).contains(&u)
            || (0x200C..=0x200D).contains(&u)
            || (0x2070..=0x218F).contains(&u)
            || (0x2C00..=0x2FEF).contains(&u)
            || (0x3001..=0xD7FF).contains(&u)
            || (0xF900..=0xFDCF).contains(&u)
            || (0xFDF0..=0xFFFD).contains(&u)
    }
    fn part(c: char) -> bool {
        let u = c as u32;
        start(c) || c == '-' || c == '.' || c.is_ascii_digit() || u == 0xB7 || (0x300..=0x36F).contains(&u) || (0x203F..=0x2040).contains(&u)
    }
    let mut chars = name.chars();
    let Some(first) = chars.next() else { return name.to_string() };
    if start(first) && name.chars().skip(1).all(part) {
        return name.to_string();
    }
    let mut out = String::new();
    if start(first) {
        out.push(first);
    } else if part(first) {
        out.push('_');
        out.push(first);
    } else {
        out.push('_');
    }
    out.extend(chars.map(|c| if part(c) { c } else { '_' }));
    out
}
