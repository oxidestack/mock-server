//! `MessageExampleGeneratorTest` and `MessageExampleGeneratorSchemaAwareTest` (mockserver-async): the example a
//! channel or message publishes, from its first example or synthesised from its payload schema.

use mock_server::asyncapi::spec::{Channel, Message, Spec, examples};
use serde_json::{Value, json};

fn read(payload: &str) -> Value {
    serde_json::from_str(payload).expect("the example is JSON")
}

/// `generateExamples(spec).get(name)`.
fn example_of(generated: &[(String, String)], name: &str) -> Option<Value> {
    generated.iter().find(|(n, _)| n == name).map(|(_, p)| read(p))
}

fn message(name: &str, schema: Option<Value>, examples: Vec<Value>) -> Message {
    Message { name: Some(name.into()), payload_schema: schema, examples, kafka_key: None, correlation_id_location: None }
}

/// `generateExample(new AsyncApiChannel("test", List.of(), schema))`, read back.
fn synthesised(schema: Value) -> Value {
    read(&Channel::new("test", Vec::new(), Some(schema)).example())
}

// ---- MessageExampleGeneratorTest ----

#[test]
fn should_use_explicit_example_when_present() {
    let example = json!({"userId": "abc123", "email": "user@test.com"});
    let schema = json!({"type": "object", "properties": {"userId": {"type": "string"}}});
    let spec = Spec::new("2.6.0", "Test", vec![Channel::new("users", vec![example], Some(schema))]);
    let result = example_of(&examples(&spec), "users").expect("an example for users");
    assert_eq!(result["userId"], json!("abc123"));
    assert_eq!(result["email"], json!("user@test.com"));
}

#[test]
fn should_synthesize_from_schema_when_no_example() {
    let schema = json!({"type": "object", "properties": {
        "name": {"type": "string"},
        "age": {"type": "integer"},
        "active": {"type": "boolean"},
        "score": {"type": "number"}
    }});
    let spec = Spec::new("2.6.0", "Test", vec![Channel::new("profiles", Vec::new(), Some(schema))]);
    let generated = examples(&spec);
    let result = example_of(&generated, "profiles").expect("an example for profiles");
    assert_eq!(result["name"], json!("string"));
    assert_eq!(result["age"].as_i64(), Some(0));
    assert_eq!(result["active"], json!(false));
    assert_eq!(result["score"].as_f64(), Some(0.0));
    // Jackson writes the synthesised `double` as `0.0`.
    assert_eq!(generated[0].1, r#"{"name":"string","age":0,"active":false,"score":0.0}"#);
}

#[test]
fn should_synthesize_array_type() {
    let channel = Channel::new("tags", Vec::new(), Some(json!({"type": "array", "items": {"type": "string"}})));
    let result = read(&channel.example());
    assert_eq!(result, json!(["string"]));
}

#[test]
fn should_fallback_to_empty_object_when_no_schema_and_no_example() {
    assert_eq!(Channel::new("empty", Vec::new(), None).example(), "{}");
}

#[test]
fn should_synthesize_nested_object() {
    let schema = json!({"type": "object", "properties": {
        "address": {"type": "object", "properties": {
            "street": {"type": "string"},
            "zip": {"type": "integer"}
        }}
    }});
    let result = read(&Channel::new("users", Vec::new(), Some(schema)).example());
    assert!(result.get("address").is_some());
    assert_eq!(result["address"]["street"], json!("string"));
    assert_eq!(result["address"]["zip"].as_i64(), Some(0));
}

#[test]
fn should_generate_examples_for_multiple_channels() {
    let spec = Spec::new("2.6.0", "Multi", vec![Channel::new("ch1", vec![json!({"a": 1})], None), Channel::new("ch2", vec![json!({"b": 2})], None)]);
    let generated = examples(&spec);
    assert_eq!(example_of(&generated, "ch1").expect("ch1")["a"].as_i64(), Some(1));
    assert_eq!(example_of(&generated, "ch2").expect("ch2")["b"].as_i64(), Some(2));
}

#[test]
fn should_handle_schema_without_explicit_type() {
    // Schema with properties but no "type" field — should infer object
    let result = read(&Channel::new("inferred", Vec::new(), Some(json!({"properties": {"name": {"type": "string"}}}))).example());
    assert_eq!(result["name"], json!("string"));
}

#[test]
fn should_generate_example_from_message_with_explicit_example() {
    let result = read(&message("testMsg", None, vec![json!({"userId": "abc123"})]).example());
    assert_eq!(result["userId"], json!("abc123"));
}

#[test]
fn should_generate_example_from_message_with_schema() {
    let schema = json!({"type": "object", "properties": {"name": {"type": "string"}}});
    let result = read(&message("testMsg", Some(schema), Vec::new()).example());
    assert_eq!(result["name"], json!("string"));
}

#[test]
fn should_generate_empty_object_from_message_with_no_schema_or_example() {
    assert_eq!(message("empty", None, Vec::new()).example(), "{}");
}

#[test]
fn should_prefer_explicit_example_over_schema_for_message() {
    let schema = json!({"type": "object", "properties": {"orderId": {"type": "integer"}}});
    let result = read(&message("msg", Some(schema), vec![json!({"orderId": 42})]).example());
    assert_eq!(result["orderId"].as_i64(), Some(42));
}

// ---- MessageExampleGeneratorSchemaAwareTest ----

#[test]
fn should_use_enum_first_value() {
    let result = synthesised(json!({"type": "object", "properties": {"status": {"type": "string", "enum": ["active", "inactive"]}}}));
    assert_eq!(result["status"], json!("active"));
}

#[test]
fn should_use_default_value() {
    let result = synthesised(json!({"type": "object", "properties": {"count": {"type": "integer", "default": 42}}}));
    assert_eq!(result["count"].as_i64(), Some(42));
}

#[test]
fn should_use_const_value() {
    let result = synthesised(json!({"type": "object", "properties": {"version": {"type": "string", "const": "v2"}}}));
    assert_eq!(result["version"], json!("v2"));
}

#[test]
fn should_respect_minimum() {
    let result = synthesised(json!({"type": "object", "properties": {"score": {"type": "integer", "minimum": 10}}}));
    assert!(result["score"].as_i64().is_some_and(|s| s >= 10), "{result}");
}

#[test]
fn should_respect_exclusive_minimum() {
    let result = synthesised(json!({"type": "object", "properties": {"score": {"type": "integer", "exclusiveMinimum": 0}}}));
    assert!(result["score"].as_i64().is_some_and(|s| s > 0), "{result}");
}

#[test]
fn should_synthesize_date_time_format() {
    let result = synthesised(json!({"type": "object", "properties": {"createdAt": {"type": "string", "format": "date-time"}}}));
    assert!(result["createdAt"].as_str().is_some_and(|s| s.contains('T')), "{result}");
}

#[test]
fn should_synthesize_email_format() {
    let result = synthesised(json!({"type": "object", "properties": {"email": {"type": "string", "format": "email"}}}));
    assert!(result["email"].as_str().is_some_and(|s| s.contains('@')), "{result}");
}

#[test]
fn should_synthesize_uuid_format() {
    let result = synthesised(json!({"type": "object", "properties": {"id": {"type": "string", "format": "uuid"}}}));
    assert!(result["id"].as_str().is_some_and(|s| s.contains('-')), "{result}");
}

#[test]
fn should_respect_min_length() {
    let result = synthesised(json!({"type": "object", "properties": {"code": {"type": "string", "minLength": 10}}}));
    assert!(result["code"].as_str().is_some_and(|s| s.chars().count() >= 10), "{result}");
}

#[test]
fn should_respect_min_items() {
    let result = synthesised(json!({"type": "array", "items": {"type": "string"}, "minItems": 3}));
    assert!(result.as_array().is_some_and(|a| a.len() >= 3), "{result}");
}

#[test]
fn should_synthesize_number_with_minimum() {
    let result = synthesised(json!({"type": "object", "properties": {"price": {"type": "number", "minimum": 9.99}}}));
    assert!(result["price"].as_f64().is_some_and(|p| p >= 9.99), "{result}");
}

/// Not an upstream test: `asInt()`/`asLong()` read a `double` constraint truncated, and `minimum + 1` wraps as a
/// Java `long` does.
#[test]
fn numeric_constraints_are_read_as_jackson_reads_them() {
    let array = |schema: Value| synthesised(schema).as_array().map_or(0, Vec::len);
    assert_eq!(array(json!({"type": "array", "items": {"type": "string"}, "minItems": 2.5})), 2);
    assert_eq!(synthesised(json!({"type": "string", "minLength": 8.0})), json!("ssssssss"));
    assert_eq!(synthesised(json!({"type": "integer", "minimum": 9.99})), json!(9));
    assert_eq!(synthesised(json!({"type": "integer", "minimum": 9223372036854775807_i64, "exclusiveMinimum": true})), json!(i64::MIN));
}
