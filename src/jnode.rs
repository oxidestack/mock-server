//! JSON read the way MockServer's `ObjectMapper` (`ObjectMapperFactory`) reads a tree, into the ported `jackson`
//! crate's `JsonNode`.

use std::sync::Arc;

use jackson::{JacksonError, JsonNode};
use serde_json::Value;

/// `ObjectMapper.readTree(String)` with `ObjectMapperFactory`'s parser features: Jackson's tree and exception text.
pub fn read_tree(text: &str) -> Result<JsonNode, JacksonError> {
    jackson::json::read_tree(text, jackson::json::ReadFeatures::mockserver())
}

/// The exception `readTree(String)` throws for `text` as `class: message` (`message` carries Jackson's
/// ` at [Source: ...; line: L, column: C]` location), or `None` when it reads (trailing content included).
pub fn syntax_failure(text: &str) -> Option<String> {
    read_tree(text).err().map(|e| format!("shaded_package.{}: {}", e.class, e.message))
}

/// `new ObjectMapper().readTree(String)` (no parser features enabled) for code that works on `serde_json` values:
/// Jackson decides whether the text parses, and its exception message is the error.
pub fn read_value_plain(text: &str) -> Result<Value, String> {
    let features = jackson::json::ReadFeatures { tree_member_values: true, ..Default::default() };
    jackson::json::read_tree(text, features).map_err(|e| e.message)?;
    crate::json::parse_lenient(text.as_bytes()).map_err(|e| e.to_string())
}

/// A `serde_json` value as the tree Jackson would have read from its text.
pub fn from_value(v: &Value) -> JsonNode {
    match v {
        Value::Null => JsonNode::Null,
        Value::Bool(b) => JsonNode::Boolean(*b),
        Value::String(s) => JsonNode::text(s.as_str()),
        Value::Number(n) => {
            let text = n.to_string();
            if text.contains(['.', 'e', 'E']) {
                JsonNode::Double(jackson::javanum::parse_double(&text).unwrap_or(0.0))
            } else if let Ok(i) = text.parse::<i32>() {
                JsonNode::Int(i)
            } else if let Ok(l) = text.parse::<i64>() {
                JsonNode::Long(l)
            } else {
                text.parse::<num_bigint::BigInt>().map_or(JsonNode::Double(n.as_f64().unwrap_or(0.0)), |b| JsonNode::BigInteger(Arc::new(b)))
            }
        }
        Value::Array(items) => JsonNode::array(items.iter().map(from_value).collect()),
        Value::Object(o) => JsonNode::object(o.iter().map(|(k, v)| (k.clone(), from_value(v))).collect()),
    }
}
