//! Binding request JSON into MockServer's chaos DTOs the way its `ObjectMapper` does (`ObjectMapperFactory`):
//! case-insensitive property names and enums, unknown properties ignored, unknown enum values read as null, and
//! Jackson's scalar coercions (numeric strings, truncated floats, integers as booleans). Errors carry Jackson's text.

use serde_json::{Map, Value};

/// A Jackson `JsonMappingException`: its message and the reference chain from the root to the failing property.
/// Boxed, so a `Result` that may fail binding stays small; its fields are reached through `Deref`.
#[derive(Debug)]
pub struct BindError(Box<BindErrorData>);

/// The fields of a [`BindError`].
#[derive(Debug)]
pub struct BindErrorData {
    pub message: String,
    chain: Vec<String>,
    /// The exception's own properties: `getCurrentToken()` (the failing value's token), `getTargetType()` and, for an
    /// `InvalidFormatException`, `getValue()`.
    token: Option<&'static str>,
    target: Option<String>,
    value: Option<Value>,
    /// A number out of range: Jackson's `InputCoercionException` (input token, target primitive), which the bean
    /// deserializer wraps in a plain `JsonMappingException`.
    coercion: Option<(&'static str, String)>,
}

const MISMATCHED_INPUT: &str = "shaded_package.com.fasterxml.jackson.databind.exc.MismatchedInputException";
const INVALID_FORMAT: &str = "shaded_package.com.fasterxml.jackson.databind.exc.InvalidFormatException";
const MAPPING: &str = "shaded_package.com.fasterxml.jackson.databind.JsonMappingException";
const INPUT_COERCION: &str = "shaded_package.com.fasterxml.jackson.core.exc.InputCoercionException";

impl std::ops::Deref for BindError {
    type Target = BindErrorData;

    fn deref(&self) -> &BindErrorData {
        &self.0
    }
}

impl std::ops::DerefMut for BindError {
    fn deref_mut(&mut self) -> &mut BindErrorData {
        &mut self.0
    }
}

impl BindError {
    fn new(message: String) -> BindError {
        BindError(Box::new(BindErrorData { message, chain: Vec::new(), token: None, target: None, value: None, coercion: None }))
    }

    /// A `MismatchedInputException` about `v` (its token) for `target`.
    fn mismatched(message: String, v: &Value, target: &str) -> BindError {
        let mut e = BindError::new(message);
        e.token = Some(token_name(v));
        e.target = Some(raw_class(target).to_string());
        e
    }

    /// An `InvalidFormatException`: `v` (its token and its value) is no `target`.
    fn invalid_format(message: String, v: &Value, target: &str) -> BindError {
        let mut e = BindError::mismatched(message, v, target);
        e.value = Some(v.clone());
        e
    }

    /// A number `v` out of the range of the primitive `target` (`InputCoercionException`).
    fn out_of_range(message: String, v: &Value, target: &str) -> BindError {
        let mut e = BindError::new(message);
        e.coercion = Some((token_name(v), target.to_string()));
        e
    }

    /// A value of the wrong JSON shape for its property (the message is not shown).
    pub fn mismatch() -> BindError {
        BindError::new("mismatched input".into())
    }

    /// Prefixes the reference chain with `class["property"]`.
    fn at(mut self, class: &str, property: &str) -> BindError {
        self.chain.insert(0, format!("{class}[\"{property}\"]"));
        self
    }

    /// Prefixes the reference chain with `class[index]`.
    pub fn at_index(mut self, class: &str, index: usize) -> BindError {
        self.chain.insert(0, format!("{class}[{index}]"));
        self
    }

    fn chain_text(&self) -> String {
        if self.chain.is_empty() { String::new() } else { format!(" (through reference chain: {})", self.chain.join("->")) }
    }

    /// `getMessage()` after `ObjectMapper.treeToValue`, which has no source location.
    pub fn tree_text(&self) -> String {
        format!("{}\n at [Source: UNKNOWN; byte offset: #UNKNOWN]{}", self.message, self.chain_text())
    }

    /// `getMessage()` after `ObjectMapper.readValue(String)`, located at `(line, column)` of the failing token.
    pub fn source_text(&self, (line, column): (usize, usize)) -> String {
        format!("{}{}{}", self.message, source_location(line, column), self.chain_text())
    }

    /// The first property of the reference chain, if any.
    pub fn property(&self) -> Option<&str> {
        let first = self.chain.first()?;
        first.split_once("[\"").map(|(_, p)| p.trim_end_matches("\"]"))
    }

    /// The exception `ObjectMapper.readValue(body, …)` throws, as a generator endpoint logs it: its message (located
    /// in `body` as [`BindError::source_text`]) and its Jackson bean.
    pub fn failure(&self, body: &str) -> crate::recorded::Failure {
        let (line, mut column) = chain_location(body, &self.chain);
        if self.coercion.is_some() {
            // the parser reports a number out of range once it has read it
            let rest = body.split('\n').nth(line - 1).unwrap_or_default().encode_utf16().skip(column - 1);
            column += rest.take_while(|u| matches!(*u, 0x30..=0x39 | 0x2B | 0x2D | 0x2E | 0x45 | 0x65)).count();
        }
        let message = self.source_text((line, column));
        let located = json_location(body, line, column);
        let path: Vec<Value> = self
            .chain
            .iter()
            .map(|reference| {
                let mut element = Map::new();
                element.insert("description".into(), reference.clone().into());
                match reference.strip_suffix("\"]").and_then(|r| r.split_once("[\"")) {
                    Some((_, field)) => {
                        element.insert("fieldName".into(), field.into());
                        element.insert("index".into(), Value::from(-1));
                    }
                    None => {
                        let index = reference.rsplit_once('[').and_then(|(_, i)| i.trim_end_matches(']').parse::<i64>().ok()).unwrap_or(-1);
                        element.insert("index".into(), index.into());
                    }
                }
                Value::Object(element)
            })
            .collect();
        let mut fields = vec![("location", located.clone()), ("originalMessage", Value::from(self.message.clone()))];
        if !path.is_empty() {
            fields.push(("path", Value::Array(path)));
            fields.push(("pathReference", self.chain.join("->").into()));
        }
        if let Some((input, target)) = &self.coercion {
            let cause = crate::recorded::Failure::of(
                INPUT_COERCION,
                format!("{}{}", self.message, source_location(line, column)),
                vec![("inputType", (*input).into()), ("location", located), ("originalMessage", self.message.clone().into()), ("targetType", target.clone().into())],
                &[],
            );
            fields.push(("cause", cause.bean));
            return crate::recorded::Failure::of(MAPPING, message, fields, &[INPUT_COERCION]);
        }
        if let Some(token) = self.token {
            fields.push(("currentToken", token.into()));
        }
        if let Some(target) = &self.target {
            fields.push(("targetType", target.clone().into()));
        }
        let class = match &self.value {
            Some(value) => {
                fields.push(("value", value.clone()));
                INVALID_FORMAT
            }
            None => MISMATCHED_INPUT,
        };
        crate::recorded::Failure::of(class, message, fields, &[])
    }
}

/// The `\n at [Source: …]` part of a Jackson message about a string read with `readValue`.
fn source_location(line: usize, column: usize) -> String {
    format!("\n at [Source: REDACTED (`StreamReadFeature.INCLUDE_SOURCE_IN_LOCATION` disabled); line: {line}, column: {column}]")
}

/// Jackson's `JsonLocation` bean for `(line, column)` of a string source: no byte offset, the character (UTF-16 unit)
/// offset from the start.
pub fn json_location(text: &str, line: usize, column: usize) -> Value {
    let mut offset = 0usize;
    for (i, l) in text.split('\n').enumerate() {
        if i + 1 == line {
            break;
        }
        offset += l.encode_utf16().count() + 1;
    }
    serde_json::json!({"byteOffset": -1, "charOffset": offset + column.saturating_sub(1), "columnNr": column, "lineNr": line})
}

/// The exception of a body `ObjectMapper` cannot read as JSON (`JsonParseException`, `JsonEOFException` at the end of
/// the input), from its message (`<reason>\n at [Source: …; line: L, column: C]`).
pub fn parse_failure(body: &str, message: &str) -> crate::recorded::Failure {
    let (original, at) = message.split_once("\n at [Source: ").unwrap_or((message, ""));
    let number = |key: &str| at.split_once(key).and_then(|(_, rest)| rest.split(|c: char| !c.is_ascii_digit()).next()?.parse::<usize>().ok()).unwrap_or(1);
    let (line, column) = (number("line: "), number("column: "));
    let class = if original.starts_with("Unexpected end-of-input") {
        "shaded_package.com.fasterxml.jackson.core.io.JsonEOFException"
    } else {
        "shaded_package.com.fasterxml.jackson.core.JsonParseException"
    };
    crate::recorded::Failure::of(class, message, vec![("location", json_location(body, line, column)), ("originalMessage", original.into())], &[])
}

/// A generic type's raw class, as `getTargetType()` names it.
fn raw_class(class: &str) -> &str {
    class.split('<').next().unwrap_or(class)
}

/// The `JsonToken` the parser stands on at `v`.
fn token_name(v: &Value) -> &'static str {
    match v {
        Value::Bool(true) => "VALUE_TRUE",
        Value::Bool(false) => "VALUE_FALSE",
        Value::Array(_) => "START_ARRAY",
        Value::Object(_) => "START_OBJECT",
        Value::String(_) => "VALUE_STRING",
        Value::Number(n) if n.is_f64() => "VALUE_NUMBER_FLOAT",
        Value::Number(_) => "VALUE_NUMBER_INT",
        Value::Null => "VALUE_NULL",
    }
}

/// `DeserializationContext.handleUnexpectedToken`'s description of the value: its shape and its token.
fn token(v: &Value) -> String {
    let shape = match v {
        Value::Bool(_) => "Boolean value",
        Value::Array(_) => "Array value",
        Value::Object(_) => "Object value",
        Value::String(_) => "String value",
        Value::Number(n) if n.is_f64() => "Floating-point value",
        Value::Number(_) => "Integer value",
        Value::Null => "Null value",
    };
    format!("{shape} (token `JsonToken.{}`)", token_name(v))
}

const STRING_MAP: &str = "java.util.LinkedHashMap<java.lang.String,java.lang.String>";
const OBJECT_NODE: &str = "shaded_package.com.fasterxml.jackson.databind.node.ObjectNode";

/// A `Map<String, String>` property: its entries in order, a null value as `None`.
pub type StringMap = Vec<(String, Option<String>)>;

/// A bean (DTO) bound from a JSON value.
pub struct Bean<'a> {
    map: &'a Map<String, Value>,
    class: &'static str,
}

impl<'a> Bean<'a> {
    /// A JSON object binds; anything else fails as Jackson's `BeanDeserializer` does for that token.
    pub fn of(v: &'a Value, class: &'static str) -> Result<Bean<'a>, BindError> {
        let creator = |what: String| BindError::mismatched(format!("Cannot construct instance of `{class}` (although at least one Creator exists): {what}"), v, class);
        match v {
            Value::Object(map) => Ok(Bean { map, class }),
            Value::String(s) => Err(creator(format!("no String-argument constructor/factory method to deserialize from String value ('{s}')"))),
            Value::Bool(b) => Err(creator(format!("no boolean/Boolean-argument constructor/factory method to deserialize from boolean value ({b})"))),
            Value::Number(n) if n.as_i64().is_some_and(|i| i32::try_from(i).is_ok()) => {
                Err(creator(format!("no int/Int-argument constructor/factory method to deserialize from Number value ({n})")))
            }
            Value::Number(n) if n.as_i64().is_some() => Err(creator(format!("no long/Long-argument constructor/factory method to deserialize from Number value ({n})"))),
            Value::Number(n) => Err(creator(format!("no double/Double-argument constructor/factory method to deserialize from Number value ({n})"))),
            other => Err(BindError::mismatched(format!("Cannot deserialize value of type `{class}` from {}", token(other)), other, class)),
        }
    }

    pub fn map(&self) -> &'a Map<String, Value> {
        self.map
    }

    /// The property's value (`ACCEPT_CASE_INSENSITIVE_PROPERTIES`; the last spelling wins); null reads as absent.
    pub fn get(&self, name: &str) -> Option<&'a Value> {
        self.map.iter().filter(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v).next_back().filter(|v| !v.is_null())
    }

    pub fn located<T>(&self, name: &str, r: Result<T, BindError>) -> Result<T, BindError> {
        r.map_err(|e| e.at(self.class, name))
    }

    /// A `Long` property.
    pub fn long(&self, name: &str) -> Result<Option<i64>, BindError> {
        self.located(name, self.get(name).map(|v| long(v, "java.lang.Long", i64::MIN, i64::MAX, "long")).transpose().map(Option::flatten))
    }

    /// An `Integer` property.
    pub fn int(&self, name: &str) -> Result<Option<i32>, BindError> {
        let v = self.located(name, self.get(name).map(|v| long(v, "java.lang.Integer", i32::MIN as i64, i32::MAX as i64, "int")).transpose().map(Option::flatten))?;
        Ok(v.map(|n| n as i32))
    }

    /// The property's value as given (the last spelling wins), an explicit null included.
    fn given(&self, name: &str) -> Option<&'a Value> {
        self.map.iter().filter(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v).next_back()
    }

    /// A primitive `int` property (Jackson names the primitive type). `None` only when absent, so the field keeps its
    /// initialiser; an explicit null, an empty string or the text `null` reads as 0, the primitive deserializer's
    /// null value.
    pub fn primitive_int(&self, name: &str) -> Result<Option<i32>, BindError> {
        Ok(self.primitive_number(name, "int", i32::MIN as i64, i32::MAX as i64)?.map(|n| n as i32))
    }

    /// A primitive `long` property, read as [`Bean::primitive_int`] reads an `int`.
    pub fn primitive_long(&self, name: &str) -> Result<Option<i64>, BindError> {
        self.primitive_number(name, "long", i64::MIN, i64::MAX)
    }

    fn primitive_number(&self, name: &str, primitive: &str, min: i64, max: i64) -> Result<Option<i64>, BindError> {
        match self.given(name) {
            None => Ok(None),
            Some(Value::Null) => Ok(Some(0)),
            Some(Value::String(s)) if s.trim() == "null" => Ok(Some(0)),
            Some(v) => self.located(name, long(v, primitive, min, max, primitive)).map(|n| Some(n.unwrap_or(0))),
        }
    }

    /// A primitive `boolean` property (`_parseBooleanPrimitive`). `None` only when absent; an explicit null, an empty
    /// string or the text `null` reads as false.
    pub fn primitive_boolean(&self, name: &str) -> Result<Option<bool>, BindError> {
        match self.given(name) {
            None => Ok(None),
            Some(Value::Null) => Ok(Some(false)),
            Some(v) => self.located(name, primitive_boolean(v)).map(|b| Some(b.unwrap_or(false))),
        }
    }

    /// A `Double` property: numbers, and numeric strings (`_parseDouble`): the special values exactly as given
    /// (`NaN`, `INF`/`Infinity` signed or not, `-` for negative), else trimmed: an empty one or the text `null` is
    /// null, and anything but a plain decimal (no `d`/`f` suffix, no hex) is refused, quoted trimmed.
    pub fn double(&self, name: &str) -> Result<Option<f64>, BindError> {
        let v = match self.get(name) {
            None => Ok(None),
            // a literal beyond the double range (`1e400`) is read as Jackson reads it: an infinity
            Some(Value::Number(n)) => Ok(n.as_f64().or_else(|| n.to_string().parse::<f64>().ok())),
            Some(Value::String(s)) if matches!(s.as_str(), "INF" | "Infinity" | "+INF" | "+Infinity") => Ok(Some(f64::INFINITY)),
            Some(Value::String(s)) if matches!(s.as_str(), "-INF" | "-Infinity") => Ok(Some(f64::NEG_INFINITY)),
            Some(Value::String(s)) if s == "NaN" => Ok(Some(f64::NAN)),
            Some(Value::String(s)) if matches!(s.trim(), "" | "null") => Ok(None),
            Some(v @ Value::String(s)) => Some(s.trim()).filter(|t| plain_decimal(t)).and_then(|t| t.parse::<f64>().ok()).map(Some).ok_or_else(|| {
                let t = s.trim();
                BindError::invalid_format(format!("Cannot deserialize value of type `java.lang.Double` from String \"{t}\": not a valid `Double` value"), v, "java.lang.Double")
            }),
            Some(v) => Err(BindError::mismatched(format!("Cannot deserialize value of type `java.lang.Double` from {}", token(v)), v, "java.lang.Double")),
        };
        self.located(name, v)
    }

    /// A `Boolean` property.
    pub fn boolean(&self, name: &str) -> Result<Option<bool>, BindError> {
        self.located(name, self.get(name).map(boolean).transpose().map(Option::flatten))
    }

    /// A `String` property: scalars as their text.
    pub fn string(&self, name: &str) -> Result<Option<String>, BindError> {
        self.located(
            name,
            match self.get(name) {
                None => Ok(None),
                Some(Value::String(s)) => Ok(Some(s.clone())),
                Some(v @ (Value::Number(_) | Value::Bool(_))) => Ok(Some(v.to_string())),
                Some(v) => Err(BindError::mismatched(format!("Cannot deserialize value of type `java.lang.String` from {}", token(v)), v, "java.lang.String")),
            },
        )
    }

    /// A `Map<String, String>` property: scalar values as their text, null values kept as null; in the order given.
    pub fn string_map(&self, name: &str) -> Result<Option<StringMap>, BindError> {
        let v = match self.get(name) {
            None => Ok(None),
            Some(Value::Object(map)) => map
                .iter()
                .map(|(k, v)| match v {
                    Value::Null => Ok((k.clone(), None)),
                    Value::String(s) => Ok((k.clone(), Some(s.clone()))),
                    Value::Number(_) | Value::Bool(_) => Ok((k.clone(), Some(v.to_string()))),
                    other => Err(BindError::mismatched(format!("Cannot deserialize value of type `java.lang.String` from {}", token(other)), other, "java.lang.String")
                        .at("java.util.LinkedHashMap", k)),
                })
                .collect::<Result<Vec<_>, _>>()
                .map(Some),
            Some(v) => Err(BindError::mismatched(format!("Cannot deserialize value of type `{STRING_MAP}` from {}", token(v)), v, STRING_MAP)),
        };
        self.located(name, v)
    }

    /// An enum property with constants `values` (in declaration order): matched case-insensitively, or by ordinal
    /// from an integer; an unknown value reads as null (`READ_UNKNOWN_ENUM_VALUES_AS_NULL`).
    pub fn enumeration(&self, name: &str, enum_class: &str, values: &[&str]) -> Result<Option<usize>, BindError> {
        self.located(
            name,
            match self.get(name) {
                None => Ok(None),
                Some(Value::String(s)) => Ok(values.iter().position(|v| v.eq_ignore_ascii_case(s.trim()))),
                Some(Value::Number(n)) => Ok(n.as_u64().map(|i| i as usize).filter(|i| *i < values.len())),
                Some(v) => Err(BindError::mismatched(format!("Cannot deserialize value of type `{enum_class}` from {}", token(v)), v, enum_class)),
            },
        )
    }

    /// A nested bean property.
    pub fn bean(&self, name: &str, class: &'static str) -> Result<Option<Bean<'a>>, BindError> {
        self.located(name, self.get(name).map(|v| Bean::of(v, class)).transpose())
    }

    /// A `List<E>` property read with `ACCEPT_SINGLE_VALUE_AS_ARRAY` (a lone value is a list of one), each element
    /// bound by `element`; `single` names the reference of a lone value's failure (Jackson's `[0]` on it).
    fn list<T>(&self, name: &str, single: &str, element: impl Fn(&'a Value) -> Result<T, BindError>) -> Result<Option<Vec<T>>, BindError> {
        let v = match self.get(name) {
            None => Ok(None),
            Some(Value::Array(items)) => {
                items.iter().enumerate().map(|(i, item)| element(item).map_err(|e| e.at_index("java.util.ArrayList", i))).collect::<Result<Vec<T>, _>>().map(Some)
            }
            Some(v) => element(v).map(|e| Some(vec![e])).map_err(|e| e.at_index(single, 0)),
        };
        self.located(name, v)
    }

    /// A `List<String>` property: scalars as their text, null elements kept as null.
    pub fn string_list(&self, name: &str) -> Result<Option<Vec<Option<String>>>, BindError> {
        self.list(name, "java.util.ArrayList", |v| match v {
            Value::Null => Ok(None),
            Value::String(s) => Ok(Some(s.clone())),
            Value::Number(_) | Value::Bool(_) => Ok(Some(v.to_string())),
            other => Err(BindError::mismatched(format!("Cannot deserialize value of type `java.lang.String` from {}", token(other)), other, "java.lang.String")),
        })
    }

    /// A `List<ObjectNode>` property.
    pub fn object_list(&self, name: &str) -> Result<Option<Vec<&'a Map<String, Value>>>, BindError> {
        self.list(name, OBJECT_NODE, |v| match v {
            Value::Object(map) => Ok(map),
            other => Err(BindError::mismatched(format!("Cannot deserialize value of type `{OBJECT_NODE}` from {}", token(other)), other, OBJECT_NODE)),
        })
    }

    /// A `Map<String, V>` property whose values may be anything (`class` is its declared type): the object.
    pub fn object(&self, name: &str, class: &str) -> Result<Option<&'a Map<String, Value>>, BindError> {
        let v = match self.get(name) {
            None => Ok(None),
            Some(Value::Object(map)) => Ok(Some(map)),
            Some(v @ Value::String(s)) => {
                let raw = raw_class(class);
                Err(BindError::mismatched(
                    format!("Cannot construct instance of `{raw}` (although at least one Creator exists): no String-argument constructor/factory method to deserialize from String value ('{s}')"),
                    v,
                    raw,
                ))
            }
            Some(v) => Err(BindError::mismatched(format!("Cannot deserialize value of type `{class}` from {}", token(v)), v, class)),
        };
        self.located(name, v)
    }
}

/// `NumberDeserializers` for `Long`/`Integer`: integers (range-checked), floats (truncated), numeric strings
/// (trimmed; an empty one or the text `null` is null, `_checkTextualNull`; a refused one is quoted trimmed).
fn long(v: &Value, class: &str, min: i64, max: i64, primitive: &str) -> Result<Option<i64>, BindError> {
    let out_of_range = |n: &dyn std::fmt::Display| BindError::out_of_range(format!("Numeric value ({n}) out of range of {primitive} ({min} - {max})"), v, primitive);
    match v {
        Value::Number(n) => match n.as_i64() {
            Some(i) if (min..=max).contains(&i) => Ok(Some(i)),
            Some(_) => Err(out_of_range(n)),
            None if n.as_u64().is_some() => Err(out_of_range(n)),
            None => {
                let f = n.as_f64().unwrap_or(0.0);
                if f < min as f64 || f > max as f64 { Err(out_of_range(n)) } else { Ok(Some(f as i64)) }
            }
        },
        Value::String(s) => match s.trim() {
            "" | "null" => Ok(None),
            t => match t.parse::<i64>() {
                Ok(i) if (min..=max).contains(&i) => Ok(Some(i)),
                _ => Err(BindError::invalid_format(format!("Cannot deserialize value of type `{class}` from String \"{t}\": not a valid `{class}` value"), v, class)),
            },
        },
        other => Err(BindError::mismatched(format!("Cannot deserialize value of type `{class}` from {}", token(other)), other, class)),
    }
}

/// `[+-]?(digits[.digits?]|.digits)([eE][+-]?digits)?`: the decimal text Jackson's `_parseDouble` accepts.
fn plain_decimal(t: &str) -> bool {
    let digits = |s: &str| s.bytes().take_while(u8::is_ascii_digit).count();
    let t = t.strip_prefix(['+', '-']).unwrap_or(t);
    let int = digits(t);
    let rest = &t[int..];
    let (frac, rest) = match rest.strip_prefix('.') {
        Some(r) => (digits(r), &r[digits(r)..]),
        None => (0, rest),
    };
    if int + frac == 0 {
        return false;
    }
    match rest.strip_prefix(['e', 'E']) {
        None => rest.is_empty(),
        Some(e) => {
            let e = e.strip_prefix(['+', '-']).unwrap_or(e);
            digits(e) > 0 && digits(e) == e.len()
        }
    }
}

/// `BooleanDeserializer`: booleans, integers (non-zero is true), and the strings `true`/`True`/`TRUE` and
/// `false`/`False`/`FALSE` (trimmed; an empty one or the text `null` is null; a refused one is quoted trimmed).
fn boolean(v: &Value) -> Result<Option<bool>, BindError> {
    match v {
        Value::Bool(b) => Ok(Some(*b)),
        Value::Number(n) if n.as_i64().is_some() => Ok(Some(n.as_i64() != Some(0))),
        Value::Number(n) => Err(BindError::invalid_format(format!("Cannot coerce Floating-point value ({n}) to `java.lang.Boolean` value"), v, "java.lang.Boolean")),
        Value::String(s) => match s.trim() {
            "" | "null" => Ok(None),
            "true" | "True" | "TRUE" => Ok(Some(true)),
            "false" | "False" | "FALSE" => Ok(Some(false)),
            t => Err(BindError::invalid_format(format!("Cannot deserialize value of type `java.lang.Boolean` from String \"{t}\": only \"true\" or \"false\" recognized"), v, "java.lang.Boolean")),
        },
        other => Err(BindError::mismatched(format!("Cannot deserialize value of type `java.lang.Boolean` from {}", token(other)), other, "java.lang.Boolean")),
    }
}

/// `_parseBooleanPrimitive`: booleans, integers (non-zero is true), and the strings `true`/`True`/`TRUE` and
/// `false`/`False`/`FALSE` (trimmed; an empty one or `null` is false). A float is refused.
fn primitive_boolean(v: &Value) -> Result<Option<bool>, BindError> {
    match v {
        Value::Bool(b) => Ok(Some(*b)),
        Value::Number(n) if n.as_i64().is_some() => Ok(Some(n.as_i64() != Some(0))),
        Value::String(s) => match s.trim() {
            "" | "null" => Ok(None),
            "true" | "True" | "TRUE" => Ok(Some(true)),
            "false" | "False" | "FALSE" => Ok(Some(false)),
            text => Err(BindError::invalid_format(
                format!("Cannot deserialize value of type `boolean` from String \"{text}\": only \"true\"/\"True\"/\"TRUE\" or \"false\"/\"False\"/\"FALSE\" recognized"),
                &Value::String(text.to_string()),
                "boolean",
            )),
        },
        other => Err(BindError::mismatched(format!("Cannot deserialize value of type `boolean` from {}", token(other)), other, "boolean")),
    }
}

/// `(line, column)` of the token Jackson reports for a failure: the root value when `property` is `None`, else the
/// value of that top-level property (matched case-insensitively). Columns count UTF-16 units from 1.
pub fn location(text: &str, property: Option<&str>) -> (usize, usize) {
    let units: Vec<u16> = text.encode_utf16().collect();
    let (mut line, mut line_start) = (1usize, 0usize);
    let mut i = 0usize;
    let skip_ws = |i: &mut usize, line: &mut usize, line_start: &mut usize| {
        while *i < units.len() && matches!(units[*i], 0x20 | 0x09 | 0x0A | 0x0D) {
            if units[*i] == 0x0A {
                *line += 1;
                *line_start = *i + 1;
            }
            *i += 1;
        }
    };
    skip_ws(&mut i, &mut line, &mut line_start);
    let root = (line, i - line_start + 1);
    let Some(property) = property else { return root };
    if units.get(i) != Some(&(b'{' as u16)) {
        return root;
    }
    i += 1;
    let mut depth = 0usize;
    let mut found = root;
    // Scan the root object's members: a string at depth 0 followed by ':' is a key naming the next value.
    while i < units.len() {
        skip_ws(&mut i, &mut line, &mut line_start);
        let Some(&c) = units.get(i) else { break };
        match c {
            0x22 | 0x27 => {
                let start = i + 1;
                i += 1;
                while i < units.len() && units[i] != c {
                    if units[i] == b'\\' as u16 {
                        i += 1;
                    }
                    i += 1;
                }
                let s = String::from_utf16_lossy(&units[start..i.min(units.len())]);
                i += 1;
                if depth == 0 {
                    skip_ws(&mut i, &mut line, &mut line_start);
                    if units.get(i) == Some(&(b':' as u16)) {
                        i += 1;
                        skip_ws(&mut i, &mut line, &mut line_start);
                        if s.eq_ignore_ascii_case(property) {
                            found = (line, i - line_start + 1);
                        }
                    }
                }
            }
            0x7B | 0x5B => {
                depth += 1;
                i += 1;
            }
            0x7D | 0x5D => {
                if depth == 0 {
                    break;
                }
                depth -= 1;
                i += 1;
            }
            _ => i += 1,
        }
    }
    found
}

/// [`location`] of the value a reference chain (`Class["name"]`, `Class[index]`) leads to: properties of the root
/// bean match case-insensitively (the last spelling wins), map keys exactly; an index into a value that is no array
/// stays on that value (`ACCEPT_SINGLE_VALUE_AS_ARRAY`).
fn chain_location(text: &str, chain: &[String]) -> (usize, usize) {
    let units: Vec<u16> = text.encode_utf16().collect();
    let is = |i: usize, c: char| units.get(i) == Some(&(c as u16));
    let skip_ws = |mut i: usize| {
        while i < units.len() && matches!(units[i], 0x20 | 0x09 | 0x0A | 0x0D) {
            i += 1;
        }
        i
    };
    // the end of the string that starts at `i` (after its closing quote)
    let skip_string = |mut i: usize| {
        let quote = units[i];
        i += 1;
        while i < units.len() && units[i] != quote {
            if units[i] == b'\\' as u16 {
                i += 1;
            }
            i += 1;
        }
        (i + 1).min(units.len())
    };
    let skip_value = |mut i: usize| {
        let mut depth = 0usize;
        while i < units.len() {
            match units[i] {
                0x22 | 0x27 => {
                    i = skip_string(i);
                    if depth == 0 {
                        return i;
                    }
                    continue;
                }
                0x7B | 0x5B => depth += 1,
                0x7D | 0x5D if depth == 0 => return i,
                0x7D | 0x5D => {
                    depth -= 1;
                    if depth == 0 {
                        return i + 1;
                    }
                }
                0x2C | 0x20 | 0x09 | 0x0A | 0x0D if depth == 0 => return i,
                _ => {}
            }
            i += 1;
        }
        i
    };
    let mut at = skip_ws(0);
    for (step, reference) in chain.iter().enumerate() {
        if let Some(field) = reference.strip_suffix("\"]").and_then(|r| r.split_once("[\"")).map(|(_, f)| f) {
            if !is(at, '{') {
                break;
            }
            let mut i = skip_ws(at + 1);
            let mut found = None;
            while i < units.len() && !is(i, '}') {
                let (key, after) = if is(i, '"') || is(i, '\'') {
                    let end = skip_string(i);
                    (String::from_utf16_lossy(&units[i + 1..end.saturating_sub(1).max(i + 1)]), end)
                } else {
                    let mut end = i;
                    while end < units.len() && !matches!(units[end], 0x3A | 0x20 | 0x09 | 0x0A | 0x0D) {
                        end += 1;
                    }
                    (String::from_utf16_lossy(&units[i..end]), end)
                };
                i = skip_ws(after);
                if !is(i, ':') {
                    break;
                }
                i = skip_ws(i + 1);
                if if step == 0 { key.eq_ignore_ascii_case(field) } else { key == field } {
                    found = Some(i);
                }
                i = skip_ws(skip_value(i));
                if is(i, ',') {
                    i = skip_ws(i + 1);
                }
            }
            match found {
                Some(i) => at = i,
                None => break,
            }
        } else {
            let index = reference.rsplit_once('[').and_then(|(_, i)| i.trim_end_matches(']').parse::<usize>().ok()).unwrap_or(0);
            if !is(at, '[') {
                continue;
            }
            let mut i = skip_ws(at + 1);
            let mut n = 0;
            while i < units.len() && !is(i, ']') && n < index {
                i = skip_ws(skip_value(i));
                if is(i, ',') {
                    i = skip_ws(i + 1);
                }
                n += 1;
            }
            at = i;
        }
    }
    let (mut line, mut line_start) = (1usize, 0usize);
    for (i, unit) in units.iter().enumerate().take(at) {
        if *unit == 0x0A {
            line += 1;
            line_start = i + 1;
        }
    }
    (line, at - line_start + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locates_member_values_like_jackson() {
        assert_eq!(location(r#"{"drainMillis": "abc"}"#, Some("drainMillis")), (1, 17));
        assert_eq!(location("{\"mode\": \"goaway\",\n  \"ttlMillis\": true}", Some("ttlMillis")), (2, 16));
        assert_eq!(location("\n  [1]", None), (2, 3));
    }
}
