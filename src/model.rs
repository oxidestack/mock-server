//! The parts of MockServer's Java model the code generators read, built from expectation JSON the way upstream's
//! DTO deserialisers build it: `NottableString` markers, insertion-ordered multimaps, body type inference.
//!
//! The input form matters, not the canonical echo: the model keeps keys in the order they were given (the JSON
//! echo sorts them) and keeps a JSON body given as a string verbatim.

use base64::Engine;
use serde_json::{Map, Value};

use crate::json;

/// `org.mockserver.model.NottableString` (and its optional / schema variants).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct NString {
    /// `None` for Java `null` (an object form with `"optional": true` and no `value`). For a schema, the
    /// pretty-printed schema (`NottableSchemaString.getValue()`).
    pub value: Option<String>,
    pub not: bool,
    pub optional: bool,
    /// The schema of a `NottableSchemaString`, as Jackson holds it.
    pub schema: Option<Value>,
    pub parameter_style: Option<String>,
    pub schema_type: Option<String>,
    /// The comparison of a `NottableDateTimeString`, whose `value` is its description.
    pub date_time: Option<DateTimeValue>,
}

/// A `NottableDateTimeString`'s fields, as `NottableStringDeserializer` read them.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct DateTimeValue {
    /// `before`, `after` or `equalToDateTime`.
    pub operator: &'static str,
    pub expected: Option<String>,
    pub actual_format: Option<String>,
    pub truncate_expected: Option<String>,
    pub truncate_actual: Option<String>,
    pub apply_truncation_last: Option<bool>,
    pub zone: Option<String>,
}

const DATE_TIME_OPERATORS: [&str; 3] = ["before", "after", "equalToDateTime"];
const DATE_TIME_OPTIONS: [&str; 5] = ["actualFormat", "truncateExpected", "truncateActual", "applyTruncationLast", "zone"];

impl DateTimeValue {
    /// The date-time comparison of an object-form value: `None` when it names no operator, else the comparison or
    /// what `NottableStringDeserializer` (and `DateTimeComparisonMatcher.compile`) throws.
    pub fn read(o: &Map<String, Value>) -> Option<Result<DateTimeValue, String>> {
        let mut operator = None;
        let mut out = DateTimeValue::default();
        let text = |v: &Value| v.as_str().map(str::to_string);
        for (key, value) in o {
            if let Some(op) = DATE_TIME_OPERATORS.iter().find(|op| **op == key) {
                if operator.is_some() {
                    return Some(Err("a date-time matcher has only one of before, after or equalToDateTime".into()));
                }
                operator = Some(*op);
                out.expected = text(value);
            }
            match key.as_str() {
                "actualFormat" => out.actual_format = text(value),
                "truncateExpected" => out.truncate_expected = text(value),
                "truncateActual" => out.truncate_actual = text(value),
                "applyTruncationLast" => out.apply_truncation_last = value.as_bool(),
                "zone" => out.zone = text(value),
                _ => {}
            }
        }
        let Some(operator) = operator else {
            if DATE_TIME_OPTIONS.iter().any(|k| o.get(*k).is_some_and(|v| !v.is_null())) {
                return Some(Err("actualFormat, truncateExpected, truncateActual, applyTruncationLast and zone need one of before, after or equalToDateTime".into()));
            }
            return None;
        };
        out.operator = operator;
        if o.get("schema").is_some_and(|v| !v.is_null()) || o.get("value").is_some_and(|v| !v.is_null()) || o.get("optional") == Some(&Value::Bool(true)) {
            return Some(Err("a date-time matcher cannot also have value, schema or optional".into()));
        }
        Some(out.comparison().map(|_| out))
    }

    /// `DateTimeComparisonMatcher.compile` of these fields.
    pub fn comparison(&self) -> Result<crate::templates::dates::comparison::DateTimeComparison, String> {
        use crate::templates::dates::comparison::{DateTimeComparison, Operator};
        let operator = Operator::for_field_name(self.operator).expect("a date-time operator");
        DateTimeComparison::compile(
            operator,
            self.expected.as_deref(),
            self.actual_format.as_deref(),
            self.truncate_expected.as_deref(),
            self.truncate_actual.as_deref(),
            self.apply_truncation_last,
            self.zone.as_deref(),
        )
    }

    /// `NottableDateTimeString.describe`: the value used for equality, ordering and log messages.
    pub fn describe(&self) -> String {
        let mut out = format!("{} {}", self.operator, self.expected.as_deref().unwrap_or("null"));
        let apply = self.apply_truncation_last.map(|b| b.to_string());
        for (name, value) in [
            ("actualFormat", &self.actual_format),
            ("truncateExpected", &self.truncate_expected),
            ("truncateActual", &self.truncate_actual),
            ("applyTruncationLast", &apply),
            ("zone", &self.zone),
        ] {
            if let Some(value) = value {
                out.push_str(&format!(", {name} {value}"));
            }
        }
        out
    }

    /// `NottableStringSerializer.writeDateTime`'s fields after the flags: the operator, then the options given.
    pub fn write(&self, o: &mut Map<String, Value>) {
        o.insert(self.operator.into(), self.expected.clone().map(Value::String).unwrap_or(Value::Null));
        for (name, value) in [("actualFormat", &self.actual_format), ("truncateExpected", &self.truncate_expected), ("truncateActual", &self.truncate_actual)] {
            if let Some(value) = value {
                o.insert(name.into(), value.clone().into());
            }
        }
        if let Some(last) = self.apply_truncation_last {
            o.insert("applyTruncationLast".into(), last.into());
        }
        if let Some(zone) = &self.zone {
            o.insert("zone".into(), zone.clone().into());
        }
    }
}

impl NString {
    fn new(value: impl Into<String>, not: bool) -> NString {
        NString { value: Some(value.into()), not, ..NString::default() }
    }

    /// `NottableString.string(String)`: a leading `?`, then `!`, then `?` are markers.
    pub fn parse(s: &str) -> NString {
        let mut value = s;
        let (mut not, mut optional) = (false, false);
        if !s.trim().is_empty() {
            if let Some(rest) = value.strip_prefix('?') {
                optional = true;
                value = rest;
            }
            if let Some(rest) = value.strip_prefix('!') {
                not = true;
                value = rest;
            }
            if let Some(rest) = value.strip_prefix('?') {
                optional = true;
                value = rest;
            }
        }
        NString { value: Some(value.to_string()), not, optional, ..NString::default() }
    }

    /// `NottableStringDeserializer`: a string with markers, or `{value, not, optional, schema}`; `None` is Java
    /// `null`.
    pub fn from_json(v: &Value) -> Option<NString> {
        match v {
            Value::String(s) => Some(NString::parse(s)),
            Value::Object(o) => {
                let not = o.get("not").and_then(Value::as_bool);
                let optional = o.get("optional").and_then(Value::as_bool);
                let value = o.get("value").and_then(Value::as_str);
                let mut result = if let Some(Ok(date_time)) = DateTimeValue::read(o) {
                    NString { value: Some(date_time.describe()), not: not.unwrap_or(false), date_time: Some(date_time), ..NString::default() }
                } else if let Some(schema) = o.get("schema").filter(|s| !s.is_null()) {
                    let tree = jackson_tree(schema);
                    NString { value: Some(json::pretty(&tree)), not: not.unwrap_or(false), schema: Some(tree), ..NString::default() }
                } else if optional == Some(true) {
                    NString { value: value.map(str::to_string), not: not.unwrap_or(false), optional: true, ..NString::default() }
                } else {
                    NString::new(value.filter(|v| !v.trim().is_empty())?, not.unwrap_or(false))
                };
                result.parameter_style = o.get("parameterStyle").and_then(Value::as_str).map(str::to_string);
                result.schema_type = o.get("schemaType").and_then(Value::as_str).map(str::to_string);
                Some(result)
            }
            _ => None,
        }
    }

    fn is_blank(&self) -> bool {
        self.value.as_deref().is_none_or(|v| v.trim().is_empty())
    }

    /// `NottableString.toString()`: `?` for optional, then `!` for negated, then the value.
    pub fn marked(&self) -> String {
        let mut out = String::new();
        if self.optional {
            out.push('?');
        }
        if self.not {
            out.push('!');
        }
        if !self.is_blank() {
            out.push_str(self.value.as_deref().unwrap_or_default());
        }
        out
    }

    /// `NottableStringSerializer.isAmbiguousAsPlainString`: re-reading the marked form would change it.
    pub fn is_ambiguous(&self) -> bool {
        if self.is_blank() {
            return false;
        }
        let reparsed = NString::parse(&self.marked());
        reparsed.not != self.not || reparsed.optional != self.optional || reparsed.value != self.value
    }

    /// `NottableStringSerializer.serialize`.
    pub fn to_json(&self) -> Value {
        let object = |value_key: &str, value: Value, always_not: bool| {
            let mut o = Map::new();
            if always_not || self.not {
                o.insert("not".into(), Value::Bool(self.not));
            }
            if self.optional {
                o.insert("optional".into(), Value::Bool(true));
            }
            if let Some(style) = &self.parameter_style {
                o.insert("parameterStyle".into(), style.clone().into());
            }
            if let Some(t) = &self.schema_type {
                o.insert("schemaType".into(), t.clone().into());
            }
            o.insert(value_key.into(), value);
            Value::Object(o)
        };
        let value = || self.value.clone().map(Value::String).unwrap_or(Value::Null);
        if let Some(date_time) = &self.date_time {
            // `NottableStringSerializer.writeDateTime`: `not` only when true, the style, the schema type, the comparison
            let mut o = Map::new();
            if self.not {
                o.insert("not".into(), Value::Bool(true));
            }
            if let Some(style) = &self.parameter_style {
                o.insert("parameterStyle".into(), style.clone().into());
            }
            if let Some(t) = &self.schema_type {
                o.insert("schemaType".into(), t.clone().into());
            }
            date_time.write(&mut o);
            Value::Object(o)
        } else if let Some(schema) = &self.schema {
            object("schema", jackson_echo_tree(schema), false)
        } else if self.parameter_style.is_some() {
            object("value", value(), false)
        } else if self.is_ambiguous() {
            object("value", value(), true)
        } else {
            Value::String(self.marked())
        }
    }

    /// `NottableString.compareTo`: by value, descending (`String.compareTo`, UTF-16 units).
    fn cmp_descending(&self, other: &NString) -> std::cmp::Ordering {
        // compared unit by unit as they are encoded: nothing is copied
        let (mine, theirs) = (self.value.as_deref().unwrap_or_default(), other.value.as_deref().unwrap_or_default());
        theirs.encode_utf16().cmp(mine.encode_utf16())
    }

    /// Multimap key identity: `Objects.hash(value, not)`.
    fn same_key(&self, other: &NString) -> bool {
        self.value == other.value && self.not == other.not
    }
}

/// `KeysToMultiValues` (headers, query parameters, body parameters) and `KeysAndValues` (cookies): entries in
/// first-insertion order. A value of `None` is a Java `null` in the value list.
pub type Entries = Vec<(NString, Vec<Option<NString>>)>;

fn put(entries: &mut Entries, key: NString, values: Vec<Option<NString>>) {
    match entries.iter_mut().find(|(k, _)| k.same_key(&key)) {
        Some((_, existing)) => existing.extend(values),
        None => entries.push((key, values)),
    }
}

/// A JSON value read as `NottableString[]` (a single value is accepted as an array).
pub fn values(v: &Value) -> Vec<Option<NString>> {
    match v {
        Value::Array(items) => items.iter().map(NString::from_json).collect(),
        other => vec![NString::from_json(other)],
    }
}

/// `KeysToMultiValuesDeserializer`: map form (`{"name": [values]}`) or list form (`[{"name", "values"}]`).
/// An entry given no values is dropped (`withEntry(name, values...)` ignores an empty array).
pub fn multi_values(v: &Value) -> Entries {
    multi_values_with_style(v).0
}

/// [`multi_values`], plus the collection's `keyMatchStyle` when given in map form.
pub fn multi_values_with_style(v: &Value) -> (Entries, Option<String>) {
    let mut out = Entries::new();
    let mut style = None;
    match v {
        Value::Object(o) => {
            for (k, v) in o {
                if k == "keyMatchStyle" {
                    style = v.as_str().map(str::to_string);
                    continue;
                }
                let mut key = NString::parse(k);
                let vs = match v {
                    // `{"parameterStyle", "values"}`: the style defaults to FORM_EXPLODED.
                    Value::Object(styled) => {
                        key.parameter_style = Some(styled.get("parameterStyle").and_then(Value::as_str).unwrap_or("FORM_EXPLODED").to_string());
                        styled.get("values").map(values).unwrap_or_default()
                    }
                    other => values(other),
                };
                if !vs.is_empty() {
                    put(&mut out, key, vs);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                let Some(key) = item.get("name").and_then(NString::from_json) else { continue };
                let vs = item.get("values").map(values).unwrap_or_default();
                if !vs.is_empty() {
                    put(&mut out, key, vs);
                }
            }
        }
        _ => {}
    }
    (out, style)
}

/// `KeysToMultiValuesSerializer`: keys sorted by [`NString::cmp_descending`] (stable), in map form, or in list
/// form when any key's marked form would be misread.
pub fn multi_values_json(entries: &Entries, key_match_style: Option<&str>) -> Value {
    let mut sorted: Vec<&(NString, Vec<Option<NString>>)> = entries.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp_descending(&b.0));
    let values_json = |vs: &Vec<Option<NString>>| Value::Array(vs.iter().map(|v| v.as_ref().map(NString::to_json).unwrap_or(Value::Null)).collect());
    if sorted.iter().any(|(k, _)| k.is_ambiguous()) {
        return Value::Array(
            sorted
                .iter()
                .map(|(k, vs)| {
                    let mut o = Map::new();
                    o.insert("name".into(), k.to_json());
                    o.insert("values".into(), values_json(vs));
                    Value::Object(o)
                })
                .collect(),
        );
    }
    let mut o = Map::new();
    if let Some(style) = key_match_style.filter(|s| *s != "SUB_SET") {
        o.insert("keyMatchStyle".into(), style.into());
    }
    for (k, vs) in sorted {
        let value = match &k.parameter_style {
            Some(style) => {
                let mut styled = Map::new();
                styled.insert("parameterStyle".into(), style.clone().into());
                styled.insert("values".into(), values_json(vs));
                Value::Object(styled)
            }
            None => values_json(vs),
        };
        o.insert(k.marked(), value);
    }
    Value::Object(o)
}

/// `CookiesSerializer`: insertion order, in list form when any name would be misread.
pub fn key_values_json(entries: &Entries) -> Value {
    let value_json = |vs: &Vec<Option<NString>>| vs.first().cloned().flatten().map(|v| v.to_json()).unwrap_or(Value::Null);
    if entries.iter().any(|(k, _)| k.is_ambiguous()) {
        return Value::Array(
            entries
                .iter()
                .map(|(k, vs)| {
                    let mut o = Map::new();
                    o.insert("name".into(), k.to_json());
                    o.insert("value".into(), value_json(vs));
                    Value::Object(o)
                })
                .collect(),
        );
    }
    Value::Object(entries.iter().map(|(k, vs)| (k.marked(), value_json(vs))).collect())
}

/// `KeysAndValues` (cookies): one value per name; a repeated name keeps its first position and its last value.
pub fn key_values(v: &Value) -> Entries {
    let mut out = Entries::new();
    let mut set = |key: NString, value: Option<NString>| match out.iter_mut().find(|(k, _)| k.same_key(&key)) {
        Some((_, existing)) => *existing = vec![value],
        None => out.push((key, vec![value])),
    };
    match v {
        Value::Object(o) => {
            for (k, v) in o {
                set(NString::parse(k), NString::from_json(v));
            }
        }
        Value::Array(items) => {
            for item in items {
                let Some(key) = item.get("name").and_then(NString::from_json) else { continue };
                set(key, item.get("value").and_then(NString::from_json));
            }
        }
        _ => {}
    }
    out
}

/// A JSON tree as Jackson holds it after reading into `Map`/`JsonNode`: floating-point numbers are `Double`s and
/// print with `Double.toString`.
pub fn jackson_tree(v: &Value) -> Value {
    match v {
        Value::Number(n) if !(n.is_i64() || n.is_u64()) && n.to_string().contains(['.', 'e', 'E']) => {
            number(&java_compat::double_to_string(n.as_f64().unwrap_or(0.0)))
        }
        Value::Array(items) => Value::Array(items.iter().map(jackson_tree).collect()),
        Value::Object(o) => Value::Object(o.iter().map(|(k, v)| (k.clone(), jackson_tree(v))).collect()),
        other => other.clone(),
    }
}

/// A JSON number printed with exactly this text. `serde_json`'s parser would rewrite `1.0E7` as `1.0e+7`, so this
/// uses its doc-hidden `from_string_unchecked` (arbitrary-precision builds only); `text` must be a valid number.
pub fn number(text: &str) -> Value {
    Value::Number(serde_json::Number::from_string_unchecked(text.to_string()))
}

/// A JSON value as MockServer echoes a body or schema it parsed: read into a `Map` (floats become `Double`),
/// printed, then re-read as a tree whose floats print as `BigDecimal`s (`1e21` → `1.0E+21`).
pub fn jackson_echo_tree(v: &Value) -> Value {
    big_decimal_tree(&jackson_tree(v))
}

/// A JSON text read as a tree and printed again: floats print as `BigDecimal`s of their own text (`1.50` stays
/// `1.50`, `1e2` becomes `1E+2`).
pub fn big_decimal_tree(v: &Value) -> Value {
    match v {
        Value::Number(n) if !(n.is_i64() || n.is_u64()) && n.to_string().contains(['.', 'e', 'E']) => {
            number(&java_compat::big_decimal_to_string(&n.to_string()).unwrap_or_else(|| n.to_string()))
        }
        Value::Array(items) => Value::Array(items.iter().map(big_decimal_tree).collect()),
        Value::Object(o) => Value::Object(o.iter().map(|(k, v)| (k.clone(), big_decimal_tree(v))).collect()),
        other => other.clone(),
    }
}

/// [`big_decimal_tree`] of a tree no longer needed as it is: its floats rewritten where they are, nothing else copied.
pub fn big_decimal_in_place(v: &mut Value) {
    match v {
        // a number's text is its `as_str` (arbitrary precision); an integer has neither a point nor an exponent
        Value::Number(n) if n.as_str().contains(['.', 'e', 'E']) && !(n.is_i64() || n.is_u64()) => {
            if let Some(text) = java_compat::big_decimal_to_string(n.as_str())
                && text != n.as_str()
            {
                *v = number(&text);
            }
        }
        Value::Array(items) => items.iter_mut().for_each(big_decimal_in_place),
        Value::Object(o) => o.values_mut().for_each(big_decimal_in_place),
        _ => {}
    }
}

/// `String.valueOf` of a scalar read into a Java `Object`.
fn java_string_value(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "null".into(),
        Value::Number(_) => match jackson_tree(v) {
            Value::Number(n) => n.to_string(),
            other => other.to_string(),
        },
        other => other.to_string(),
    }
}

/// `Body.Type` constants.
pub const BODY_TYPES: &[&str] = &[
    "BINARY", "JSON", "JSON_SCHEMA", "JSON_PATH", "PARAMETERS", "MULTIPART", "REGEX", "FUZZY", "STRING", "XML",
    "XML_SCHEMA", "XPATH", "JSON_RPC", "GRAPHQL", "FILE", "WASM", "ALL_OF",
];

/// A request body as `BodyDTODeserializer` builds it; only what the generators print is kept.
#[derive(Debug, Clone, PartialEq)]
pub enum Body {
    String(String),
    Regex(String),
    Fuzzy { value: String, threshold: f64, ignore_case: bool },
    Json { value: String, match_type: String, numbers_as_strings: bool },
    JsonSchema(String),
    JsonPath(String),
    Xml(String),
    XmlSchema(String),
    XPath(String),
    Parameters(Entries),
    GraphQl { query: Option<String>, operation_name: Option<String>, variables_schema: Option<String>, selection_set_match_type: Option<String> },
    Binary(Option<Vec<u8>>),
    /// Multipart, JSON-RPC, file, WASM and all-of bodies, which the generators skip.
    Unprinted,
}

fn eq(key: &str, names: &[&str]) -> bool {
    names.iter().any(|n| n.eq_ignore_ascii_case(key))
}

/// `BodyDTODeserializer.deserialize`, in the order it inspects the fields.
pub fn request_body(v: &Value) -> Option<Body> {
    let o = match v {
        Value::String(s) => return Some(Body::String(if s.trim().is_empty() { String::new() } else { s.clone() })),
        Value::Array(_) => return Some(Body::Json { value: json::pretty(&jackson_tree(v)), match_type: "ONLY_MATCHING_FIELDS".into(), numbers_as_strings: false }),
        Value::Object(o) => o,
        _ => return None,
    };
    let mut kind: Option<String> = None;
    let mut value = String::new();
    let mut raw: Option<Vec<u8>> = None;
    let (mut threshold, mut ignore_case) = (0.8, false);
    let mut match_type = "ONLY_MATCHING_FIELDS".to_string();
    let mut numbers_as_strings = false;
    let mut parameters = None;
    let (mut graph_query, mut graph_operation, mut graph_variables, mut graph_selection) = (None, None, None, None);
    let (mut query, mut operation, mut variables, mut selection) = (None, None, None, None);
    const TYPES: &[&str] = &[
        "BINARY", "JSON", "JSON_SCHEMA", "JSON_PATH", "PARAMETERS", "MULTIPART", "REGEX", "FUZZY", "STRING", "XML",
        "XML_SCHEMA", "XPATH", "JSON_RPC", "GRAPHQL", "FILE", "WASM", "ALL_OF",
    ];
    const FIELD_TYPES: &[(&str, &str)] = &[
        ("base64bytes", "BINARY"), ("json", "JSON"), ("jsonschema", "JSON_SCHEMA"), ("jsonpath", "JSON_PATH"),
        ("regex", "REGEX"), ("fuzzy", "FUZZY"), ("string", "STRING"), ("xml", "XML"), ("xmlschema", "XML_SCHEMA"),
        ("xpath", "XPATH"), ("filepath", "FILE"), ("modulename", "WASM"),
    ];
    let pretty = |v: &Value| json::pretty(&jackson_tree(v));
    for (key, entry) in o {
        if key.eq_ignore_ascii_case("type") && let Some(t) = entry.as_str().filter(|t| TYPES.contains(t)) {
            kind = Some(t.to_string());
        }
        if key.eq_ignore_ascii_case("jsonRpc") && entry.is_object() {
            kind = Some("JSON_RPC".into());
        }
        if key.eq_ignore_ascii_case("graphQL") && let Value::Object(g) = entry {
            kind = Some("GRAPHQL".into());
            graph_query = g.get("query").map(java_string_value);
            graph_operation = g.get("operationName").map(java_string_value);
            graph_variables = g.get("variablesSchema").map(pretty);
            graph_selection = g.get("selectionSetMatchType").and_then(Value::as_str).map(str::to_string);
        }
        if eq(key, &["string", "regex", "fuzzy", "json", "jsonSchema", "jsonPath", "xml", "xmlSchema", "xpath", "base64Bytes", "filePath", "moduleName"])
            && kind.as_deref() != Some("PARAMETERS")
        {
            let lower = key.to_ascii_lowercase();
            if let Some((_, t)) = FIELD_TYPES.iter().find(|(f, _)| *f == lower) {
                kind = Some((*t).to_string());
            }
            value = if entry.is_object() || (eq(key, &["json", "jsonSchema"]) && !entry.is_string()) {
                pretty(entry)
            } else {
                java_string_value(entry)
            };
        }
        if eq(key, &["rawBytes", "base64Bytes"]) && let Some(s) = entry.as_str() && let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(s) {
            raw = Some(bytes);
        }
        if key.eq_ignore_ascii_case("matchType") && let Some(m) = entry.as_str().filter(|m| ["STRICT", "ONLY_MATCHING_FIELDS"].contains(m)) {
            match_type = m.to_string();
        }
        if key.eq_ignore_ascii_case("matchNumbersAsStrings") {
            numbers_as_strings = java_string_value(entry).eq_ignore_ascii_case("true");
        }
        if key.eq_ignore_ascii_case("threshold") && let Ok(t) = java_string_value(entry).trim().parse::<f64>() {
            threshold = t;
        }
        if key.eq_ignore_ascii_case("ignoreCase") {
            ignore_case = java_string_value(entry).eq_ignore_ascii_case("true");
        }
        if key.eq_ignore_ascii_case("query") && entry.is_string() {
            query = entry.as_str().map(str::to_string);
        }
        if key.eq_ignore_ascii_case("operationName") && entry.is_string() {
            operation = entry.as_str().map(str::to_string);
        }
        if key.eq_ignore_ascii_case("variablesSchema") {
            variables = match entry {
                Value::String(s) => Some(s.clone()),
                Value::Object(_) => Some(pretty(entry)),
                _ => variables,
            };
        }
        if key.eq_ignore_ascii_case("selectionSetMatchType") && let Some(s) = entry.as_str().filter(|s| ["SUBSET", "EXACT"].contains(s)) {
            selection = Some(s.to_string());
        }
        if key.eq_ignore_ascii_case("parameters") {
            parameters = Some(multi_values(entry));
        }
        // Upstream's mapper reads JSON arrays as `Object[]`, never `List`, so any `fields` means multipart.
        if key.eq_ignore_ascii_case("fields") || eq(key, &["filenames", "partContentTypes"]) {
            kind = Some("MULTIPART".into());
        }
        if key.eq_ignore_ascii_case("bodyAllOf") && entry.is_array() {
            kind = Some("ALL_OF".into());
        }
    }
    let Some(kind) = kind else {
        return (!o.is_empty()).then(|| Body::Json { value: pretty(v), match_type: "ONLY_MATCHING_FIELDS".into(), numbers_as_strings: false });
    };
    Some(match kind.as_str() {
        "BINARY" => Body::Binary(raw),
        "JSON" => Body::Json { value, match_type, numbers_as_strings },
        "JSON_SCHEMA" => Body::JsonSchema(value),
        "JSON_PATH" => Body::JsonPath(value),
        "PARAMETERS" => Body::Parameters(parameters.unwrap_or_default()),
        "REGEX" => Body::Regex(value),
        "FUZZY" => Body::Fuzzy { value, threshold, ignore_case },
        "STRING" => Body::String(if value.trim().is_empty() { String::new() } else { value }),
        "XML" => Body::Xml(value),
        "XML_SCHEMA" => Body::XmlSchema(value),
        "XPATH" => Body::XPath(value),
        "GRAPHQL" => Body::GraphQl {
            query: graph_query.or(query),
            operation_name: graph_operation.or(operation),
            variables_schema: graph_variables.or(variables),
            selection_set_match_type: graph_selection.or(selection),
        },
        _ => Body::Unprinted,
    })
}

/// A response body (`BodyWithContentTypeDTODeserializer`): what `HttpResponse.getBodyAsString()` returns, and
/// whether it is binary (the generators print binary bodies as bytes).
pub enum ResponseBody {
    Text(String),
    Binary(Option<Vec<u8>>),
}

pub fn response_body(v: &Value) -> Option<ResponseBody> {
    let o = match v {
        Value::String(s) => return Some(ResponseBody::Text(s.clone())),
        Value::Array(_) => return Some(ResponseBody::Text(json::pretty(&jackson_tree(v)))),
        Value::Object(o) => o,
        _ => return None,
    };
    const FIELD_TYPES: &[(&str, &str)] = &[("base64bytes", "BINARY"), ("json", "JSON"), ("string", "STRING"), ("xml", "XML"), ("filepath", "FILE")];
    const TYPES: &[&str] = &[
        "BINARY", "JSON", "JSON_SCHEMA", "JSON_PATH", "PARAMETERS", "MULTIPART", "REGEX", "FUZZY", "STRING", "XML",
        "XML_SCHEMA", "XPATH", "JSON_RPC", "GRAPHQL", "FILE", "WASM", "ALL_OF",
    ];
    let mut kind: Option<String> = None;
    let mut value = String::new();
    let mut raw = None;
    for (key, entry) in o {
        if key.eq_ignore_ascii_case("type") && let Some(t) = entry.as_str().filter(|t| TYPES.contains(t)) {
            kind = Some(t.to_string());
        }
        if eq(key, &["string", "regex", "json", "jsonSchema", "jsonPath", "xml", "xmlSchema", "xpath", "base64Bytes", "filePath"])
            && kind.as_deref() != Some("PARAMETERS")
        {
            let lower = key.to_ascii_lowercase();
            if let Some((_, t)) = FIELD_TYPES.iter().find(|(f, _)| *f == lower) {
                kind = Some((*t).to_string());
            }
            value = if entry.is_object() || (eq(key, &["json", "jsonSchema"]) && !entry.is_string()) {
                json::pretty(&jackson_tree(entry))
            } else {
                java_string_value(entry)
            };
        }
        if eq(key, &["rawBytes", "base64Bytes"]) && let Some(bytes) = entry.as_str().and_then(|s| base64::engine::general_purpose::STANDARD.decode(s).ok()) {
            raw = Some(bytes);
        }
    }
    match kind.as_deref() {
        Some("BINARY") => Some(ResponseBody::Binary(raw)),
        Some("JSON" | "STRING" | "XML") => Some(ResponseBody::Text(value)),
        // `FileBody.toString()` reads the file; unreadable files give "".
        Some("FILE") => Some(ResponseBody::Text(std::fs::read_to_string(&value).unwrap_or_default())),
        // Any other type builds nothing, and an object body that built nothing becomes `{ }`.
        Some(_) => Some(ResponseBody::Text("{ }".into())),
        None if o.is_empty() => Some(ResponseBody::Text("{ }".into())),
        None => Some(ResponseBody::Text(json::pretty(&jackson_tree(v)))),
    }
}

/// Object field lookup that treats JSON `null` as absent, like Jackson populating a DTO.
pub fn get<'a>(o: &'a Map<String, Value>, key: &str) -> Option<&'a Value> {
    o.get(key).filter(|v| !v.is_null())
}

#[cfg(test)]
mod tests {
    #[test]
    fn big_decimal_in_place_is_big_decimal_tree() {
        let text = r#"{"a":1.50,"b":[1e2,2.0E-3,7,-0.0,{"c":12345678901234567890.25,"d":"1.5"}],"e":-3,"f":1E+21,"g":0.1e1}"#;
        let parsed = crate::json::parse_lenient(text.as_bytes()).unwrap();
        let mut in_place = parsed.clone();
        super::big_decimal_in_place(&mut in_place);
        let tree = super::big_decimal_tree(&parsed);
        assert_eq!(crate::json::compact(&in_place), crate::json::compact(&tree));
        assert_eq!(in_place, tree);
    }
}
