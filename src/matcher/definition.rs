//! Control-plane matching of a filter against another request *definition* (`retrieve?type=ACTIVE_EXPECTATIONS`,
//! `clear`): `RequestMatchers` compiles the filter with `controlPlaneMatcher = true` and hands it each
//! expectation's `httpRequest` as the matched request, so both sides of every comparison are `NottableString`s
//! (regexes, negations, schemas) rather than received values (`HttpRequestPropertiesMatcher.matches`).

use base64::Engine;
use serde_json::{Map, Value};

use super::body::BodyMatcher;
use super::multimap::MultiMapMatcher;
use super::{PathMatcher, RequestMatcher, StringMatcher};
use crate::canonical;
use crate::request::{BodyKind, HttpRequest, MultiMap};

impl RequestMatcher {
    /// Whether this filter matches the canonical request definition `definition` (not yet negated by the
    /// definition's own `not`, which the caller applies).
    pub fn matches_definition(&self, definition: &Value) -> bool {
        if self.unsupported || self.conditional.is_some() {
            return false;
        }
        if let Some(alternatives) = self.alternatives() {
            return alternatives.iter().any(|a| a.matches_definition(definition));
        }
        self.definition_fields_match(definition) != self.not
    }

    /// The differences a failing [`RequestMatcher::matches_definition`] of an OpenAPI operation's matcher records
    /// on its way (`RegexStringMatcher` on the method and the path, fail-fast), as their log texts. Only the method
    /// and the path record one here: the fields an operation matcher fails on first.
    pub(crate) fn definition_differences(&self, d: &Value) -> Vec<String> {
        if self.unsupported || self.conditional.is_some() || self.openapi.is_some() || self.not {
            return Vec::new();
        }
        let absent = StringMatcher::from_text("");
        let failed = |matcher: Option<&StringMatcher>, value: Option<StringMatcher>| -> Option<String> {
            let value = value.filter(|v| !v.raw_value().trim().is_empty())?;
            let matcher = matcher.unwrap_or(&absent);
            (!matcher.matches_nottable(&value, true))
                .then(|| super::Difference::String { expected: matcher.printed(), found: value.printed() }.log_text())
        };
        if let Some(text) = failed(self.method.as_ref(), d.get("method").map(StringMatcher::compile)) {
            return vec![text];
        }
        let d_has_parameters = d.get("pathParameters").is_some_and(non_empty_map);
        let d_path = d.get("path").map(|p| PathMatcher::compile(p, d_has_parameters).matcher);
        failed(self.path.as_ref().map(|p| &p.matcher), d_path).into_iter().collect()
    }

    fn definition_fields_match(&self, d: &Value) -> bool {
        let value = |k: &str| d.get(k).map(StringMatcher::compile);
        let blank = |m: &Option<StringMatcher>| m.as_ref().is_none_or(|m| m.raw_value().trim().is_empty());
        let d_has_parameters = d.get("pathParameters").is_some_and(non_empty_map);
        let d_path = d.get("path").map(|p| PathMatcher::compile(p, d_has_parameters));
        let d_path_value = d_path.as_ref().map(|p| p.original().to_string()).unwrap_or_default();

        // METHOD
        let method = value("method");
        // An absent filter method or path is the blank string (`HttpRequest` defaults), which still fails a negated
        // or schema value on the other side.
        let absent = StringMatcher::from_text("");
        if !blank(&method) && !self.method.as_ref().unwrap_or(&absent).matches_nottable(method.as_ref().unwrap(), true) {
            return false;
        }

        // PATH: the filter's path against the definition's, normalised as a template (`{name}` parts as `.*`).
        let mut path_ok = d_path.as_ref().is_none_or(|p| p.matcher.raw_value().trim().is_empty())
            || self.path.as_ref().map_or(&absent, |m| &m.matcher).matches_nottable(&d_path.as_ref().unwrap().matcher, true);
        let d_parameters = d.get("pathParameters").map(MultiMapMatcher::compile).unwrap_or_default();
        // With path parameters of its own, the filter extracts them from the definition's path.
        let actual_parameters = match self.path.as_ref().filter(|_| !self.path_parameters.is_empty()).and_then(|p| p.extract(&d_path_value, &[])) {
            Some(Ok(extracted)) => MultiMapMatcher::compile(&merged(d.get("pathParameters"), &extracted)),
            Some(Err(_)) => {
                if self.has_path() {
                    path_ok = false;
                }
                d_parameters
            }
            None => d_parameters,
        };
        if !path_ok {
            return false;
        }

        // BODY
        let d_request = as_request(d);
        if !self.body_matches_definition(d, &d_request) {
            return false;
        }

        // HEADERS, COOKIES
        let map = |k: &str| d.get(k).map(MultiMapMatcher::compile).unwrap_or_default();
        if !self.headers.matches_definition(&map("headers")) {
            return false;
        }
        if !self.cookies.matches_definition(&d.get("cookies").map(MultiMapMatcher::compile_single).unwrap_or_default()) {
            return false;
        }

        // PATH_PARAMETERS: the values the definition's template extracts from the filter's path (added to the
        // filter's own) are matched against the definition's path parameters.
        if self.has_path() {
            let filter_path = self.path.as_ref().map(|p| p.original().to_string()).unwrap_or_default();
            let filter_parameters = self.definition.get("pathParameters");
            let expected = match d_path.as_ref().and_then(|p| p.extract(&filter_path, &[])) {
                Some(Ok(extracted)) => merged(filter_parameters, &extracted),
                Some(Err(_)) => Value::Object(Map::new()),
                None => filter_parameters.cloned().unwrap_or(Value::Object(Map::new())),
            };
            if !MultiMapMatcher::compile(&expected).matches_definition(&actual_parameters) {
                return false;
            }
        }

        // QUERY_PARAMETERS
        if !self.query.matches_definition(&map("queryStringParameters")) {
            return false;
        }

        // KEEP_ALIVE, SECURE (`BooleanMatcher`: an absent value only satisfies an absent matcher), PROTOCOL
        let flag = |k: &str| d.get(k).and_then(Value::as_bool);
        if self.keep_alive.is_some_and(|k| flag("keepAlive") != Some(k)) || self.secure.is_some_and(|s| flag("secure") != Some(s)) {
            return false;
        }
        if self.protocol.as_deref().is_some_and(|p| d.get("protocol").and_then(Value::as_str) != Some(p)) {
            return false;
        }
        self.client_certificate_difference(&d_request).is_none() && self.jwt_difference(&d_request).is_none()
    }

    /// `HttpRequestPropertiesMatcher.bodyMatches` on the control plane: equal string forms match outright; else the
    /// filter's body matcher over the definition's body; else the definition's body read back as a body definition
    /// (`StrictBodyDTODeserializer`) and matched, as a matcher, over the filter's body.
    fn body_matches_definition(&self, d: &Value, d_request: &HttpRequest) -> bool {
        let Some(matcher) = &self.body else { return true };
        let filter_body = self.definition.get("body");
        let d_body = d.get("body");
        if let (Some(f), Some(b)) = (filter_body, d_body) && body_to_string(f).to_lowercase() == body_to_string(b).to_lowercase() {
            return true;
        }
        if matcher.matches(d_request, true) {
            return true;
        }
        let text = match d_body {
            Some(b) => body_as_json_or_xml_string(b, d_request.first_header("content-type")),
            None => return false,
        };
        if text.trim().is_empty() {
            return false;
        }
        match strict_body_definition(&text) {
            Some(body) => BodyMatcher::compile(&canonical::body(&body)).matches(&as_request(&self.definition), true),
            None => false,
        }
    }
}

fn non_empty_map(v: &Value) -> bool {
    v.as_object().is_some_and(|m| m.keys().any(|k| k != "keyMatchStyle")) || v.as_array().is_some_and(|a| !a.is_empty())
}

/// `extractPathParameters`: the `base` path parameters, with each extracted value they do not hold yet added.
fn merged(base: Option<&Value>, extracted: &MultiMap) -> Value {
    let mut out = match base {
        Some(Value::Object(o)) => o.clone(),
        Some(Value::Array(items)) => {
            let mut items = items.clone();
            for (name, values) in extracted {
                items.push(serde_json::json!({"name": name, "values": values}));
            }
            return Value::Array(items);
        }
        _ => Map::new(),
    };
    for (name, values) in extracted {
        let slot = out.entry(name.clone()).or_insert_with(|| Value::Array(Vec::new()));
        if !slot.is_array() {
            *slot = Value::Array(vec![slot.clone()]);
        }
        let list = slot.as_array_mut().expect("array");
        for v in values {
            if !list.iter().any(|e| e.as_str() == Some(v)) {
                list.push(Value::String(v.clone()));
            }
        }
    }
    Value::Object(out)
}

/// A definition as the request its body and headers describe: plain header values, and the body as
/// `getBodyAsString()` (a binary body as its bytes).
fn as_request(d: &Value) -> HttpRequest {
    let headers: MultiMap = match d.get("headers") {
        Some(Value::Object(o)) => o
            .iter()
            .filter(|(k, _)| k.as_str() != "keyMatchStyle")
            .map(|(k, vs)| (k.trim_start_matches(['!', '?']).to_string(), plain_values(vs)))
            .collect(),
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|i| Some((i.get("name")?.as_str()?.to_string(), plain_values(i.get("values").unwrap_or(&Value::Null)))))
            .collect(),
        _ => MultiMap::new(),
    };
    let body: Vec<u8> = match d.get("body") {
        Some(b) if body_type(b).as_deref() == Some("BINARY") => base64::engine::general_purpose::STANDARD
            .decode(b.get("base64Bytes").and_then(Value::as_str).unwrap_or_default())
            .unwrap_or_default(),
        Some(b) => body_to_string(b).into_bytes(),
        None => Vec::new(),
    };
    HttpRequest {
        method: d.get("method").and_then(Value::as_str).unwrap_or_default().to_string(),
        path: d.get("path").and_then(Value::as_str).unwrap_or_default().to_string(),
        headers,
        body: body.into(),
        body_kind: BodyKind::PlainString,
        ..HttpRequest::default()
    }
}

fn plain_values(v: &Value) -> Vec<String> {
    match v {
        Value::Array(items) => items.iter().filter_map(|i| i.as_str().map(str::to_string)).collect(),
        Value::String(s) => vec![s.clone()],
        _ => Vec::new(),
    }
}

/// The `type` of a canonical body: `STRING` for a string, `JSON` for an untyped object or array.
fn body_type(b: &Value) -> Option<String> {
    match b {
        Value::String(_) => Some("STRING".into()),
        Value::Object(o) => Some(canonical::body_type(o).unwrap_or_else(|| "JSON".into())),
        Value::Array(_) => Some("JSON".into()),
        _ => None,
    }
}

/// `Body.toString()`: the value of a string, JSON or XML body, a parameter body form-encoded, a binary body's
/// base64, and every other body as its JSON serialisation.
pub(crate) fn body_to_string(b: &Value) -> String {
    let text = |k: &str| match b.get(k) {
        Some(Value::String(s)) => s.clone(),
        Some(v) => crate::json::pretty(v),
        None => String::new(),
    };
    match (b, body_type(b).as_deref()) {
        (Value::String(s), _) => s.clone(),
        (Value::Object(o), Some("JSON")) if canonical::body_type(o).is_some() => text("json"),
        (Value::Object(_) | Value::Array(_), Some("JSON")) => crate::json::pretty(b),
        (_, Some("STRING")) => text("string"),
        (_, Some("XML")) => text("xml"),
        (_, Some("BINARY")) => text("base64Bytes"),
        (_, Some("PARAMETERS")) => form_encoded(b.get("parameters")),
        _ => crate::json::pretty(b),
    }
}

/// `HttpRequest.getBodyAsJsonOrXmlString`: a string body re-read through the definition's `Content-Type` charset.
fn body_as_json_or_xml_string(b: &Value, content_type: Option<&str>) -> String {
    let text = body_to_string(b);
    if b.is_string() || body_type(b).as_deref() == Some("STRING") {
        let charset = crate::media_type::MediaType::parse(content_type).charset_or_default().map(str::to_string);
        return String::from_utf8_lossy(&crate::media_type::encode(&text, charset.as_deref())).into_owned();
    }
    text
}

/// `ParameterBody.toString`: `name=value` pairs, values `URLEncoder`-encoded, joined by `&`.
fn form_encoded(parameters: Option<&Value>) -> String {
    let Some(Value::Object(o)) = parameters else { return String::new() };
    let mut pairs = Vec::new();
    for (name, values) in o.iter().filter(|(k, _)| k.as_str() != "keyMatchStyle") {
        let name = name.trim_start_matches(['!', '?']);
        let values: Vec<String> = match values {
            Value::Array(items) => items.iter().map(|v| StringMatcher::compile(v).value).collect(),
            other => vec![StringMatcher::compile(other).value],
        };
        if values.is_empty() {
            pairs.push(format!("{name}="));
        }
        for v in values {
            pairs.push(format!("{name}={}", url_encode(&v)));
        }
    }
    pairs.join("&")
}

/// `URLEncoder.encode(value, UTF-8)`.
fn url_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'-' | b'*' | b'_' => out.push(b as char),
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

const BODY_TYPES: &[&str] = &[
    "BINARY", "JSON", "JSON_SCHEMA", "JSON_PATH", "PARAMETERS", "REGEX", "FUZZY", "STRING", "XML", "XML_SCHEMA", "XPATH",
    "JSON_RPC", "GRAPHQL", "LOG_EVENT", "FILE", "WASM", "MULTIPART", "ALL_OF",
];

/// `StrictBodyDTODeserializer`: a JSON object that names its body type (a valid `type`, or a payload field such as
/// `jsonSchema`), with that type made explicit; anything else is no body definition.
fn strict_body_definition(text: &str) -> Option<Value> {
    let Ok(Value::Object(mut o)) = crate::json::parse_lenient(text.as_bytes()) else { return None };
    const PAYLOADS: &[(&str, &str)] = &[
        ("string", "STRING"),
        ("regex", "REGEX"),
        ("fuzzy", "FUZZY"),
        ("json", "JSON"),
        ("jsonSchema", "JSON_SCHEMA"),
        ("jsonPath", "JSON_PATH"),
        ("xml", "XML"),
        ("xmlSchema", "XML_SCHEMA"),
        ("xpath", "XPATH"),
        ("base64Bytes", "BINARY"),
        ("moduleName", "WASM"),
    ];
    let mut kind: Option<&str> = None;
    for (key, value) in &o {
        if key.eq_ignore_ascii_case("type") && let Some(t) = value.as_str().and_then(|t| BODY_TYPES.iter().find(|b| **b == t)) {
            kind = Some(t);
        }
        if key.eq_ignore_ascii_case("jsonRpc") && value.is_object() {
            kind = Some("JSON_RPC");
        }
        if key.eq_ignore_ascii_case("graphQL") && value.is_object() {
            kind = Some("GRAPHQL");
        }
        if kind != Some("PARAMETERS") && let Some((_, t)) = PAYLOADS.iter().find(|(p, _)| key.eq_ignore_ascii_case(p)) {
            kind = Some(t);
        }
        if (key.eq_ignore_ascii_case("fields") && !value.is_array()) || key.eq_ignore_ascii_case("filenames") || key.eq_ignore_ascii_case("partContentTypes") {
            kind = Some("MULTIPART");
        }
        if key.eq_ignore_ascii_case("bodyAllOf") && value.is_array() {
            kind = Some("ALL_OF");
        }
    }
    let kind = kind?;
    o.retain(|k, _| !k.eq_ignore_ascii_case("type"));
    o.insert("type".into(), kind.into());
    Some(Value::Object(o))
}

/// The `NullPointerException` text a request matcher's body throws in `BodyDTODeserializer`, or `None`.
/// It reads the body object's fields in order and dereferences each payload field's value (`string`, `regex`, …, any
/// case) unless the type read so far is `PARAMETERS`, so a null one throws.
pub(crate) fn body_deserialization_failure(definition: &Value) -> Option<&'static str> {
    const PAYLOADS: &[&str] = &[
        "string", "regex", "fuzzy", "json", "jsonSchema", "jsonPath", "xml", "xmlSchema", "xpath", "base64Bytes", "filePath", "moduleName",
    ];
    payload_null_failure(definition, PAYLOADS, false)
}

/// The same for a response's body, read by `BodyWithContentTypeDTODeserializer`: its payload fields
/// lack `fuzzy` and `moduleName`, and only `type` decides whether they are read.
pub(crate) fn response_body_deserialization_failure(response: &Value) -> Option<&'static str> {
    const PAYLOADS: &[&str] = &["string", "regex", "json", "jsonSchema", "jsonPath", "xml", "xmlSchema", "xpath", "base64Bytes", "filePath"];
    payload_null_failure(response, PAYLOADS, true)
}

/// What reading an expectation's DTO throws for a null payload field in one of its bodies, with Jackson's reference
/// chain, or `None`. Jackson reads the fields in the order given, so the first failing one wins.
pub(crate) fn expectation_body_failure(expectation: &Value) -> Option<(&'static str, String)> {
    const DTO: &str = "org.mockserver.serialization.model.";
    let Value::Object(fields) = expectation else { return None };
    fields.iter().find_map(|(key, value)| match key.as_str() {
        "httpRequest" => body_deserialization_failure(value).map(|cause| (cause, format!("{DTO}ExpectationDTO[\"httpRequest\"]"))),
        "httpResponse" => response_body_deserialization_failure(value)
            .map(|cause| (cause, format!("{DTO}ExpectationDTO[\"httpResponse\"]->{DTO}HttpResponseDTO[\"body\"]"))),
        "httpOverrideForwardedRequest" => value.as_object()?.iter().find_map(|(key, value)| {
            let (cause, dto) = match key.as_str() {
                "requestOverride" => (body_deserialization_failure(value)?, "HttpRequestDTO"),
                "responseOverride" => (response_body_deserialization_failure(value)?, "HttpResponseDTO"),
                _ => return None,
            };
            let chain = format!(
                "{DTO}ExpectationDTO[\"httpOverrideForwardedRequest\"]->{DTO}HttpOverrideForwardedRequestDTO[\"{key}\"]->{DTO}{dto}[\"body\"]"
            );
            Some((cause, chain))
        }),
        _ => None,
    })
}

fn payload_null_failure(definition: &Value, payloads: &[&str], response: bool) -> Option<&'static str> {
    let Some(Value::Object(body)) = definition.get("body") else { return None };
    let mut parameters = false;
    for (key, value) in body {
        let is = |name: &str| key.eq_ignore_ascii_case(name);
        // `Body.Type.valueOf(String.valueOf(value))`: an invalid name leaves the type as it was.
        if is("type") && let Some(t) = value.as_str().filter(|t| BODY_TYPES.contains(t)) {
            parameters = t == "PARAMETERS";
        }
        if response {
            if !parameters && value.is_null() && payloads.iter().any(|p| is(p)) {
                return Some("Cannot invoke \"Object.getClass()\" because the return value of \"java.util.Map$Entry.getValue()\" is null");
            }
            continue;
        }
        if (is("jsonRpc") || is("graphQL")) && value.is_object() {
            parameters = false;
        }
        if !parameters && payloads.iter().any(|p| is(p)) {
            if value.is_null() {
                return Some("Cannot invoke \"Object.getClass()\" because the return value of \"java.util.Map$Entry.getValue()\" is null");
            }
            parameters = false;
        }
        if (is("fields") && !value.is_array()) || is("filenames") || is("partContentTypes") || (is("bodyAllOf") && value.is_array()) {
            parameters = false;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::super::RequestMatcher;
    use serde_json::json;

    fn matches(filter: serde_json::Value, definition: serde_json::Value) -> bool {
        RequestMatcher::compile(&filter).matches_definition(&crate::canonical::request_definition(&definition))
    }

    #[test]
    fn schema_and_regex_values_on_the_definition_side() {
        assert!(!matches(json!({"method": "GET"}), json!({"method": {"schema": {"type": "string", "pattern": "^P.{2,3}$"}}})));
        assert!(matches(json!({"method": "PUT"}), json!({"method": {"schema": {"type": "string", "pattern": "^P.{2,3}$"}}})));
        assert!(matches(json!({"headers": {"someKey": ["someValue"]}}), json!({"headers": {"someK[a-z]{2}": ["someV[a-z]{4}"]}})));
        assert!(matches(json!({"path": "/some/path/someValue"}), json!({"path": "/some/path/{someKey}", "pathParameters": {"someK[a-z]{2}": ["someV[a-z]{4}"]}})));
    }

    #[test]
    fn an_absent_filter_method_or_path_fails_negated_and_schema_values() {
        assert!(!matches(json!({}), json!({"method": "!POST"})));
        assert!(!matches(json!({}), json!({"path": {"not": true, "value": "/x"}})));
        assert!(!matches(json!({}), json!({"method": {"schema": {"type": "string", "enum": ["GET", "POST"]}}})));
        assert!(matches(json!({}), json!({"method": "POST", "path": "/x"})));
    }

    #[test]
    fn absent_booleans_satisfy_only_absent_filters() {
        assert!(!matches(json!({"secure": false}), json!({})));
        assert!(!matches(json!({"keepAlive": true}), json!({})));
        assert!(matches(json!({"keepAlive": true}), json!({"keepAlive": true})));
    }

    #[test]
    fn a_body_definition_given_as_text_is_read_back_as_a_matcher() {
        let schema = "{\"type\": \"JSON_SCHEMA\", \"jsonSchema\": {\"type\": \"string\", \"pattern\": \"^someB[a-z]{3}$\"}}";
        assert!(matches(json!({"body": "\"someBody\""}), json!({"body": schema})));
        assert!(!matches(json!({"body": "\"otherBody\""}), json!({"body": schema})));
        assert!(matches(json!({"body": "somebody"}), json!({"body": {"type": "REGEX", "regex": "someb[a-z]{3}"}})));
    }

    #[test]
    fn a_null_payload_field_fails_unless_read_after_type_parameters() {
        let fails = |body: serde_json::Value| super::body_deserialization_failure(&json!({"body": body})).is_some();
        assert!(fails(json!({"type": "REGEX", "regex": null})));
        assert!(fails(json!({"Base64Bytes": null})));
        assert!(fails(json!({"regex": null, "type": "PARAMETERS"})));
        assert!(!fails(json!({"type": "PARAMETERS", "regex": null})));
        assert!(!fails(json!({"type": "PARAMETERS", "string": "x", "regex": null})));
        assert!(fails(json!({"type": "PARAMETERS", "filenames": {}, "regex": null})));
        assert!(!fails(json!({"type": "BINARY", "base64Bytes": ""})));
        assert!(!fails(json!({"type": "STRING", "not": null})));
    }
}
