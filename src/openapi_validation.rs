//! OpenAPI contract validation of traffic (`OpenAPIRequestValidator`, `OpenAPIResponseValidator`,
//! `OpenApiTrafficValidator`): a request against the operation its method and path select, a response against
//! that operation's declared responses, each failure a human-readable line.

use std::sync::{Arc, LazyLock};

use parking_lot::Mutex;
use serde_json::{Value, json};

use crate::matcher::json_schema_report;
use crate::request::{self, HttpRequest, MultiMap};

/// Parsed specs by their text (`OpenAPIParser`'s cache).
fn spec(spec_url_or_payload: &str) -> Result<Arc<Value>, String> {
    type Parsed = (String, Arc<Value>);
    static CACHE: LazyLock<Mutex<Vec<Parsed>>> = LazyLock::new(Default::default);
    if let Some((_, v)) = CACHE.lock().iter().find(|(k, _)| k == spec_url_or_payload) {
        return Ok(v.clone());
    }
    let mut openapi = crate::openapi::load(spec_url_or_payload)?;
    crate::openapi::add_missing_operation_ids(&mut openapi);
    let openapi = Arc::new(openapi);
    let mut cache = CACHE.lock();
    if cache.len() >= 16 {
        cache.remove(0);
    }
    cache.push((spec_url_or_payload.to_string(), openapi.clone()));
    Ok(openapi)
}

fn placeholder_count(template: &str) -> usize {
    template.matches('{').count()
}

/// A path template's `{…}` segments match any run of non-`/` characters.
fn path_matches(template: &str, path: &str) -> bool {
    let mut pattern = String::from("^");
    let mut rest = template;
    while let Some(start) = rest.find('{') {
        let Some(end) = rest[start..].find('}') else { break };
        pattern.push_str(&regex::escape(&rest[..start]));
        pattern.push_str("[^/]+");
        rest = &rest[start + end + 1..];
    }
    pattern.push_str(&regex::escape(rest));
    pattern.push('$');
    regex::Regex::new(&pattern).is_ok_and(|r| r.is_match(path))
}

/// How [`find_operation`] picks among the path templates a path matches.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Precedence {
    /// The one with fewest placeholders, ties in declaration order (`OpenAPIRequestValidator.findMatchingOperation`).
    MostSpecific,
    /// The first declared (`HttpForwardValidateActionHandler.findOperationId`).
    Declared,
}

/// The operation `method` and `path` select, the path template chosen by `precedence`. `(template, METHOD,
/// operation)`.
fn find_operation<'a>(openapi: &'a Value, path: &str, method: &str, precedence: Precedence) -> Option<(String, String, &'a Value)> {
    let paths = openapi.get("paths")?.as_object()?;
    let mut matching: Vec<(&String, &Value)> = paths.iter().filter(|(t, _)| path_matches(t, path)).collect();
    if precedence == Precedence::MostSpecific {
        matching.sort_by_key(|(t, _)| placeholder_count(t));
    }
    for (template, item) in matching {
        for m in ["get", "put", "post", "patch", "delete", "head", "options", "trace"] {
            if m.eq_ignore_ascii_case(method) && let Some(operation) = item.get(m).filter(|o| o.is_object()) {
                return Some((template.clone(), m.to_ascii_uppercase(), operation));
            }
        }
    }
    None
}

fn schema_of(v: &Value) -> Option<Value> {
    v.get("schema").filter(|s| s.is_object()).map(crate::openapi::json_schema)
}

/// The media type entry a message's `Content-Type` selects: its base type, else JSON, else `*/*`, else the first.
fn media<'a>(content: &'a Value, content_type: Option<&str>) -> Option<&'a Value> {
    let content = content.as_object()?;
    let base = content_type.map(|c| c.split(';').next().unwrap_or_default().trim().to_string());
    base.and_then(|b| content.get(&b)).or_else(|| content.get("application/json")).or_else(|| content.get("*/*")).or_else(|| content.values().next())
}

fn primary_type(schema: &Value) -> Option<String> {
    match schema.get("type") {
        Some(Value::String(t)) => Some(t.clone()),
        Some(Value::Array(types)) => types.iter().filter_map(Value::as_str).find(|t| *t != "null").map(str::to_string),
        _ => None,
    }
}

/// `validate(spec, request)`: every way `request` breaks the operation it selects.
pub fn validate_request(spec_url_or_payload: &str, request: &HttpRequest, matched_template: Option<&str>) -> Vec<String> {
    let openapi = match spec(spec_url_or_payload) {
        Ok(o) => o,
        Err(e) => return vec![format!("OpenAPI request validation failed: {e}")],
    };
    let path = if request.path.is_empty() { "/" } else { &request.path };
    let method = if request.method.is_empty() { "get" } else { &request.method };
    let Some((template, _, operation)) = find_operation(&openapi, path, method, Precedence::MostSpecific) else {
        return vec![format!("no operation found matching {} {path} in OpenAPI spec", method.to_ascii_uppercase())];
    };
    let template = matched_template.map(str::to_string).unwrap_or(template);
    let mut errors = Vec::new();
    validate_parameters(operation, request, &template, &mut errors);
    validate_request_body(operation, request, &mut errors);
    errors
}

fn path_values(template: &str, path: &str) -> Vec<(String, String)> {
    let (t, p): (Vec<&str>, Vec<&str>) = (template.split('/').collect(), path.split('/').collect());
    if t.len() != p.len() {
        return Vec::new();
    }
    t.iter()
        .zip(p)
        .filter(|(t, v)| t.len() > 2 && t.starts_with('{') && t.ends_with('}') && !v.trim().is_empty())
        .map(|(t, v)| (t[1..t.len() - 1].to_string(), v.to_string()))
        .collect()
}

fn validate_parameters(operation: &Value, request: &HttpRequest, template: &str, errors: &mut Vec<String>) {
    let Some(parameters) = operation.get("parameters").and_then(Value::as_array) else { return };
    let path_values = path_values(template, &request.path);
    for parameter in parameters {
        let (Some(name), Some(location)) = (parameter.get("name").and_then(Value::as_str), parameter.get("in").and_then(Value::as_str)) else { continue };
        let required = location == "path" || parameter.get("required").and_then(Value::as_bool) == Some(true);
        let value: Option<String> = match location {
            "query" => request.query.iter().find(|(k, _)| k == name).map(|(_, vs)| vs.first().cloned().unwrap_or_default()),
            "header" => request.first_header(name).map(str::to_string),
            "cookie" => request.cookies.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone()),
            "path" => path_values.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone()),
            _ => None,
        };
        let schema = parameter.get("schema").filter(|s| s.is_object());
        // Style-serialised arrays and objects are rebuilt into JSON (`OpenApiStyleParameterDeserializer`); a value
        // that cannot be rebuilt soundly is only checked for presence (fail-open).
        if let Some(schema) = schema.filter(|s| matches!(primary_type(s).as_deref(), Some("array" | "object"))) {
            let (present, rebuilt) = style::deserialize(parameter, location, name, schema, request, &path_values);
            if !present && value.is_none() {
                if required {
                    errors.push(format!("required {location} parameter '{name}' is missing"));
                }
                continue;
            }
            if let Some(rebuilt) = rebuilt {
                let report = json_schema_report(&crate::openapi::json_schema(schema), &rebuilt);
                if !report.trim().is_empty() {
                    errors.push(format!("{location} parameter '{name}' validation error: {report}"));
                }
            }
            continue;
        }
        let Some(value) = value else {
            if required {
                errors.push(format!("required {location} parameter '{name}' is missing"));
            }
            continue;
        };
        let Some(schema) = schema else { continue };
        let json_schema = crate::openapi::json_schema(schema);
        let coerced = match primary_type(schema).as_deref() {
            Some("integer" | "number") if is_number(&value) => value.clone(),
            Some("boolean") if value == "true" || value == "false" => value.clone(),
            None => continue,
            _ => Value::String(value.clone()).to_string(),
        };
        let report = json_schema_report(&json_schema, &coerced);
        if !report.trim().is_empty() {
            errors.push(format!("{location} parameter '{name}' validation error: {report}"));
        }
    }
}

/// `OpenApiStyleParameterDeserializer`: an array or object parameter, serialised by its `style` and `explode`,
/// rebuilt into a JSON literal whose scalars are coerced by the item or property type.
mod style {
    use serde_json::Value;

    use super::{is_number, primary_type};
    use crate::request::HttpRequest;

    /// `(present, json)`: `json` is None when the value cannot be rebuilt soundly (the schema check is skipped).
    pub(super) fn deserialize(parameter: &Value, location: &str, name: &str, schema: &Value, request: &HttpRequest, path_values: &[(String, String)]) -> (bool, Option<String>) {
        let style = parameter.get("style").and_then(Value::as_str).map(str::to_string).unwrap_or_else(|| {
            if matches!(location, "path" | "header") { "simple" } else { "form" }.to_string()
        });
        let explode = parameter.get("explode").and_then(Value::as_bool).unwrap_or(style == "form");
        let path_value = path_values.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str());
        if primary_type(schema).as_deref() == Some("array") {
            array(location, name, schema, &style, explode, request, path_value)
        } else {
            object(location, name, schema, &style, explode, request, path_value)
        }
    }

    fn primitive(t: Option<&str>) -> bool {
        matches!(t, Some("string" | "integer" | "number" | "boolean"))
    }

    /// `coerceScalarToken`.
    fn coerce(t: Option<&str>, token: &str) -> String {
        match t {
            Some("integer" | "number") if is_number(token) => token.to_string(),
            Some("boolean") if token == "true" || token == "false" => token.to_string(),
            _ => Value::String(token.to_string()).to_string(),
        }
    }

    /// `String.split(regex, -1)`.
    fn split(value: &str, pattern: &str) -> Vec<String> {
        regex::Regex::new(pattern).map(|r| r.split(value).map(str::to_string).collect()).unwrap_or_else(|_| vec![value.to_string()])
    }

    fn query_values<'a>(request: &'a HttpRequest, name: &str) -> Option<&'a Vec<String>> {
        request.query.iter().find(|(k, _)| k == name).map(|(_, vs)| vs)
    }

    fn first_query(request: &HttpRequest, name: &str) -> Option<String> {
        query_values(request, name).map(|vs| vs.first().cloned().unwrap_or_default())
    }

    fn cookie<'a>(request: &'a HttpRequest, name: &str) -> Option<&'a str> {
        request.cookies.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }

    fn array(location: &str, name: &str, schema: &Value, style: &str, explode: bool, request: &HttpRequest, path_value: Option<&str>) -> (bool, Option<String>) {
        let tokens: Option<Vec<String>> = match location {
            "query" if style == "deepObject" => None,
            "query" if explode => {
                Some(request.query.iter().filter(|(k, _)| k == name).flat_map(|(_, vs)| vs.iter().cloned()).collect())
            }
            "query" => first_query(request, name).map(|raw| {
                split(&raw, match style {
                    "spaceDelimited" => r"\s+",
                    "pipeDelimited" => r"\|",
                    _ => ",",
                })
            }),
            "path" => path_value.and_then(|raw| match style {
                "label" => Some(split(raw.strip_prefix('.').unwrap_or(raw), if explode { r"\." } else { "," })),
                "matrix" => {
                    let prefix = format!(";{name}=");
                    if !raw.starts_with(';') {
                        return None;
                    }
                    let content = raw.strip_prefix(prefix.as_str()).unwrap_or(&raw[1..]);
                    Some(split(content, &if explode { format!(";{}=", regex::escape(name)) } else { ",".into() }))
                }
                _ => Some(split(raw, ",")),
            }),
            "header" => request.first_header(name).map(|raw| split(raw, ",")),
            "cookie" => cookie(request, name).map(|raw| split(raw, ",")),
            _ => None,
        };
        let Some(tokens) = tokens.filter(|t| !t.is_empty()) else { return (false, None) };
        let items = schema.get("items").filter(|i| i.is_object());
        let item_type = items.and_then(primary_type);
        if items.is_none() || !primitive(item_type.as_deref()) {
            return (true, None);
        }
        let elements: Vec<String> = tokens.iter().map(|t| coerce(item_type.as_deref(), t)).collect();
        (true, Some(format!("[{}]", elements.join(","))))
    }

    fn object(location: &str, name: &str, schema: &Value, style: &str, explode: bool, request: &HttpRequest, path_value: Option<&str>) -> (bool, Option<String>) {
        let properties = schema.get("properties").and_then(Value::as_object);
        let pairs: Option<Vec<(String, String)>> = match location {
            "query" if style == "deepObject" => {
                let pattern = regex::Regex::new(&format!(r"^{}\[([^\]]+)]$", regex::escape(name))).expect("valid");
                let mut pairs: Vec<(String, String)> = Vec::new();
                for (k, vs) in &request.query {
                    if let (Some(m), Some(v)) = (pattern.captures(k), vs.first()) {
                        put(&mut pairs, m[1].to_string(), v.clone());
                    }
                }
                Some(pairs)
            }
            "query" if style == "form" && explode => properties.map(|p| {
                p.keys().filter_map(|k| first_query(request, k).map(|v| (k.clone(), v))).collect()
            }),
            "query" if style == "form" => first_query(request, name).and_then(|raw| alternating(split(&raw, ","))),
            "query" => None,
            "path" => path_value.and_then(|raw| match style {
                "label" => {
                    let content = raw.strip_prefix('.').unwrap_or(raw);
                    if explode { exploded(split(content, r"\.")) } else { alternating(split(content, ",")) }
                }
                "matrix" => {
                    let prefix = format!(";{name}=");
                    let content = raw.strip_prefix(prefix.as_str()).or_else(|| raw.strip_prefix(';')).unwrap_or(raw);
                    if explode { None } else { alternating(split(content, ",")) }
                }
                _ => if explode { exploded(split(raw, ",")) } else { alternating(split(raw, ",")) },
            }),
            "header" => request.first_header(name).and_then(|raw| if explode { exploded(split(raw, ",")) } else { alternating(split(raw, ",")) }),
            _ => None,
        };
        let Some(pairs) = pairs.filter(|p| !p.is_empty()) else { return (false, None) };
        let mut members = Vec::new();
        for (key, value) in &pairs {
            let property = properties.and_then(|p| p.get(key));
            let property_type = property.and_then(primary_type);
            if property.is_some() && !primitive(property_type.as_deref()) {
                return (true, None);
            }
            members.push(format!("{}:{}", Value::String(key.clone()), coerce(property_type.as_deref(), value)));
        }
        (true, Some(format!("{{{}}}", members.join(","))))
    }

    /// A `LinkedHashMap.put`: a repeated key keeps its first position and takes the last value.
    fn put(pairs: &mut Vec<(String, String)>, key: String, value: String) {
        match pairs.iter_mut().find(|(k, _)| *k == key) {
            Some(entry) => entry.1 = value,
            None => pairs.push((key, value)),
        }
    }

    fn alternating(tokens: Vec<String>) -> Option<Vec<(String, String)>> {
        if tokens.is_empty() || !tokens.len().is_multiple_of(2) {
            return None;
        }
        let mut pairs = Vec::new();
        for chunk in tokens.chunks(2) {
            put(&mut pairs, chunk[0].clone(), chunk[1].clone());
        }
        Some(pairs)
    }

    fn exploded(tokens: Vec<String>) -> Option<Vec<(String, String)>> {
        if tokens.is_empty() {
            return None;
        }
        let mut pairs = Vec::new();
        for token in tokens {
            let index = token.find('=').filter(|i| *i > 0)?;
            put(&mut pairs, token[..index].to_string(), token[index + 1..].to_string());
        }
        Some(pairs)
    }
}

fn is_number(value: &str) -> bool {
    static NUMBER: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"^[-+]?\d+(\.\d+)?([eE][-+]?\d+)?$").expect("valid"));
    NUMBER.is_match(value)
}

fn validate_request_body(operation: &Value, request: &HttpRequest, errors: &mut Vec<String>) {
    let Some(body) = operation.get("requestBody").filter(|b| b.is_object()) else { return };
    let text = request.body_str();
    if text.trim().is_empty() {
        if body.get("required").and_then(Value::as_bool) == Some(true) {
            errors.push("request body is required but was empty".into());
        }
        return;
    }
    let Some(content) = body.get("content").filter(|c| c.as_object().is_some_and(|o| !o.is_empty())) else { return };
    let Some(schema) = media(content, request.first_header("content-type")).and_then(schema_of) else { return };
    let report = json_schema_report(&schema, &text);
    if !report.trim().is_empty() {
        errors.push(format!("request body validation error: {report}"));
    }
}

/// A response as the validators read it.
pub struct Response<'a> {
    pub status: u32,
    pub headers: &'a MultiMap,
    pub body: &'a str,
}

/// `OpenAPIResponseValidator.validate`: how `response` breaks what operation `operation_id` declares for its status.
pub fn validate_response(spec_url_or_payload: &str, operation_id: &str, response: &Response) -> Vec<String> {
    let openapi = match spec(spec_url_or_payload) {
        Ok(o) => o,
        Err(e) => return vec![format!("OpenAPI response validation for operation {operation_id} failed: {e}")],
    };
    let operation = ["paths", "webhooks"].iter().filter_map(|s| openapi.get(*s).and_then(Value::as_object)).flat_map(|items| items.values()).flat_map(crate::openapi::map_operations).map(|(_, o)| o).find(|o| o.get("operationId").and_then(Value::as_str) == Some(operation_id));
    let Some(operation) = operation else { return vec![format!("operation {operation_id} not found in OpenAPI spec")] };
    let status = response.status.to_string();
    let responses = operation.get("responses").and_then(Value::as_object);
    let bucket = format!("{}XX", &status[..1]);
    let declared = responses.and_then(|r| {
        r.get(&status).or_else(|| r.iter().find(|(k, _)| k.eq_ignore_ascii_case(&bucket)).map(|(_, v)| v)).or_else(|| r.get("default"))
    });
    let Some(declared) = declared else {
        let available = responses.filter(|r| !r.is_empty()).map(|r| r.keys().cloned().collect::<Vec<_>>().join(", ")).unwrap_or_else(|| "none".into());
        return vec![format!("response status code {status} not defined in OpenAPI spec for operation {operation_id} - defined response status codes are {available}")];
    };
    let mut errors = Vec::new();
    if let Some(content) = declared.get("content").filter(|c| c.as_object().is_some_and(|o| !o.is_empty())) && !response.body.trim().is_empty() && let Some(schema) = media(content, request::first(response.headers, "content-type")).and_then(schema_of) {
        let report = json_schema_report(&schema, response.body);
        if !report.trim().is_empty() {
            errors.push(format!("response body validation error: {report}"));
        }
    }
    for (name, definition) in declared.get("headers").and_then(Value::as_object).into_iter().flatten() {
        let value = request::first(response.headers, name).filter(|v| !v.trim().is_empty());
        let Some(value) = value else {
            if definition.get("required").and_then(Value::as_bool) == Some(true) {
                errors.push(format!("required response header {name} not found in response"));
            }
            continue;
        };
        let Some(schema) = definition.get("schema").filter(|s| s.is_object()) else { continue };
        let text = match primary_type(schema).as_deref() {
            Some("integer" | "number" | "boolean") => value.to_string(),
            _ => Value::String(value.to_string()).to_string(),
        };
        let report = json_schema_report(&crate::openapi::json_schema(schema), &text);
        if !report.trim().is_empty() {
            errors.push(format!("response header {name} validation error: {report}"));
        }
    }
    errors
}

/// `resolveOperationId`: the operation id a request selects, if any.
pub fn operation_id(spec_url_or_payload: &str, request: &HttpRequest) -> Option<String> {
    let openapi = spec(spec_url_or_payload).ok()?;
    let method = if request.method.is_empty() { "get" } else { &request.method };
    let (_, _, operation) = find_operation(&openapi, &request.path, method, Precedence::MostSpecific)?;
    operation.get("operationId").and_then(Value::as_str).map(str::to_string)
}

/// `handleTrafficValidate`'s SSRF check: a spec URL (`OpenAPIParser.isSpecUrl`, a `.json`/`.yaml`/`.yml` suffix)
/// with an `http`/`https` scheme has its host checked by `InetAddressValidator` before anything is fetched.
pub fn spec_fetch_blocked(state: &crate::state::State, spec: &str) -> Option<String> {
    if ![".json", ".yaml", ".yml"].iter().any(|suffix| spec.ends_with(suffix)) {
        return None;
    }
    let uri = crate::java_uri::parse(spec.trim()).ok()?;
    let scheme = uri.scheme.as_deref()?;
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return None;
    }
    let host = uri.host.filter(|h| !h.trim().is_empty())?;
    crate::ws_relay::blocked_blocking(state, &host)
}

/// `OpenApiTrafficValidator.validate` as the `trafficValidate` report: one result per request-response pair.
pub fn traffic_report(spec_url_or_payload: &str, pairs: &[(HttpRequest, Response)]) -> Result<Value, String> {
    let openapi = spec(spec_url_or_payload)?;
    let mut results = Vec::new();
    for (request, response) in pairs {
        let path = if request.path.is_empty() { "/".to_string() } else { request.path.clone() };
        let method = if request.method.is_empty() { "GET".to_string() } else { request.method.to_ascii_uppercase() };
        let result = match find_operation(&openapi, &path, &method, Precedence::MostSpecific) {
            None => json!({
                "method": method, "path": path, "matchedOperation": null, "passed": false,
                "requestErrors": [format!("no matching operation found for {method} {path}")], "responseErrors": [],
            }),
            Some((template, verb, operation)) => {
                let operation_id = operation.get("operationId").and_then(Value::as_str).unwrap_or_default().to_string();
                let request_errors = validate_request(spec_url_or_payload, request, Some(&template));
                let response_errors = validate_response(spec_url_or_payload, &operation_id, response);
                let passed = request_errors.is_empty() && response_errors.is_empty();
                json!({
                    "method": method, "path": path, "matchedOperation": format!("{verb} {template}"), "passed": passed,
                    "requestErrors": request_errors, "responseErrors": response_errors,
                })
            }
        };
        results.push(result);
    }
    let passed = results.iter().filter(|r| r["passed"] == Value::Bool(true)).count();
    Ok(json!({
        "totalRequests": results.len(),
        "passed": passed,
        "failed": results.len() - passed,
        "allPassed": passed == results.len(),
        "results": results,
    }))
}

/// `HttpForwardValidateActionHandler.findOperationId`: the operation id of the first declared operation whose path
/// template matches the request's path and whose method is the request's; `unknown` when there is none.
pub fn forward_operation_id(spec_url_or_payload: &str, request: &HttpRequest) -> String {
    let Ok(openapi) = spec(spec_url_or_payload) else { return "unknown".into() };
    let path = if request.path.is_empty() { "/" } else { &request.path };
    let method = if request.method.is_empty() { "get" } else { &request.method };
    find_operation(&openapi, path, method, Precedence::Declared)
        .and_then(|(_, _, o)| o.get("operationId").and_then(Value::as_str).map(str::to_string))
        .unwrap_or_else(|| "unknown".into())
}
