//! `PUT /mockserver/generateExpectation` (`HttpState.handleGenerateExpectation`): an expectation suggested for an
//! unmatched request, added at once when `preview` is false.
//!
//! Without an LLM backend upstream answers `generateSimpleStub` at confidence 0.5. With one it prompts the backend
//! (`StubGenerationPromptBuilder`, up to 10 active expectations as context) and falls back to the same stub at
//! confidence 0.3 when the call gives no completion; a completion is read as expectations (up to `limit`, at 0.75),
//! or as the stub when it does not parse.

use jackson::JsonNode;
use serde_json::{Value, json};

use crate::reply::Reply;
use crate::request::HttpRequest;
use crate::state::State;

/// `handleGenerateExpectation`, authenticated by the caller.
pub fn route(state: &State, request: &HttpRequest) -> Reply {
    let error = crate::chaos::error;
    let body = request.body_json_or_xml_str();
    if body.trim().is_empty() {
        return error("request body is required with 'request' field");
    }
    let node = match crate::jnode::read_tree(&body) {
        Ok(node) => node,
        Err(e) => {
            let entry = crate::recorded::LogEntry::at(crate::recorded::Level::Warn, "failed to generate expectation:{}").args([e.message.as_str()]);
            crate::log::warn_event(state, entry);
            return error(&format!("failed to generate expectation: {}", e.message));
        }
    };
    if node.get("request").is_none_or(JsonNode::is_null) {
        return error("'request' field is required (the unmatched HttpRequest)");
    }
    let preview = node.path("preview").as_boolean_or(true);
    // `limit`: `asInt(1)` clamped to 1..5; it only caps the LLM's suggestions.
    let limit = node.path("limit").as_int_or(1).clamp(1, 5) as usize;
    let Some(definition) = crate::json::parse_lenient(body.as_bytes()).ok().and_then(|v| v.get("request").cloned()) else {
        return error("failed to generate expectation");
    };
    if let Err(report) = crate::schema::validate_request_definition(&definition) {
        // `objectMapper.writeValueAsString(node.get("request"))` is what the serializer echoes.
        let raw = serde_json::to_string(&definition).unwrap_or_default();
        return error(&format!("failed to parse 'request' field: {}", crate::schema::incorrect_request_matcher(&raw, &report)));
    }
    let Some(backend) = crate::llm::client::resolve_default(state) else {
        return answer(state, preview, vec![simple_stub(&definition)], 0.5, Some("Generated from request pattern (no LLM backend configured)"));
    };
    let prompt = prompt(state, &definition);
    let text = state.llm.generation.complete_blocking(state, &backend, &prompt).filter(|t| !java_blank(t));
    let Some(text) = text else {
        return answer(state, preview, vec![simple_stub(&definition)], 0.3, Some("LLM call returned no result, falling back to template"));
    };
    let suggestions: Vec<Value> = match expectations(state, &extract_json(&text)) {
        Some(parsed) => parsed.into_iter().take(limit).collect(),
        None => vec![simple_stub(&definition)],
    };
    // Added (unless `preview`) before the entry is logged.
    let confidence = if suggestions.is_empty() { 0.0 } else { 0.75 };
    let shown = suggested(state, preview, &suggestions);
    if state.info_enabled() {
        // An OpenAPI definition stands for `request().withPath("/")`.
        let path = if definition.get("specUrlOrPayload").is_some() { "/".to_string() } else { nottable_value(definition.get("path")) };
        let entry = crate::recorded::LogEntry::new(crate::log_entry::Kind::ServerConfiguration, "generated {} expectation suggestion(s) via LLM for path:{}")
            .request(request)
            .args([json!(suggestions.len()).into(), crate::log_entry::Arg::from(path.as_str())]);
        crate::log::info_event(state, entry);
    }
    reply(shown, confidence, preview, None)
}

/// The suggestions as the answer shows them: added at once unless `preview`.
fn suggested(state: &State, preview: bool, stubs: &[Value]) -> Vec<Value> {
    if preview {
        stubs.iter().filter_map(Value::as_object).map(|o| crate::control::compile_expectation(state, o).canonical).collect()
    } else if stubs.is_empty() {
        Vec::new()
    } else {
        crate::control::add_generated(state, stubs)
    }
}

/// A template stub answer.
fn answer(state: &State, preview: bool, stubs: Vec<Value>, confidence: f64, explanation: Option<&str>) -> Reply {
    reply(suggested(state, preview, &stubs), confidence, preview, explanation)
}

/// `buildGenerateExpectationResponse`.
fn reply(suggestions: Vec<Value>, confidence: f64, preview: bool, explanation: Option<&str>) -> Reply {
    let mut out = serde_json::Map::new();
    out.insert("suggestions".into(), Value::Array(suggestions));
    out.insert("confidence".into(), json!(confidence));
    out.insert("preview".into(), json!(preview));
    if let Some(explanation) = explanation {
        out.insert("explanation".into(), json!(explanation));
    }
    crate::chaos::pretty(&Value::Object(out))
}

/// `StubGenerationPromptBuilder.MAX_EXPECTATIONS_CONTEXT` and `MAX_BODY_LENGTH`.
const MAX_CONTEXT: usize = 10;
const MAX_BODY_LENGTH: usize = 2000;

/// `StubGenerationPromptBuilder.build`: the unmatched request and the first 10 active expectations' method and path.
fn prompt(state: &State, definition: &Value) -> String {
    let openapi = definition.get("specUrlOrPayload").is_some();
    let field = |k: &str| if openapi { None } else { definition.get(k) };
    let mut p = String::from("You are an API mock server assistant. Given an HTTP request that has no matching stub, ");
    p.push_str("generate a realistic MockServer expectation JSON that would be a plausible response for this request.\n\n");
    p.push_str("UNMATCHED REQUEST:\n");
    p.push_str(&format!("Method: {}\n", or_default(nottable_value(field("method")), "GET")));
    let path = or_default(if openapi { "/".into() } else { nottable_value(field("path")) }, "/");
    p.push_str(&format!("Path: {}\n", crate::llm::redact::mask_path(&path)));
    // `LlmPromptRedactor.redactHeadersAndQuery`: sensitive headers and credential-named query parameters replaced
    // whole, `code` too in an OAuth request, every other value masked as free text
    let data_plane_header = state.config.property("dataPlaneApiKeyAuthenticationHeader");
    let mut query = key_to_multi_value(field("queryStringParameters"));
    let query_values: Vec<(&str, Vec<String>)> = query.iter().map(|(n, v)| (n.1.as_str(), v.iter().map(|x| x.1.clone()).collect())).collect();
    let oauth = crate::llm::redact::oauth_request(&nottable_value(field("path")), query_values.iter().map(|(n, v)| (*n, v.as_slice())));
    drop(query_values);
    for (name, values) in &mut query {
        if crate::llm::redact::sensitive_query_parameter(&name.1) || (oauth && name.1.eq_ignore_ascii_case("code")) {
            *name = (false, name.1.clone());
            *values = vec![(false, crate::llm::redact::REDACTED.to_string())];
        }
    }
    mask_values(&mut query);
    if !query.is_empty() {
        p.push_str(&format!("Query Parameters: {}\n", java_list(&query)));
    }
    let mut headers = key_to_multi_value(field("headers"));
    for (name, values) in &mut headers {
        if crate::llm::redact::sensitive_header(&name.1, data_plane_header.as_deref()) {
            *name = (false, name.1.clone());
            *values = vec![(false, crate::llm::redact::REDACTED.to_string())];
        }
    }
    mask_values(&mut headers);
    if !headers.is_empty() {
        p.push_str(&format!("Headers: {}\n", java_list(&headers)));
    }
    // `redactBodyForPrompt`: none for a binary body; a declared JSON body is parsed even when it does not look like
    // JSON
    let body = field("body").filter(|b| b.get("type").and_then(Value::as_str) != Some("BINARY"));
    if let Some(body) = body.and_then(|b| body_as_string(b).filter(|t| !t.is_empty()).map(|t| crate::llm::redact::redact_body_text(&t, b.get("type").and_then(Value::as_str) == Some("JSON"), oauth))) {
        let units: Vec<u16> = body.encode_utf16().collect();
        let body = if units.len() > MAX_BODY_LENGTH { format!("{}...[truncated]", String::from_utf16_lossy(&units[..MAX_BODY_LENGTH])) } else { body };
        p.push_str(&format!("Request Body: {body}\n"));
    }
    p.push('\n');
    // `requestMatchers.retrieveActiveExpectations(null)`, the first ten; only `HttpRequest` matchers are listed.
    let context = state.store.retrievable();
    if !context.is_empty() {
        p.push_str("EXISTING EXPECTATIONS (for context on the API style):\n");
        for e in context.iter().take(MAX_CONTEXT) {
            let r = &e.canonical["httpRequest"];
            if e.dns.is_some() || r.get("specUrlOrPayload").is_some() {
                continue;
            }
            p.push_str(&format!("- {} {}\n", or_default(nottable_value(r.get("method")), "GET"), crate::llm::redact::mask_path(&or_default(nottable_value(r.get("path")), "/"))));
        }
        p.push('\n');
    }
    p.push_str("Generate a valid MockServer expectation JSON. Return ONLY the JSON, no explanation.\n");
    p.push_str("The expectation should:\n");
    p.push_str("1. Match the exact method and path from the unmatched request\n");
    p.push_str("2. Return a realistic HTTP response with appropriate status code (200 for GET, 201 for POST, etc.)\n");
    p.push_str("3. Include a plausible JSON response body if it looks like a REST API\n");
    p.push_str("4. Use httpRequest/httpResponse structure per MockServer format\n\n");
    p.push_str("Return the JSON expectation object only.");
    p
}

fn or_default(value: String, default: &str) -> String {
    if value.is_empty() { default.to_string() } else { value }
}

/// A `NottableString`: whether it is negated, and its value.
type Nottable = (bool, String);

/// A `KeyToMultiValue` list (`getQueryStringParameterList()`, `getHeaderList()`) from either JSON form, each entry's
/// name and values as `NottableString`s.
fn key_to_multi_value(v: Option<&Value>) -> Vec<(Nottable, Vec<Nottable>)> {
    let text = |v: &Value| match v {
        Value::String(s) => (false, s.clone()),
        Value::Object(o) => (o.get("not").and_then(Value::as_bool) == Some(true), o.get("value").and_then(Value::as_str).unwrap_or_default().to_string()),
        other => (false, crate::jnode::from_value(other).as_text()),
    };
    let values = |v: Option<&Value>| match v {
        Some(Value::Array(items)) => items.iter().map(text).collect(),
        Some(Value::Null) | None => Vec::new(),
        Some(one) => vec![text(one)],
    };
    match v {
        Some(Value::Object(map)) => map.iter().filter(|(k, _)| k.as_str() != "keyMatchStyle").map(|(k, v)| ((false, k.clone()), values(Some(v)))).collect(),
        Some(Value::Array(items)) => items.iter().map(|e| (e.get("name").map(text).unwrap_or_default(), values(e.get("values")))).collect(),
        _ => Vec::new(),
    }
}

/// `maskValues`: each value masked as free text, its negation kept.
fn mask_values(entries: &mut [(Nottable, Vec<Nottable>)]) {
    for (_, values) in entries {
        for value in values.iter_mut() {
            value.1 = crate::llm::redact::mask_value(&value.1);
        }
    }
}

/// `List.toString()` of `KeyToMultiValue`s, each its `ObjectWithJsonToString` (pretty JSON; `!` before a negated
/// `NottableString`).
fn java_list(entries: &[(Nottable, Vec<Nottable>)]) -> String {
    let shown = |(not, value): &Nottable| if *not { format!("!{value}") } else { value.clone() };
    let items: Vec<String> = entries.iter().map(|(name, values)| crate::json::pretty(&json!({"name": shown(name), "values": values.iter().map(shown).collect::<Vec<_>>()}))).collect();
    format!("[{}]", items.join(", "))
}

/// `HttpRequest.getBodyAsString()` of a request definition's body.
fn body_as_string(body: &Value) -> Option<String> {
    match body {
        Value::String(s) => Some(s.clone()),
        Value::Object(o) => {
            let ty = o.get("type").and_then(Value::as_str).unwrap_or_default();
            let key = match ty {
                "STRING" => "string",
                "JSON" => "json",
                "XML" => "xml",
                "REGEX" => "regex",
                "JSON_PATH" => "jsonPath",
                "XPATH" => "xpath",
                "JSON_SCHEMA" => "jsonSchema",
                "XML_SCHEMA" => "xmlSchema",
                _ => return Some(serde_json::to_string(body).unwrap_or_default()),
            };
            match o.get(key) {
                Some(Value::String(s)) => Some(s.clone()),
                Some(other) => Some(serde_json::to_string(other).unwrap_or_default()),
                None => None,
            }
        }
        Value::Null => None,
        other => Some(serde_json::to_string(other).unwrap_or_default()),
    }
}

/// `StringUtils.isBlank`: empty or only `Character.isWhitespace` characters.
fn java_blank(s: &str) -> bool {
    s.chars().all(|c| matches!(c, '\t'..='\r' | '\x1C'..='\x1F') || (c.is_whitespace() && !matches!(c, '\u{A0}' | '\u{2007}' | '\u{202F}')))
}

/// `extractJsonFromLlmResponse`: trimmed, a markdown code fence stripped.
fn extract_json(text: &str) -> String {
    let stripped = crate::llm::service::java_trim(text);
    if stripped.starts_with("```") && let (Some(start), Some(end)) = (stripped.find('\n'), stripped.rfind("```")) && start > 0 && end > start {
        return crate::llm::service::java_trim(&stripped[start + 1..end]).to_string();
    }
    stripped.to_string()
}

/// `ExpectationSerializer.deserializeArray(json, true)`: the expectations in input form (an OpenAPI one expanded into
/// its operations), `None` where the text is not JSON or any item fails validation.
fn expectations(state: &State, json_text: &str) -> Option<Vec<Value>> {
    if json_text.trim().is_empty() {
        return None;
    }
    let parsed = crate::json::parse_lenient(json_text.as_bytes()).ok()?;
    let items = match parsed {
        Value::Array(items) => items,
        other => vec![other],
    };
    let mut out = Vec::new();
    for item in items {
        if let Some(definition) = item.as_object().filter(|o| o.contains_key("specUrlOrPayload")) {
            crate::schema::validate_openapi_expectation(&item).ok()?;
            let built = crate::openapi::checking_spec_fetches(&state.config, || crate::openapi_expectations::build(definition, state.config.bool_property("generateRealisticExampleValues", false))).ok()?;
            out.extend(built.into_iter().map(Value::Object));
        } else {
            crate::schema::validate_expectation(&item).ok()?;
            out.push(item);
        }
    }
    Some(out)
}

/// `generateSimpleStub`: the request's method and path (their values, without `not`), answered 201 for a POST, 204
/// for a DELETE and 200 otherwise with `{"status":"ok"}`. An OpenAPI definition stands for `request().withPath("/")`.
fn simple_stub(definition: &Value) -> Value {
    let (method, path) = if definition.get("specUrlOrPayload").is_some() {
        (String::new(), "/".to_string())
    } else {
        (nottable_value(definition.get("method")), nottable_value(definition.get("path")))
    };
    let status = if method.eq_ignore_ascii_case("POST") {
        201
    } else if method.eq_ignore_ascii_case("DELETE") {
        204
    } else {
        200
    };
    let mut matcher = serde_json::Map::new();
    if !method.is_empty() {
        matcher.insert("method".into(), method.into());
    }
    if !path.is_empty() {
        matcher.insert("path".into(), path.into());
    }
    json!({
        "id": uuid::Uuid::new_v4().to_string(),
        "httpRequest": matcher,
        "httpResponse": {
            "statusCode": status,
            "body": {"type": "STRING", "string": "{\"status\":\"ok\"}", "contentType": "application/json; charset=utf-8"}
        }
    })
}

/// `NottableString.getValue()` of a method or path as given: a string, or the `value` of its object form.
fn nottable_value(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Object(o)) => o.get("value").and_then(Value::as_str).unwrap_or_default().to_string(),
        _ => String::new(),
    }
}

