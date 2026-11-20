//! `ExpectationExportSerializer.serializeAsOpenApi`: expectations as an OpenAPI 3.0.3 document, one operation per
//! path and method (later expectations add their responses to it).

use serde_json::{Map, Value, json};

use super::{Expectation, entries, negated_or_schema, plain};

const METHODS: &[&str] = &["get", "put", "post", "delete", "options", "head", "patch", "trace"];

pub fn serialize(expectations: &[Expectation]) -> String {
    let mut paths = Map::new();
    let mut operation_ids: Vec<String> = Vec::new();
    for e in expectations {
        add_operation(&mut paths, e, &mut operation_ids);
    }
    let document = json!({
        "openapi": "3.0.3",
        "info": {
            "title": super::COLLECTION_NAME,
            "version": "1.0.0",
            "description": super::COLLECTION_DESCRIPTION,
        },
        "paths": paths,
    });
    crate::json::pretty(&document)
}

fn add_operation(paths: &mut Map<String, Value>, e: &Expectation, operation_ids: &mut Vec<String>) {
    let Some(request) = &e.request else { return };
    // A negated or schema path or method cannot be an operation.
    if request.get("path").is_some_and(negated_or_schema) || request.get("method").is_some_and(negated_or_schema) {
        return;
    }
    let raw_path = request.get("path").and_then(plain).unwrap_or_else(|| "/".into());
    let raw_path = if raw_path.is_empty() { "/".to_string() } else { raw_path };
    let path = if raw_path.starts_with('/') { raw_path } else { format!("/{raw_path}") };
    let method = request.get("method").and_then(plain).unwrap_or_else(|| "get".into()).trim().to_lowercase();
    let method = if method.is_empty() { "get".to_string() } else { method };
    if !METHODS.contains(&method.as_str()) {
        return;
    }
    let item = paths.entry(path.clone()).or_insert_with(|| json!({}));
    let item = item.as_object_mut().expect("path item");
    if let Some(existing) = item.get_mut(&method).and_then(Value::as_object_mut) {
        let responses = existing.entry("responses").or_insert_with(|| json!({}));
        add_responses(responses.as_object_mut().expect("responses"), e.response.as_ref());
        return;
    }
    let mut operation = Map::new();
    operation.insert("summary".into(), format!("{} {path}", method.to_uppercase()).into());
    operation.insert("operationId".into(), unique(e.id.clone(), operation_ids).into());
    let mut parameters: Vec<Value> = Vec::new();
    add_parameters(&mut parameters, request.get("queryStringParameters"), "query", &path);
    let emitted = add_parameters(&mut parameters, request.get("pathParameters"), "path", &path);
    for (name, _) in entries(request.get("headers")) {
        if negated_or_schema(&name) {
            continue;
        }
        parameters.push(json!({"name": plain(&name).unwrap_or_default(), "in": "header", "required": false, "schema": {"type": "string"}}));
    }
    // Every `{name}` placeholder needs its path parameter.
    let mut seen = emitted;
    let mut rest = path.as_str();
    while let Some(start) = rest.find('{') {
        let after = &rest[start + 1..];
        let Some(end) = after.find('}') else { break };
        let name = &after[..end];
        if !name.is_empty() && !name.contains(['/', '{']) && !seen.iter().any(|s| s == name) {
            seen.push(name.to_string());
            parameters.push(json!({"name": name, "in": "path", "required": true, "schema": {"type": "string"}}));
        }
        rest = &after[end + 1..];
    }
    if !parameters.is_empty() {
        operation.insert("parameters".into(), Value::Array(parameters));
    }
    let mut responses = Map::new();
    add_responses(&mut responses, e.response.as_ref());
    operation.insert("responses".into(), Value::Object(responses));
    item.insert(method, Value::Object(operation));
}

fn unique(base: String, emitted: &mut Vec<String>) -> String {
    let mut candidate = base.clone();
    let mut suffix = 2;
    while emitted.contains(&candidate) {
        candidate = format!("{base}-{suffix}");
        suffix += 1;
    }
    emitted.push(candidate.clone());
    candidate
}

/// The parameters of one location; returns the path parameters emitted.
fn add_parameters(parameters: &mut Vec<Value>, map: Option<&Value>, location: &str, path: &str) -> Vec<String> {
    let mut emitted = Vec::new();
    for (name, values) in entries(map) {
        if negated_or_schema(&name) {
            continue;
        }
        let name = plain(&name).unwrap_or_default();
        if location == "path" && !path.contains(&format!("{{{name}}}")) {
            continue;
        }
        let mut schema = Map::new();
        schema.insert("type".into(), "string".into());
        if let Some(first) = values.first().filter(|v| !negated_or_schema(v)) {
            schema.insert("example".into(), plain(first).unwrap_or_default().into());
        }
        parameters.push(json!({"name": name, "in": location, "required": location == "path", "schema": Value::Object(schema)}));
        if location == "path" {
            emitted.push(name);
        }
    }
    emitted
}

fn add_responses(responses: &mut Map<String, Value>, response: Option<&Value>) {
    match response {
        Some(r) => {
            let code = r.get("statusCode").and_then(Value::as_i64).unwrap_or(200).to_string();
            let node = responses.entry(code).or_insert_with(|| json!({}));
            let node = node.as_object_mut().expect("response");
            if !node.contains_key("description") {
                node.insert("description".into(), r.get("reasonPhrase").and_then(Value::as_str).unwrap_or("OK").into());
            }
            let content_type = entries(r.get("headers"))
                .into_iter()
                .find(|(k, _)| plain(k).is_some_and(|k| k.eq_ignore_ascii_case("content-type")))
                .and_then(|(_, vs)| vs.first().and_then(plain));
            add_body(node, r.get("body"), content_type.filter(|c| !c.trim().is_empty()));
        }
        None if responses.is_empty() => {
            responses.insert("200".into(), json!({"description": "Dynamic response (forward / callback / template / error / LLM)"}));
        }
        None => {}
    }
}

fn add_body(node: &mut Map<String, Value>, body: Option<&Value>, content_type: Option<String>) {
    let Some(body) = body.filter(|b| !b.is_null()) else { return };
    let text = super::body_text(body, content_type.as_deref());
    let media = |default: &str| content_type.clone().unwrap_or_else(|| default.to_string());
    // `emitExample`: a JSON media type's example is the JSON value itself when the text parses as JSON.
    let example = |node: &mut Map<String, Value>, media: String, text: &str| {
        let parsed = (crate::media_type::MediaType::parse(Some(&media)).is_json() && !text.trim().is_empty())
            .then(|| crate::json::parse_lenient(text.as_bytes()).ok())
            .flatten();
        let example = parsed.unwrap_or_else(|| Value::String(text.to_string()));
        node.insert("content".into(), json!({ media: {"example": example} }));
    };
    match super::body_type(body) {
        "BINARY" => {
            node.insert("content".into(), json!({ media("application/octet-stream"): {"schema": {"type": "string", "format": "binary"}} }));
        }
        "JSON" => example(node, media("application/json"), &text),
        "XML" => example(node, media("application/xml"), &text),
        "PARAMETERS" => example(node, media("application/x-www-form-urlencoded"), &text),
        "STRING" => example(node, media("text/plain"), &text),
        kind @ ("REGEX" | "FUZZY" | "JSON_SCHEMA" | "JSON_PATH" | "XPATH" | "XML_SCHEMA") => {
            let description = format!("matcher body ({kind}) — pattern not exported as a literal value");
            node.insert("content".into(), json!({ media("text/plain"): {"schema": {"type": "string", "description": description}} }));
        }
        _ => {
            if !text.is_empty() {
                let detected = super::detect_content_type(&text);
                example(node, content_type.clone().unwrap_or_else(|| detected.to_string()), &text);
            }
        }
    }
}
