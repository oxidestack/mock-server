//! `ExpectationExportSerializer.serializeAsPostmanCollection`: expectations as a Postman v2.1 collection, one item
//! per expectation, with a `baseUrl` variable.

use serde_json::{Map, Value, json};

use super::Expectation;

const SCHEMA: &str = "https://schema.getpostman.com/json/collection/v2.1.0/collection.json";

pub fn serialize(expectations: &[Expectation]) -> String {
    let items: Vec<Value> = expectations.iter().map(item).collect();
    let document = json!({
        "info": {"name": super::COLLECTION_NAME, "description": super::COLLECTION_DESCRIPTION, "schema": SCHEMA},
        "item": items,
        "variable": [{"key": "baseUrl", "value": "http://localhost:1080"}],
    });
    crate::json::pretty(&document)
}

fn item(e: &Expectation) -> Value {
    let empty = json!({});
    let request = e.request.as_ref().unwrap_or(&empty);
    // An expectation without a method has the empty one, which `stringValue` keeps.
    let method = match e.request.as_ref() {
        Some(r) => r.get("method").and_then(super::plain).unwrap_or_default(),
        None => "GET".into(),
    };
    let path = request.get("path").and_then(super::plain).unwrap_or_else(|| "/".into());
    let mut o = Map::new();
    o.insert("name".into(), format!("{} {path}", method.to_uppercase()).into());
    let mut r = Map::new();
    r.insert("method".into(), method.to_uppercase().into());
    r.insert("header".into(), key_values(request.get("headers")));
    let slashed = if path.starts_with('/') { path.clone() } else { format!("/{path}") };
    let mut url = Map::new();
    url.insert("raw".into(), format!("{{{{baseUrl}}}}{slashed}").into());
    url.insert("host".into(), json!(["{{baseUrl}}"]));
    url.insert("path".into(), Value::Array(slashed.split('/').filter(|s| !s.is_empty()).map(|s| Value::String(s.into())).collect()));
    if !super::entries(request.get("queryStringParameters")).is_empty() {
        url.insert("query".into(), key_values(request.get("queryStringParameters")));
    }
    r.insert("url".into(), Value::Object(url));
    let content_type = super::first_header_value(request.get("headers"), "content-type");
    let body = request.get("body").filter(|b| !b.is_null()).map(|b| super::body_text(b, content_type.as_deref())).filter(|b| !b.is_empty());
    if let Some(body) = body {
        r.insert("body".into(), json!({"mode": "raw", "raw": body, "options": {"raw": {"language": "json"}}}));
    }
    o.insert("request".into(), Value::Object(r));
    let mut responses = Vec::new();
    if let Some(response) = &e.response {
        let mut resp = Map::new();
        resp.insert("name".into(), "Example response".into());
        let code = response.get("statusCode").and_then(Value::as_i64).unwrap_or(200);
        // `HttpResponseStatus.valueOf(code).reasonPhrase()` when the response names no reason phrase.
        let reason = response.get("reasonPhrase").and_then(Value::as_str).map(str::to_string);
        resp.insert("status".into(), reason.unwrap_or_else(|| crate::status::reason_phrase(u32::try_from(code).unwrap_or(0))).into());
        resp.insert("code".into(), code.into());
        let content_type = super::first_header_value(response.get("headers"), "content-type");
        let body = response.get("body").filter(|b| !b.is_null());
        if let Some(body) = body {
            resp.insert("body".into(), super::body_text(body, content_type.as_deref()).into());
        }
        let mut headers = key_values(response.get("headers"));
        // The body's content type is served as Content-Type when no header sets one, so the example carries it.
        let has_content_type = super::entries(response.get("headers")).iter().any(|(k, _)| super::plain(k).is_some_and(|k| k.eq_ignore_ascii_case("content-type")));
        if let Some(body_type) = body.and_then(super::body_content_type).filter(|t| !has_content_type && !t.trim().is_empty()) {
            headers.as_array_mut().expect("header array").push(json!({"key": "Content-Type", "value": body_type}));
        }
        resp.insert("header".into(), headers);
        responses.push(Value::Object(resp));
    }
    o.insert("response".into(), Value::Array(responses));
    Value::Object(o)
}

/// Each entry's name and first value (`""` when it has none).
fn key_values(v: Option<&Value>) -> Value {
    Value::Array(
        super::entries(v)
            .into_iter()
            .map(|(k, vs)| json!({"key": super::plain(&k).unwrap_or_default(), "value": vs.first().and_then(super::plain).unwrap_or_default()}))
            .collect(),
    )
}
