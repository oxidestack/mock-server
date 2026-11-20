//! `PostmanCollectionImporter` (collection v2.0/v2.1): one expectation per saved example response, walking
//! folders recursively; requests without examples are skipped.

use jackson::JsonNode;
use serde_json::Value;

use super::{Options, Req, Resp, expectation, parse, path_and_query, respond, set};
use super::TextOrNull;
use crate::request::MultiMap;

pub fn import(collection: &str, options: &Options) -> Result<Vec<Value>, String> {
    if collection.trim().is_empty() {
        return Err("Postman collection JSON body is required".into());
    }
    let root = parse(collection).map_err(|e| format!("failed to parse Postman collection JSON: {e}"))?;
    if root.path("info").is_missing() {
        return Err("not a valid Postman collection — missing top-level 'info' object".into());
    }
    let Some(items) = root.path("item").as_array().cloned() else { return Err("not a valid Postman collection — missing top-level 'item' array".into()) };
    let mut expectations = Vec::new();
    walk(&items, &mut expectations);
    Ok(super::ids_from_request_matchers(super::redact::redact(expectations, options)))
}

fn walk(items: &[JsonNode], expectations: &mut Vec<Value>) {
    for item in items {
        if let Some(nested) = item.path("item").as_array().filter(|a| !a.is_empty()) {
            walk(nested, expectations);
            continue;
        }
        let Some(request) = item.get("request") else { continue };
        let Some(responses) = item.path("response").as_array().filter(|a| !a.is_empty()).cloned() else { continue };
        let name = item.text_or_null("name");
        for example in &responses {
            if let Some(e) = build(request, example, name.as_deref()) {
                expectations.push(e);
            }
        }
    }
}

fn build(request: &JsonNode, example: &JsonNode, name: Option<&str>) -> Option<Value> {
    let method = request.get("method").and_then(JsonNode::text_value)?;
    let (path, query) = url(request);
    let mut req = Req { method: Some(method.to_uppercase()), path: Some(path), ..Req::default() };
    set(&mut req.query, query);
    set(&mut req.headers, headers(&request.path("header")));
    if let Some(raw) = request.path("body").text_or_null("raw").filter(|r| !r.is_empty()) {
        req.body = Some(Value::String(raw));
    }
    let mut resp = Resp::status(example.path("code").as_int_or(200) as i64);
    set(&mut resp.headers, headers(&example.path("header")));
    if let Some(body) = example.text_or_null("body").filter(|b| !b.is_empty()) {
        resp.body = Some(Value::String(body));
    }
    let suffix = name.filter(|n| !n.is_empty()).map_or_else(|| "item".to_string(), super::slug);
    // The readable part of the id; `ids_from_request_matchers` completes it once the expectations are redacted.
    let mut e = expectation(Some(&format!("postman-{suffix}")), &req);
    respond(&mut e, &resp);
    Some(Value::Object(e))
}

/// `resolveUrl`: a string, or an object's `path` segments and `query`, else its `raw` string.
fn url(request: &JsonNode) -> (String, MultiMap) {
    let url = request.path("url");
    match &url {
        JsonNode::Text(s) => path_and_query(s),
        JsonNode::Object(_) => {
            let path = match url.path("path").as_array().filter(|a| !a.is_empty()) {
                Some(segments) => segments.iter().map(|s| format!("/{}", s.as_text())).collect(),
                None => match url.text_or_null("raw") {
                    Some(raw) => return path_and_query(&raw),
                    None => "/".to_string(),
                },
            };
            let query = url.path("query").as_array().map(|list| list.iter().filter_map(|q| Some((q.text_or_null("key")?, vec![q.text_or_null("value").unwrap_or_default()]))).collect()).unwrap_or_default();
            (path, query)
        }
        _ => ("/".into(), Vec::new()),
    }
}

fn headers(list: &JsonNode) -> MultiMap {
    let Some(list) = list.as_array() else { return Vec::new() };
    list.iter()
        .filter_map(|h| {
            let name = h.text_or_null("key").or_else(|| h.text_or_null("name"))?;
            let value = h.text_or_null("value")?;
            Some((name, vec![value]))
        })
        .collect()
}
