//! `HarImporter`: one expectation per `log.entries[]` item (method, path, query, non-volatile headers, a small
//! request body), answering the entry's status, non-volatile headers and body.

use jackson::JsonNode;
use serde_json::Value;

use super::{Options, Req, Resp, expectation, parse, path_and_query, respond, set};
use super::TextOrNull;
use crate::request::MultiMap;

/// `HarImporter.VOLATILE_REQUEST_HEADERS`, also stripped by consolidation.
pub const VOLATILE_REQUEST_HEADERS: &[&str] = &[
    "host", "date", "user-agent", "accept", "accept-encoding", "accept-language", "connection", "keep-alive", "upgrade", "transfer-encoding",
    "content-length", "cookie", "referer", "origin", "cache-control", "pragma", "if-none-match", "if-modified-since", "authorization",
    "proxy-authorization", "x-request-id", "x-correlation-id", "traceparent", "tracestate",
];

pub(super) const VOLATILE_RESPONSE_HEADERS: &[&str] = &[
    "date", "transfer-encoding", "content-length", "connection", "keep-alive", "server", "set-cookie", "age", "x-request-id", "x-correlation-id",
    "traceparent", "tracestate", "vary",
];

const MAX_REQUEST_BODY_SIZE: usize = 4096;

pub fn import(har: &str, options: &Options) -> Result<Vec<Value>, String> {
    if har.trim().is_empty() {
        return Err("HAR JSON body is required".into());
    }
    let root = parse(har).map_err(|e| format!("failed to parse HAR JSON: {e}"))?;
    let log = root.path("log");
    if log.is_missing() {
        return Err("not a valid HAR document — missing top-level 'log' object".into());
    }
    let Some(entries) = log.path("entries").as_array().cloned() else { return Err("not a valid HAR document — missing 'log.entries' array".into()) };
    let expectations = entries.iter().filter_map(entry).collect();
    Ok(super::ids_from_request_matchers(super::redact::redact(expectations, options)))
}

fn entry(entry: &JsonNode) -> Option<Value> {
    let request = entry.get("request")?;
    let response = entry.get("response")?;
    let method = request.text_or_null("method")?;
    let url = request.text_or_null("url")?;
    let (path, mut query) = path_and_query(&url);
    if let Some(list) = request.path("queryString").as_array().filter(|a| !a.is_empty()) {
        query = list.iter().filter_map(|p| Some((p.text_or_null("name")?, vec![p.text_or_null("value").unwrap_or_default()]))).collect();
    }
    let mut req = Req { method: Some(method.to_uppercase()), path: Some(path), ..Req::default() };
    set(&mut req.query, query);
    let mut headers = filter_headers(&request.path("headers"), VOLATILE_REQUEST_HEADERS);
    headers.retain(|(name, _)| !crate::transport_headers::is_transport_header(name));
    set(&mut req.headers, headers);
    if let Some(text) = request.path("postData").text_or_null("text") && !text.is_empty() && text.encode_utf16().count() <= MAX_REQUEST_BODY_SIZE {
        req.body = Some(Value::String(text));
    }

    let mut resp = Resp::status(response.path("status").as_int_or(200) as i64);
    let mut response_headers = filter_headers(&response.path("headers"), VOLATILE_RESPONSE_HEADERS);
    let content = response.path("content");
    // `content.mimeType` is the Content-Type when no response header sets one.
    if let Some(mime_type) = content.text_or_null("mimeType").filter(|m| !m.trim().is_empty()) && !response_headers.iter().any(|(name, _)| name.eq_ignore_ascii_case("content-type")) {
        response_headers.push(("Content-Type".to_string(), vec![mime_type]));
    }
    set(&mut resp.headers, response_headers);
    if let Some(mut text) = content.text_or_null("text").filter(|t| !t.is_empty()) {
        if content.text_or_null("encoding").is_some_and(|e| e.eq_ignore_ascii_case("base64")) && let Some(bytes) = super::base64_decode(&text) {
            text = String::from_utf8_lossy(&bytes).into_owned();
        }
        resp.body = Some(Value::String(text));
    }
    // The readable part of the id; `ids_from_request_matchers` completes it once the expectations are redacted.
    let mut e = expectation(Some("har"), &req);
    respond(&mut e, &resp);
    Some(Value::Object(e))
}

fn filter_headers(headers: &JsonNode, volatile: &[&str]) -> MultiMap {
    let Some(list) = headers.as_array() else { return Vec::new() };
    list.iter()
        .filter_map(|h| {
            let name = h.text_or_null("name")?;
            let value = h.text_or_null("value")?;
            (!volatile.contains(&name.to_lowercase().as_str())).then(|| (name, vec![value]))
        })
        .collect()
}
