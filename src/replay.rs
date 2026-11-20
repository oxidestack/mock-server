//! `PUT /mockserver/replay` (`HttpState.handleReplay`): an `HttpRequest` JSON is sent again through the forwarding
//! client (the `replayHandler`, `NettyHttpClient.sendRequest(request)`: to its socket address, else its `Host`), and
//! the upstream's response comes back serialised as an `HttpResponse` JSON. Both bodies are capped at 10 MiB
//! (`REPLAY_MAX_BODY_SIZE`), and the target passes the forward's SSRF policy first.

use crate::recorded::{self, BodyForm, Level, LogEntry};
use crate::reply::Reply;
use crate::request::{self, HttpRequest, MultiMap};
use crate::state::State;
use serde_json::{Map, Value};
use std::sync::Arc;

/// `REPLAY_MAX_BODY_SIZE`.
const MAX_BODY_SIZE: usize = 10 * 1024 * 1024;

/// `HopByHopHeaderFilter.responseHeadersToRemove`, which `NettyHttpClient` applies to every response it completes.
const HOP_BY_HOP: &[&str] = &["proxy-connection", "connection", "keep-alive", "transfer-encoding", "content-length", "te", "trailer", "upgrade"];

/// Answers `PUT /mockserver/replay` (and its bare alias); `None` for any other request.
pub async fn route(state: &Arc<State>, request: &HttpRequest) -> Option<Reply> {
    if request.method != "PUT" || !matches!(request.path.as_str(), "/mockserver/replay" | "/replay") {
        return None;
    }
    if let Some(reply) = crate::auth::control_plane_refusal(state, request) {
        return Some(reply);
    }
    Some(handle(state, request).await)
}

fn error(status: u32, message: &str) -> Reply {
    Reply::api_body(status, "application/json", crate::json::compact(&serde_json::json!({"error": message})))
}

/// The handler's catch: `exception handling replay request:{}error:{}` (ERROR), answered `400 {"error": message}`.
fn failed(state: &State, request: &HttpRequest, message: &str) -> Reply {
    let entry = LogEntry::at(Level::Error, "exception handling replay request:{}error:{}")
        .request(request)
        .args([recorded::logged(request), Value::String(message.to_string())]);
    crate::log::error_event(state, entry);
    error(400, message)
}

async fn handle(state: &Arc<State>, request: &HttpRequest) -> Reply {
    let body = request.body_json_or_xml_str();
    if body.trim().is_empty() {
        return error(400, "request body must contain an HttpRequest JSON definition");
    }
    // `HttpRequestSerializer.deserialize`.
    let replayed = match crate::dashboard::parse_filter(state, &body) {
        Ok(Some(v)) => v,
        Ok(None) => return failed(state, request, "unknown error"),
        Err(message) => return failed(state, request, &message),
    };
    if crate::forward::request_from_json(&replayed).body.len() > MAX_BODY_SIZE {
        return error(413, &format!("request body exceeds maximum replay size of {MAX_BODY_SIZE} bytes"));
    }
    // `toString()` of the request: its echoed form.
    let described = crate::canonical::request_definition(&replayed);
    let socket_host = replayed.get("socketAddress").and_then(|s| s.get("host")).filter(|h| !h.is_null());
    let host_header = host_header(&replayed).filter(|h| !h.trim().is_empty());
    // `resolveReplayTargetHost`: the socket address's host, else the `Host` header's.
    let target = match (socket_host, &host_header) {
        (Some(h), _) => Some(h.as_str().map(str::to_string).unwrap_or_else(|| h.to_string())),
        (None, Some(h)) => Some(split_host_port(h).0),
        (None, None) => None,
    };
    if let Some(host) = target.filter(|h| !h.trim().is_empty()) && let Some(reason) = crate::ws_relay::blocked(state, &host).await {
        let entry = LogEntry::at(Level::Warn, "replay blocked by SSRF policy:{}").request_json(described.clone()).args([reason.clone()]);
        crate::log::warn_event(state, entry);
        return error(403, &format!("replay blocked by SSRF policy: {reason}"));
    }
    // `socketAddressFromHostHeader()`, which `sendRequest(request)` calls before anything is sent.
    let mut outbound = replayed.clone();
    if socket_host.is_none() {
        let Some(header) = &host_header else {
            // `HttpRequest.socketAddressFromHostHeader`: names the request by `getMethod("") + " " + getPath()` only.
            let message = format!(
                "Host header must be provided to determine remote socket address, the request \"{} {}\" does not include the \"Host\" header",
                nottable_text(described.get("method")),
                nottable_text(described.get("path"))
            );
            return failed(state, request, &message);
        };
        if let Some(port) = split_host_port(header).1 && port.parse::<i32>().is_err() {
            return failed(state, request, &format!("For input string: \"{port}\""));
        }
        if let Some(o) = outbound.as_object_mut() {
            o.remove("socketAddress");
        }
    }

    let timeout = std::time::Duration::from_millis(state.config.int_property("maxSocketTimeoutInMillis", 20_000).max(1) as u64);
    // `orTimeout(maxSocketTimeoutInMillis)` races the client's own read timeout, which normally answers first.
    let sent = tokio::time::timeout(timeout + std::time::Duration::from_millis(500), crate::forward::send_json(state, &outbound)).await;
    let failure = match sent {
        Err(_) => "TimeoutException".to_string(),
        Ok(Err(e)) => match &e {
            // Netty's resolver failure: an `UnknownHostException` whose message is the host alone.
            crate::client::Error::Resolve { host, .. } => host.clone(),
            _ => e.logged_message(),
        },
        Ok(Ok(mut upstream)) => {
            if let Some(mut chunks) = upstream.stream.take() {
                let mut body = bytes::BytesMut::from(&upstream.body[..]);
                while let Some(chunk) = chunks.recv().await {
                    body.extend_from_slice(&chunk);
                }
                upstream.body = body.freeze();
            }
            if upstream.body.len() > MAX_BODY_SIZE {
                return error(
                    502,
                    &format!("upstream response body exceeds maximum replay size of {MAX_BODY_SIZE} bytes — response too large to return via control plane"),
                );
            }
            return Reply::api_body(200, "application/json", crate::json::pretty(&response_json(&upstream)));
        }
    };
    let entry = LogEntry::at(Level::Warn, "exception replaying request:{}error:{}").request_json(described.clone()).args([described, Value::String(failure.clone())]);
    crate::log::warn_event(state, entry);
    error(502, &format!("replay failed: {failure}"))
}

/// A `NottableString`'s `toString()` from its echoed form (`"!x"` or `{"not": true, "value": "x"}`), `""` when absent.
fn nottable_text(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Object(o)) => {
            let text = o.get("value").and_then(Value::as_str).unwrap_or_default();
            if o.get("not").and_then(Value::as_bool) == Some(true) { format!("!{text}") } else { text.to_string() }
        }
        _ => String::new(),
    }
}

/// The first `Host` header of a request in input JSON form (either map or list form).
fn host_header(request: &Value) -> Option<String> {
    let first = |v: &Value| match v {
        Value::Array(values) => values.first().and_then(Value::as_str).map(str::to_string),
        Value::String(s) => Some(s.clone()),
        _ => None,
    };
    match request.get("headers")? {
        Value::Object(map) => map.iter().find(|(k, _)| k.eq_ignore_ascii_case("host")).and_then(|(_, v)| first(v)),
        Value::Array(entries) => entries
            .iter()
            .find(|e| e.get("name").and_then(Value::as_str).is_some_and(|n| n.eq_ignore_ascii_case("host")))
            .and_then(|e| e.get("values").and_then(first)),
        _ => None,
    }
}

/// `HttpRequest.splitHostPort`: a bracketed IPv6 host, else `String.split(":")`'s first two parts.
pub fn split_host_port(host_port: &str) -> (String, Option<String>) {
    if let Some(rest) = host_port.strip_prefix('[') && let Some(end) = rest.find(']').filter(|e| *e > 0) {
        let host = rest[..end].to_string();
        return (host, rest[end..].find(':').map(|p| rest[end + p + 1..].to_string()));
    }
    let mut parts = host_port.split(':');
    (parts.next().unwrap_or_default().to_string(), parts.next().map(str::to_string))
}

/// `HttpResponseSerializer.serialize` of the client's response: `HopByHopHeaderFilter.onResponse` (which keeps every
/// header when filtering would leave none), the cookies `FullHttpResponseToMockServerHttpResponse` reads from
/// `Set-Cookie`, and the body as its content type decodes it.
fn response_json(upstream: &crate::client::Upstream) -> Value {
    let mut all = MultiMap::new();
    for (k, v) in &upstream.headers {
        request::push(&mut all, k, v.clone());
    }
    let filtered: MultiMap = all.iter().filter(|(k, _)| !HOP_BY_HOP.iter().any(|h| k.eq_ignore_ascii_case(h))).cloned().collect();
    let headers = if filtered.is_empty() { all } else { filtered };
    let mut cookies: Vec<(String, String)> = Vec::new();
    for (_, values) in headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie")) {
        for value in values {
            if let Some((n, v)) = value.split(';').next().and_then(|p| p.split_once('=')) {
                let (n, v) = (n.trim().to_string(), unquote(v));
                match cookies.iter_mut().find(|(k, _)| *k == n) {
                    Some(existing) => existing.1 = v,
                    None => cookies.push((n, v)),
                }
            }
        }
    }
    let reason = if upstream.reason.is_empty() { crate::status::reason_phrase(upstream.status) } else { upstream.reason.clone() };
    let mut o = Map::new();
    o.insert("statusCode".into(), upstream.status.into());
    o.insert("reasonPhrase".into(), reason.into());
    if !headers.is_empty() {
        o.insert("headers".into(), recorded::literal_map_value(&headers));
    }
    if !cookies.is_empty() {
        o.insert("cookies".into(), recorded::literal_cookies_value(&cookies));
    }
    let content_type = request::first(&headers, "content-type").filter(|_| !upstream.text_body);
    if let Some(body) = recorded::body_json(&upstream.body, content_type, BodyForm::Ordered) {
        o.insert("body".into(), body);
    }
    Value::Object(o)
}

/// Netty's cookie decoder: a value wrapped in double quotes is unwrapped.
fn unquote(value: &str) -> String {
    let value = value.trim();
    match value.strip_prefix('"').and_then(|v| v.strip_suffix('"')) {
        Some(inner) if value.len() >= 2 => inner.to_string(),
        _ => value.to_string(),
    }
}
