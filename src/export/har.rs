//! `HarConverter.serialize`: request-response pairs as a HAR 1.2 log, through the `Har*` model classes (fields in
//! declaration order, nulls left out).

use serde_json::{Map, Value, json};

use super::{Body, Pair, Request, Response, url_encode};

/// The HAR document, pretty-printed as `ObjectMapper` with `INDENT_OUTPUT` writes it.
pub fn serialize(pairs: &[Pair]) -> String {
    let entries: Vec<Value> = pairs.iter().map(entry).collect();
    let document = json!({
        "log": {
            "version": "1.2",
            "creator": {"name": "MockServer", "version": crate::control::VERSION},
            "entries": entries,
        }
    });
    crate::json::pretty(&document)
}

fn entry(pair: &Pair) -> Value {
    let timing = pair.response.as_ref().and_then(|r| r.timing.as_ref());
    let total = timing.and_then(|t| t.get("totalTimeInMillis")).and_then(Value::as_i64);
    let mut o = Map::new();
    o.insert("startedDateTime".into(), pair.timestamp.clone().unwrap_or_default().into());
    o.insert("time".into(), total.unwrap_or(0).into());
    o.insert("request".into(), request(pair.request.as_ref()));
    o.insert("response".into(), response(pair.response.as_ref()));
    o.insert("cache".into(), json!({}));
    o.insert("timings".into(), timings(timing));
    if let Some(r) = &pair.request {
        if let Some(remote) = r.remote_address.as_deref().filter(|a| !a.trim().is_empty()) {
            let remote = remote.split_once('/').map_or(remote, |(_, after)| after);
            let host = match remote.rfind(':') {
                Some(i) if i > 0 => &remote[..i],
                _ => remote,
            };
            o.insert("serverIPAddress".into(), host.into());
        } else if let Some(host) = r.socket.as_ref().and_then(|(h, _)| h.as_deref()).filter(|h| !h.trim().is_empty()) {
            o.insert("serverIPAddress".into(), host.into());
        }
        if let Some(stream) = &r.stream_id {
            o.insert("connection".into(), stream.clone().into());
        }
    }
    Value::Object(o)
}

fn name_values(items: &[(String, Vec<String>)]) -> Value {
    Value::Array(items.iter().flat_map(|(k, vs)| vs.iter().map(move |v| json!({"name": k, "value": v}))).collect())
}

fn cookies(items: &[(String, String)]) -> Value {
    Value::Array(items.iter().map(|(k, v)| json!({"name": k, "value": v})).collect())
}

fn request(r: Option<&Request>) -> Value {
    let mut o = Map::new();
    let Some(r) = r else {
        o.insert("method".into(), "".into());
        o.insert("url".into(), "".into());
        o.insert("httpVersion".into(), "HTTP/1.1".into());
        o.insert("cookies".into(), json!([]));
        o.insert("headers".into(), json!([]));
        o.insert("queryString".into(), json!([]));
        o.insert("headersSize".into(), (-1).into());
        o.insert("bodySize".into(), (-1).into());
        return Value::Object(o);
    };
    o.insert("method".into(), r.method.clone().unwrap_or_else(|| "GET".into()).into());
    o.insert("url".into(), url(r).into());
    o.insert("httpVersion".into(), http_version(r.protocol.as_deref()).into());
    o.insert("cookies".into(), cookies(&r.cookies));
    o.insert("headers".into(), name_values(&r.headers));
    o.insert("queryString".into(), name_values(&r.query));
    if let Some(body) = &r.body {
        o.insert("postData".into(), post_data(body));
    }
    o.insert("headersSize".into(), (-1).into());
    o.insert("bodySize".into(), r.body.as_ref().map_or(-1, |b| b.raw_len as i64).into());
    Value::Object(o)
}

fn post_data(body: &Body) -> Value {
    let mut o = Map::new();
    o.insert("mimeType".into(), body.content_type.clone().unwrap_or_default().into());
    match &body.parameters {
        Some(parameters) => {
            o.insert("params".into(), name_values(parameters));
        }
        None => {
            o.insert("text".into(), body.text.clone().into());
        }
    }
    Value::Object(o)
}

fn response(r: Option<&Response>) -> Value {
    let mut o = Map::new();
    let status = r.and_then(|r| r.status).unwrap_or(0);
    o.insert("status".into(), status.into());
    o.insert("statusText".into(), r.and_then(|r| r.reason.clone()).unwrap_or_default().into());
    o.insert("httpVersion".into(), "HTTP/1.1".into());
    o.insert("cookies".into(), r.map_or(json!([]), |r| cookies(&r.cookies)));
    o.insert("headers".into(), r.map_or(json!([]), |r| name_values(&r.headers)));
    let body = r.and_then(|r| r.body.as_ref());
    let mut content = Map::new();
    match body {
        None => {
            content.insert("size".into(), 0.into());
            content.insert("mimeType".into(), "".into());
        }
        Some(b) => {
            content.insert("size".into(), b.raw_len.into());
            // As served: an explicit Content-Type header wins over the body's own content type.
            let header = r.and_then(|r| r.first_header("Content-Type")).filter(|h| !h.trim().is_empty());
            content.insert("mimeType".into(), header.map(str::to_string).or_else(|| b.content_type.clone()).unwrap_or_default().into());
            if b.binary {
                if b.raw_len > 0 {
                    content.insert("text".into(), b.text.clone().into());
                    content.insert("encoding".into(), "base64".into());
                }
            } else {
                content.insert("text".into(), b.text.clone().into());
            }
        }
    }
    o.insert("content".into(), Value::Object(content));
    let location = r.and_then(|r| r.first_header("Location")).filter(|l| !l.trim().is_empty());
    o.insert("redirectURL".into(), location.unwrap_or_default().into());
    o.insert("headersSize".into(), (-1).into());
    o.insert("bodySize".into(), body.map(|b| b.raw_len).filter(|n| *n > 0).map_or(-1, |n| n as i64).into());
    Value::Object(o)
}

/// `reconstructUrl`: scheme, the socket address or else the `Host` header (else `localhost`), a non-default port,
/// the path and the query, URL-encoded.
fn url(r: &Request) -> String {
    let scheme = if r.secure { "https" } else { "http" };
    let mut port: i64 = if r.secure { 443 } else { 80 };
    let mut host: Option<String> = None;
    if let Some((h, p)) = &r.socket {
        if let Some(h) = h.as_ref().filter(|h| !h.trim().is_empty()) {
            host = Some(h.clone());
        }
        if let Some(p) = p {
            port = *p;
        }
    }
    if host.is_none() && let Some(header) = r.first_header("host").filter(|h| !h.trim().is_empty()) {
        let (h, p) = split_host_port(header);
        host = Some(h);
        if let Some(p) = p.and_then(|p| p.parse().ok()) {
            port = p;
        }
    }
    let mut url = format!("{scheme}://{}", host.unwrap_or_else(|| "localhost".into()));
    if !((r.secure && port == 443) || (!r.secure && port == 80)) {
        url.push_str(&format!(":{port}"));
    }
    match r.path.as_deref().filter(|p| !p.trim().is_empty()) {
        Some(p) => {
            if !p.starts_with('/') {
                url.push('/');
            }
            url.push_str(p);
        }
        None => url.push('/'),
    }
    let query: Vec<String> = r.query.iter().flat_map(|(k, vs)| vs.iter().map(move |v| format!("{}={}", url_encode(k), url_encode(v)))).collect();
    if !query.is_empty() {
        url.push('?');
        url.push_str(&query.join("&"));
    }
    url
}

/// `HttpRequest.splitHostPort`: a bracketed IPv6 literal loses its brackets (`[::1]:1080` gives `::1`).
fn split_host_port(value: &str) -> (String, Option<String>) {
    if let Some(rest) = value.strip_prefix('[') && let Some(end) = rest.find(']') {
        let port = rest[end..].find(':').map(|p| rest[end + p + 1..].to_string());
        return (rest[..end].to_string(), port);
    }
    // `hostPort.split(":")`: an IPv6 literal without brackets (`::1:1080`) leaves an empty host and an empty port
    let mut parts = value.split(':');
    (parts.next().unwrap_or_default().to_string(), parts.next().map(str::to_string))
}

fn http_version(protocol: Option<&str>) -> &'static str {
    match protocol {
        Some("HTTP_3") => "HTTP/3",
        Some("HTTP_2") => "HTTP/2",
        _ => "HTTP/1.1",
    }
}

/// `buildHarTimings`: all "not applicable" without a `timing`.
fn timings(timing: Option<&Value>) -> Value {
    let (send, wait, receive, connect) = match timing {
        None => (0, 0, 0, -1),
        Some(t) => {
            let get = |k: &str| t.get(k).and_then(Value::as_i64);
            let connect = get("connectionTimeInMillis").unwrap_or(0);
            let wait = match (get("timeToFirstByteInMillis"), get("responseReceivedMillis"), get("connectionEstablishedMillis")) {
                (Some(ttfb), _, _) => ttfb - connect,
                (None, Some(received), Some(established)) => received - established,
                _ => 0,
            }
            .max(0);
            let total = get("totalTimeInMillis").unwrap_or(0);
            let receive = (total - wait - connect).max(0);
            (0, wait, receive, if connect > 0 { connect } else { -1 })
        }
    };
    json!({"send": send, "wait": wait, "receive": receive, "blocked": -1, "dns": -1, "connect": connect, "ssl": -1})
}
