//! `TransportHeaderFilter`: the request headers that describe the connection or the message framing rather than the
//! request, which a recorded expectation never requires. Upstream applies it where recorded traffic becomes an
//! expectation (`MockServerEventLog.logEntryToRecordedExpectation`: every `RECORDED_EXPECTATIONS` format, promote,
//! persisted recorded expectations), each time on a copy: the stored log entry keeps them (`LOG_ENTRIES` shows them).
//! Promotion also drops `Host`, so an application calling MockServer directly matches the promoted mock.

use std::sync::Arc;

use serde_json::Value;

use crate::recorded::Exchange;

/// The hop-by-hop headers of RFC 9110 section 7.6.1, `content-length` and the forward loop guard's
/// `x-mockserver-forwarded-by` (whose values identify one run of a server), besides every `proxy-*` header.
const TRANSPORT_HEADERS: &[&str] = &["connection", "keep-alive", "te", "trailer", "transfer-encoding", "upgrade", "content-length", crate::forward_loop::HEADER];

/// `isTransportHeader`: judged by the name alone, in any case.
pub fn is_transport_header(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower.starts_with("proxy-") || TRANSPORT_HEADERS.contains(&lower.as_str())
}

/// A header name or value as either form writes it: a plain string, or a literal/not-string object's `value`.
fn text(v: &Value) -> Option<&str> {
    match v {
        Value::String(s) => Some(s),
        Value::Object(o) => o.get("value").and_then(Value::as_str),
        _ => None,
    }
}

/// The values of a map-form entry (one value or a list) or a list-form entry's `values`.
fn values(v: &Value) -> Vec<&str> {
    match v {
        Value::Array(items) => items.iter().filter_map(text).collect(),
        other => text(other).into_iter().collect(),
    }
}

/// `withoutTransportHeaders(request, stripHost)` on a request's JSON (`headers` in map or list form), in place:
/// the transport headers, those its own `Connection` header nominates and, with `strip_host`, `Host`; `headers`
/// goes when nothing is left. Whether anything was removed.
pub fn strip_request(request: &mut Value, strip_host: bool) -> bool {
    let Some(headers) = request.get_mut("headers") else { return false };
    let entries: Vec<(String, Vec<String>)> = match &*headers {
        Value::Object(o) => o.iter().map(|(k, v)| (k.clone(), values(v).into_iter().map(str::to_string).collect())).collect(),
        Value::Array(items) => items
            .iter()
            .filter_map(|i| Some((text(i.get("name")?)?.to_string(), i.get("values").map(values).unwrap_or_default().into_iter().map(str::to_string).collect())))
            .collect(),
        _ => return false,
    };
    let nominated: Vec<String> = entries
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case("connection"))
        .flat_map(|(_, vs)| vs.iter().flat_map(|v| v.split(',')).map(|t| t.trim().to_lowercase()).filter(|t| !t.is_empty()).collect::<Vec<_>>())
        .collect();
    let removed = |name: &str| is_transport_header(name) || (strip_host && name.eq_ignore_ascii_case("host")) || nominated.contains(&name.to_lowercase());
    if !entries.iter().any(|(n, _)| removed(n)) {
        return false;
    }
    let empty = match headers {
        Value::Object(o) => {
            o.retain(|k, _| !removed(k));
            o.is_empty()
        }
        Value::Array(items) => {
            items.retain(|i| !i.get("name").and_then(text).is_some_and(removed));
            items.is_empty()
        }
        _ => false,
    };
    if empty && let Some(o) = request.as_object_mut() {
        o.remove("headers");
    }
    true
}

/// An expectation's JSON (`httpRequest` inside) without its request's transport headers, in place.
pub fn strip_expectation(expectation: &mut Value, strip_host: bool) -> bool {
    expectation.get_mut("httpRequest").is_some_and(|r| strip_request(r, strip_host))
}

/// A recorded exchange as the recorded-expectation surfaces read it: both forms of its recorded expectation without
/// the transport headers (and `Host` with `strip_host`); the same exchange when there is nothing to drop.
pub fn recorded_view(exchange: Arc<Exchange>, strip_host: bool) -> Arc<Exchange> {
    let mut recorded = exchange.recorded.clone();
    let mut input = exchange.recorded_input.clone();
    let changed = recorded.as_mut().is_some_and(|e| strip_expectation(e, strip_host)) | input.as_mut().is_some_and(|e| strip_expectation(e, strip_host));
    if !changed {
        return exchange;
    }
    let mut copy = (*exchange).clone();
    copy.recorded = recorded;
    copy.recorded_input = input;
    Arc::new(copy)
}
