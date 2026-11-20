//! `?format=recording` (`RecordedTrafficImporter`): an NDJSON archive of `HttpRequestAndHttpResponse` lines, from
//! the body or from `persistedRecordedRequestsPath`, goes back into the event log as forwarded exchanges, which
//! `retrieve` and promotion then see like live recordings. Unparseable lines are skipped and counted.

use serde_json::{Map, Value, json};

use super::{Level, Options};
use crate::reply::Reply;
use crate::request::HttpRequest;
use crate::state::State;
use crate::{canonical, json};

pub fn import(state: &State, request: &HttpRequest, options: &Options) -> Result<Reply, String> {
    let from_body = request.body_json_or_xml_str();
    let from_disk = super::query(request, "source").is_some_and(|s| s.eq_ignore_ascii_case("disk")) || from_body.trim().is_empty();
    let (pairs, skipped) = if from_disk {
        let configured = state.config.property("persistedRecordedRequestsPath").unwrap_or_else(|| "recordedRequests.ndjson".into());
        let path = std::path::Path::new(&configured);
        if !path.exists() {
            let absolute = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
            return Err(format!(
                "no persisted recorded requests archive found at {} (set mockserver.persistedRecordedRequestsPath or supply the archive in the request body)",
                absolute.display()
            ));
        }
        // Read line by line: an archive can be large.
        let mut reader = std::io::BufReader::new(std::fs::File::open(path).map_err(|e| e.to_string())?);
        let lines = std::iter::from_fn(move || {
            let mut line = Vec::new();
            match std::io::BufRead::read_until(&mut reader, b'\n', &mut line) {
                Ok(0) | Err(_) => None,
                Ok(_) => Some(String::from_utf8_lossy(&line).into_owned()),
            }
        });
        parse(state, lines)?
    } else {
        parse(state, from_body.split('\n').map(str::to_string))?
    };
    let pairs: Vec<(Option<Value>, Option<Value>)> = pairs
        .into_iter()
        .map(|(req, resp)| {
            if !options.enabled {
                return (req, resp);
            }
            let (redacted, resp) = super::redact::redact_pair(req.as_ref().unwrap_or(&Value::Null), resp.as_ref(), options);
            (req.map(|_| redacted), resp)
        })
        .collect();
    let mut shown = Vec::new();
    for (req, resp) in &pairs {
        let mut o = Map::new();
        if let Some(req) = req {
            o.insert("httpRequest".into(), canonical::request_definition(req));
        }
        if let Some(resp) = resp {
            o.insert("httpResponse".into(), canonical::response(resp));
        }
        shown.push(Value::Object(o));
        if let Some(req) = req {
            reimport(state, req, resp.as_ref());
        }
    }
    let body = if shown.is_empty() { "[]".to_string() } else { json::pretty(&shown) };
    let mut reply = Reply::api_body(201, "application/json", body);
    if skipped > 0 {
        reply.headers.insert(0, ("x-mockserver-recorded-requests-skipped".into(), skipped.to_string()));
    }
    Ok(reply)
}

type Pair = (Option<Value>, Option<Value>);

/// The intact pairs and the count of skipped lines, each skip logged; `Err` when no non-blank line parses.
fn parse(state: &State, lines: impl Iterator<Item = String>) -> Result<(Vec<Pair>, usize), String> {
    let mut pairs = Vec::new();
    let (mut skipped, mut non_blank) = (0, 0);
    for (index, line) in lines.enumerate() {
        let line = line.strip_suffix('\n').unwrap_or(&line);
        let line = line.strip_suffix('\r').unwrap_or(line).trim();
        if line.is_empty() {
            continue;
        }
        non_blank += 1;
        match deserialize(state, line) {
            Ok(pair) => pairs.push(pair),
            Err(message) => {
                skipped += 1;
                let format = format!("skipping unparseable line {} while re-importing recorded traffic archive: {message}", index + 1);
                super::event(state, Level::Warn, crate::recorded::LogEntry::at(crate::recorded::Level::Warn, format));
            }
        }
    }
    if pairs.is_empty() && non_blank > 0 {
        return Err(format!("not a recorded-traffic NDJSON archive — none of the {non_blank} non-blank line(s) could be parsed as an HttpRequestAndHttpResponse"));
    }
    if skipped > 0 {
        let format = format!("re-imported {} recorded exchange(s), skipped {skipped} unparseable line(s)", pairs.len());
        super::event(state, Level::Warn, crate::recorded::LogEntry::at(crate::recorded::Level::Warn, format));
    }
    Ok((pairs, skipped))
}

/// `HttpRequestAndHttpResponseSerializer.deserialize`: an optional `httpRequestAndHttpResponse` wrapper, then
/// `JsonSchemaValidator.isValid`; `Err` is the exception's message.
fn deserialize(state: &State, line: &str) -> Result<Pair, String> {
    let mut text = line.to_string();
    if line.contains("\"httpRequestAndHttpResponse\"") {
        match crate::jnode::read_tree(line) {
            Ok(node) => {
                if let Some(inner) = node.get("httpRequestAndHttpResponse") {
                    text = inner.to_java_string();
                }
            }
            Err(e) => {
                let format = format!("exception while parsing{{}}for HttpRequestAndHttpResponse {}", e.message);
                super::event(state, Level::Error, crate::recorded::LogEntry::new(crate::recorded::Kind::Info, format.clone()).args([line]));
                return Err(format!("exception while parsing [{line}] for HttpRequestAndHttpResponse"));
            }
        }
    }
    let incorrect = |report: &str| {
        let message = crate::matcher::format_log_message(0, "incorrect json format for:{}schema validation errors:{}", &[&text, report]);
        message.strip_suffix('\n').map(str::to_string).unwrap_or(message)
    };
    if let Err(e) = crate::jnode::read_tree(&text) {
        super::event(state, Level::Error, crate::recorded::LogEntry::at(crate::recorded::Level::Error, "exception validating JSON"));
        let class = e.class.rsplit('.').next().unwrap_or_default();
        return Err(incorrect(&format!("{class} - {}", e.message)));
    }
    let v = json::parse_lenient(text.as_bytes()).map_err(|e| incorrect(&e.to_string()))?;
    crate::schema::validate_request_and_response(&v).map_err(|report| incorrect(&report))?;
    let field = |k: &str| v.get(k).filter(|r| !r.is_null()).cloned();
    Ok((field("httpRequest"), field("httpResponse")))
}

/// The recorded expectation's serialisation (`ExpectationSerializer` with bodies by default) writes bodies typed:
/// a string with its bytes, shorthand JSON as a `JSON` body.
fn typed(mut message: Value) -> Value {
    match message.get("body").cloned() {
        Some(Value::String(text)) => {
            use base64::Engine;
            message["body"] = json!({"type": "STRING", "string": text, "rawBytes": base64::engine::general_purpose::STANDARD.encode(text.as_bytes())});
        }
        Some(b @ (Value::Object(_) | Value::Array(_))) if b.get("type").is_none() => message["body"] = json!({"type": "JSON", "json": b}),
        _ => {}
    }
    message
}

/// [`typed`] on a canonical expectation's request and responses.
pub(super) fn typed_bodies(mut expectation: Value) -> Value {
    for key in ["httpRequest", "httpResponse"] {
        if let Some(message) = expectation.get_mut(key).filter(|m| m.is_object()) {
            *message = typed(message.take());
        }
    }
    if let Some(Value::Array(responses)) = expectation.get_mut("httpResponses") {
        for response in responses {
            *response = typed(response.take());
        }
    }
    expectation
}

/// `MockServerEventLog.importRecordedRequestResponse`: a forwarded exchange with its recorded expectation.
fn reimport(state: &State, request: &Value, response: Option<&Value>) {
    let canonical_request = canonical::request_definition(request);
    let canonical_response = response.map(canonical::response);
    let recorded_response = typed(canonical_response.clone().unwrap_or(Value::Null));
    let mut recorded = Map::new();
    recorded.insert("httpRequest".into(), typed(canonical_request.clone()));
    if !recorded_response.is_null() {
        recorded.insert("httpResponse".into(), recorded_response);
    }
    recorded.insert("id".into(), uuid::Uuid::new_v4().to_string().into());
    recorded.insert("priority".into(), 0.into());
    recorded.insert("timeToLive".into(), json!({"unlimited": true}));
    recorded.insert("times".into(), json!({"remainingTimes": 1}));
    let mut input = Map::new();
    input.insert("httpRequest".into(), request.clone());
    if let Some(r) = response {
        input.insert("httpResponse".into(), r.clone());
    }
    input.insert("times".into(), json!({"remainingTimes": 1}));
    input.insert("timeToLive".into(), json!({"unlimited": true}));
    // A missing response is `null`, which `setArguments` makes "".
    let response_argument = canonical_response.clone().map_or_else(|| crate::recorded::Arg::from(""), crate::recorded::Arg::from);
    let message = crate::recorded::LogEntry::new(crate::recorded::Kind::ForwardedRequest, "re-imported recorded request:{}and response:{}from persisted archive")
        .request_json(canonical_request.clone())
        .args([crate::recorded::Arg::from(&canonical_request), response_argument]);
    // The re-imported request keeps its `socketAddress` (the report's upstream host and the sniffer read it).
    let mut model = crate::forward::request_from_json(request);
    if let Some(sa) = request.get("socketAddress").filter(|sa| sa.is_object()) {
        let host = sa.get("host").and_then(Value::as_str).unwrap_or_default().to_string();
        let secure = sa.get("scheme").and_then(Value::as_str).is_some_and(|s| s.eq_ignore_ascii_case("HTTPS"));
        let port = sa.get("port").and_then(Value::as_u64).and_then(|p| u16::try_from(p).ok()).unwrap_or(if secure { 443 } else { 80 });
        model.socket_address = Some((host, port, secure));
    }
    state.log.record_reimported(
        model,
        canonical_request,
        canonical_response.unwrap_or(Value::Null),
        (Value::Object(recorded), Value::Object(input)),
        message,
    );
}
