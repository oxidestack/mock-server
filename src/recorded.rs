//! The request log and the JSON shapes MockServer uses for recorded requests.
//!
//! MockServer writes a recorded request two ways, and the oracle shows both:
//! - **flat** (`retrieve?type=REQUESTS`, verification failures): properties alphabetical, headers in Java
//!   `HashMap` iteration order, no socket addresses, typed bodies carry `rawBytes`;
//! - **ordered** (`REQUEST_RESPONSES`, logs): the matcher key order with socket addresses, headers in the
//!   descending order used for expectations, JSON bodies without `rawBytes`.

use std::collections::VecDeque;
use std::sync::Arc;

use base64::Engine;
use bytes::Bytes;
use chrono::{DateTime, Local};
use parking_lot::Mutex;
use serde_json::{Map, Value, json};

use crate::canonical;
use crate::config::Config;
pub use crate::log_entry::{Arg, Kind, Level, LogEntry};
use crate::matcher::{Mode, RequestMatcher};
use crate::request::{BodyKind, HttpRequest, MultiMap};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// A request as verification reads the event log (`requestLogPredicate`, `answeredRequestLogPredicate`): an HTTP
/// request, or the definition a DNS query's or binary message's received entry carries (upstream #97, #101).
#[derive(Clone)]
pub enum Received {
    Http(Arc<HttpRequest>),
    Definition(Value),
}

impl Received {
    pub fn http(&self) -> Option<&Arc<HttpRequest>> {
        match self {
            Received::Http(r) => Some(r),
            Received::Definition(_) => None,
        }
    }
}

/// One entry [`RequestLog::recorded_requests`] reads: the request, the id of the expectation that answered it (for
/// an answered read) and when it was logged.
#[derive(Clone)]
pub struct RecordedRequest {
    pub request: Received,
    pub expectation_id: Option<String>,
    pub millis: i64,
}

pub struct Exchange {
    /// Shared with the request's arrival entry when the log holds the same request for both.
    pub request: Arc<HttpRequest>,
    /// Canonical `httpResponse` as MockServer logs it (the action's response, or the 404); a served request's is shared
    /// with the earlier exchanges that logged an equal one ([`interned`]).
    pub response: Arc<Value>,
    pub timestamp: DateTime<Local>,
    /// For forwarded exchanges: the expectation `retrieve?type=RECORDED_EXPECTATIONS` reports.
    pub recorded: Option<Value>,
    /// The same expectation in input form, keeping header order (read by the Java code format).
    pub recorded_input: Option<Value>,
    /// The expectation that produced the response, if any (verification by expectation id).
    pub expectation_id: Option<String>,
    /// Its entry (and line in `retrieve?type=LOGS`), when upstream writes one for this kind of completion: see
    /// [`Exchange::entry`].
    entry: ExchangeEntry,
    /// A `NO_MATCH_RESPONSE`: no expectation matched (what `explainUnmatched` explains).
    pub no_match: bool,
    /// The request as `REQUEST_RESPONSES` shows it, for an exchange re-imported from an archive (the model object
    /// it was read into, not a received request).
    pub shown_request: Option<Value>,
}

/// An exchange's entry: none, built when the exchange was logged, or built the first time the log is read. Most
/// served requests' entries are never read (below INFO nothing prints them), and building one was most of the cost of
/// logging a request.
enum ExchangeEntry {
    None,
    /// Boxed: a `LogEntry` is ~600 bytes, and most exchanges hold a deferred one.
    Built(Box<LogEntry>),
    Deferred(Box<Deferred>),
}

/// What a deferred entry is built from: its call site's builder, then what logging it adds ([`completed_entry`]) in
/// the port scope it was logged in. The type is known without building it.
struct Deferred {
    kind: Kind,
    portless: bool,
    make: Box<dyn Fn(&Exchange) -> LogEntry + Send + Sync>,
    built: std::sync::OnceLock<Box<LogEntry>>,
}

impl Exchange {
    /// A completion logged now, with no entry yet.
    pub fn new(request: Arc<HttpRequest>, response: impl Into<Arc<Value>>, expectation_id: Option<String>) -> Exchange {
        Exchange {
            request,
            response: response.into(),
            timestamp: Local::now(),
            recorded: None,
            recorded_input: None,
            expectation_id,
            entry: ExchangeEntry::None,
            no_match: false,
            shown_request: None,
        }
    }

    /// The exchange with `entry` as its entry, as logged.
    pub fn with_entry(mut self, entry: Option<LogEntry>) -> Exchange {
        self.entry = entry.map_or(ExchangeEntry::None, |e| ExchangeEntry::Built(Box::new(e)));
        self
    }

    /// The exchange's entry, built now if it was deferred.
    pub fn entry(&self) -> Option<&LogEntry> {
        match &self.entry {
            ExchangeEntry::None => None,
            ExchangeEntry::Built(entry) => Some(entry),
            ExchangeEntry::Deferred(d) => Some(d.built.get_or_init(|| Box::new(completed_entry((d.make)(self), self, d.portless)))),
        }
    }

    /// The type of the exchange's entry, without building it.
    pub fn entry_kind(&self) -> Option<Kind> {
        match &self.entry {
            ExchangeEntry::None => None,
            ExchangeEntry::Built(entry) => Some(entry.kind),
            ExchangeEntry::Deferred(d) => Some(d.kind),
        }
    }

    /// The entry as its call site made it, before logging completes it.
    fn take_entry(&mut self) -> Option<LogEntry> {
        match std::mem::replace(&mut self.entry, ExchangeEntry::None) {
            ExchangeEntry::None => None,
            ExchangeEntry::Built(entry) => Some(*entry),
            ExchangeEntry::Deferred(d) => Some((d.make)(self)),
        }
    }

    /// The type a completion's entry takes when its call site set none.
    fn completion_kind(&self) -> Kind {
        match (self.no_match, self.recorded.is_some()) {
            (true, _) => Kind::NoMatchResponse,
            (_, true) => Kind::ForwardedRequest,
            _ => Kind::ExpectationResponse,
        }
    }
}

impl Clone for Exchange {
    /// A copy holds its entry built.
    fn clone(&self) -> Exchange {
        Exchange {
            request: self.request.clone(),
            response: self.response.clone(),
            timestamp: self.timestamp,
            recorded: self.recorded.clone(),
            recorded_input: self.recorded_input.clone(),
            expectation_id: self.expectation_id.clone(),
            entry: self.entry().map_or(ExchangeEntry::None, |e| ExchangeEntry::Built(Box::new(e.clone()))),
            no_match: self.no_match,
            shown_request: self.shown_request.clone(),
        }
    }
}

/// A completion's entry as the log keeps it: the exchange's type and attachments unless its call site set them, and
/// no port when logged in a portless scope.
fn completed_entry(mut entry: LogEntry, x: &Exchange, portless: bool) -> LogEntry {
    entry.portless |= portless;
    if entry.kind == Kind::Info {
        entry.kind = x.completion_kind();
    }
    if entry.requests.is_none() {
        entry = entry.request(&x.request);
    }
    if entry.correlation_id.is_none() && !x.request.log_correlation_id.is_empty() {
        entry.correlation_id = Some(x.request.log_correlation_id.clone());
    }
    if entry.response.is_none() && !x.response.is_null() {
        entry.response = Some(crate::log_entry::Json::new(logged_response(&x.response)));
    }
    // the arguments equal to the entry's response (the response, a static response action) are that value
    if let Some(response) = entry.response.clone() {
        for argument in entry.arguments.iter_mut().flatten() {
            // an argument still unrendered is not compared: that would render it on every request, and the
            // response is never a request's JSON
            if argument.is_rendered() && !crate::log_entry::Json::ptr_eq(argument, &response) && **argument == *response {
                *argument = response.clone();
            }
        }
    }
    if entry.expectation_id.is_none() && entry.kind == Kind::ExpectationResponse {
        entry.expectation_id = x.expectation_id.clone();
    }
    // `setExpectation(request, response)`: the recorded expectation, its response as the entry's.
    if entry.expectation.is_none() && entry.kind == Kind::ForwardedRequest {
        entry.expectation = x.recorded.as_ref().map(|recorded| {
            let mut recorded = recorded.clone();
            if let Some(o) = recorded.as_object_mut() {
                if let Some(r) = o.get("httpRequest").cloned().map(model_json) {
                    o.insert("httpRequest".into(), r);
                }
                if let (true, Some(response)) = (o.contains_key("httpResponse"), entry.response.as_ref()) {
                    o.insert("httpResponse".into(), Value::clone(response));
                }
            }
            crate::log_entry::Json::new(recorded)
        });
        entry.synthetic_expectation = entry.expectation.is_some();
    }
    entry
}

tokio::task_local! {
    /// Set while an MCP request is handled: upstream logs its entries off the Netty channel, with no port.
    static PORTLESS: bool;
}

/// Runs `work` with every entry it logs stamped with no port (an MCP request's).
pub fn portless<F: std::future::Future>(work: F) -> impl std::future::Future<Output = F::Output> {
    PORTLESS.scope(true, work)
}

/// [`portless`] for synchronous work: what `work` logs carries no port (a forward's `responseTemplate`, rendered on
/// the thread that completes the forward's future).
pub fn portless_sync<R>(work: impl FnOnce() -> R) -> R {
    PORTLESS.sync_scope(true, work)
}

pub(crate) fn in_portless_scope() -> bool {
    PORTLESS.try_with(|p| *p).unwrap_or(false)
}

/// `MockServerEventLog.TRUNCATED_BODY_HEADER`: on a request or response whose body `maxLoggedBodyBytes` cut, the body's
/// original length.
const TRUNCATED_BODY_HEADER: &str = "x-mockserver-body-truncated";

/// The raw bytes of a body in the JSON a logged response or request matcher carries (`getBodyAsRawBytes`): a bare
/// string, a typed `STRING`/`XML`/`JSON`/`BINARY` body, or a bare JSON value. A JSON body is counted as Jackson's
/// default printer writes it, which is what the model holds for a body built from a parsed value; any other typed
/// body (a matcher's `REGEX`, …) has none.
fn response_body_bytes(body: &Value) -> Vec<u8> {
    match body {
        Value::Null => Vec::new(),
        Value::String(s) => s.as_bytes().to_vec(),
        Value::Object(o) => match o.get("type").and_then(Value::as_str) {
            Some("STRING") => o.get("string").and_then(Value::as_str).unwrap_or_default().as_bytes().to_vec(),
            Some("XML") => o.get("xml").and_then(Value::as_str).unwrap_or_default().as_bytes().to_vec(),
            Some("JSON") => match o.get("json") {
                Some(Value::String(s)) => s.as_bytes().to_vec(),
                Some(json) => crate::json::pretty(json).into_bytes(),
                None => Vec::new(),
            },
            Some("BINARY") => o.get("base64Bytes").and_then(Value::as_str).and_then(|b| B64.decode(b).ok()).unwrap_or_default(),
            Some(_) => Vec::new(),
            None => crate::json::pretty(body).into_bytes(),
        },
        other => crate::json::pretty(other).into_bytes(),
    }
}

/// `MockServerEventLog.truncatedForLog` on a request or response in a log entry's JSON: when its body has more than
/// `max` raw bytes, a copy holding the first `max` of them (a base64 text, or a typed `BINARY` body when `typed`, as
/// an expectation writes it) and their original count in `x-mockserver-body-truncated`, ahead of its other headers.
pub(crate) fn cut_message(message: &Value, max: usize, typed: bool) -> Option<Value> {
    let fields = message.as_object()?;
    let bytes = response_body_bytes(fields.get("body")?);
    if bytes.len() <= max {
        return None;
    }
    let marker = json!([bytes.len().to_string()]);
    let headers = |given: Option<&Value>| match given {
        Some(Value::Array(list)) => {
            let mut out = vec![json!({"name": TRUNCATED_BODY_HEADER, "values": marker.clone()})];
            out.extend(list.iter().filter(|h| !h.get("name").and_then(Value::as_str).is_some_and(|n| n.eq_ignore_ascii_case(TRUNCATED_BODY_HEADER))).cloned());
            Value::Array(out)
        }
        given => {
            let mut out = Map::new();
            out.insert(TRUNCATED_BODY_HEADER.into(), marker.clone());
            for (k, v) in given.and_then(Value::as_object).into_iter().flatten().filter(|(k, _)| !k.eq_ignore_ascii_case(TRUNCATED_BODY_HEADER)) {
                out.insert(k.clone(), v.clone());
            }
            Value::Object(out)
        }
    };
    let encoded = B64.encode(&bytes[..max]);
    let body = if typed { json!({"type": "BINARY", "base64Bytes": encoded}) } else { Value::String(encoded) };
    let mut out = Map::new();
    let mut headers_placed = false;
    for (k, v) in fields {
        match k.as_str() {
            "headers" => {
                out.insert(k.clone(), headers(Some(v)));
                headers_placed = true;
            }
            "body" => {
                if !headers_placed {
                    out.insert("headers".into(), headers(None));
                    headers_placed = true;
                }
                out.insert(k.clone(), body.clone());
            }
            _ => {
                out.insert(k.clone(), v.clone());
            }
        }
    }
    Some(Value::Object(out))
}

/// `cutOnce` on an expectation in a log entry's JSON: its `httpRequest` (an `HttpRequest` matcher) and its
/// `httpResponse` with their bodies cut ([`cut_message`]); `None` when neither is.
pub(crate) fn cut_expectation(expectation: &Value, max: usize) -> Option<Value> {
    let fields = expectation.as_object()?;
    let request = fields.get("httpRequest").filter(|r| r.get("specUrlOrPayload").is_none()).and_then(|r| cut_message(r, max, true));
    let response = fields.get("httpResponse").and_then(|r| cut_message(r, max, true));
    if request.is_none() && response.is_none() {
        return None;
    }
    let mut out = fields.clone();
    if let Some(r) = request {
        out.insert("httpRequest".into(), r);
    }
    if let Some(r) = response {
        out.insert("httpResponse".into(), r);
    }
    Some(Value::Object(out))
}

/// `LogEntry.cutText`: a text of more than `max` characters (UTF-16 units) cut to them (one fewer when that would
/// split a surrogate pair), saying how many were left out.
pub(crate) fn cut_text(text: &str, max: usize) -> Option<String> {
    let units: Vec<u16> = text.encode_utf16().collect();
    if units.len() <= max {
        return None;
    }
    let end = if max > 0 && (0xD800..0xDC00).contains(&units[max - 1]) { max - 1 } else { max };
    Some(format!("{}... ({} more characters not logged)", String::from_utf16_lossy(&units[..end]), units.len() - end))
}

/// Which entries `retrieve?format=LOG_ENTRIES` reads.
#[derive(Clone, Copy)]
pub enum EntryScope {
    /// `type=LOGS`.
    Messages,
    /// `type=REQUEST_RESPONSES`: `EXPECTATION_RESPONSE`, `NO_MATCH_RESPONSE`, `FORWARDED_REQUEST`.
    RequestResponses,
    /// `type=RECORDED_EXPECTATIONS`: `FORWARDED_REQUEST`.
    RecordedExpectations,
    /// `type=REQUESTS` by a DNS or binary filter: the `RECEIVED_REQUEST` entries of DNS queries and binary messages
    /// whose definition passes it (upstream #97).
    ReceivedDefinitions,
}

/// A line of `retrieve?type=LOGS`.
/// One entry [`RequestLog::explainable`] reads: its type, the HTTP request it holds, when it was logged, and the
/// entry itself (none for a request's arrival).
pub struct Explainable {
    pub kind: Kind,
    pub request: Option<HttpRequest>,
    pub timestamp: DateTime<Local>,
    pub entry: Option<LogEntry>,
}

pub struct Message {
    pub timestamp: DateTime<Local>,
    /// The entry's type, known without building it.
    kind: Kind,
    entry: MessageEntry,
    pub subject: Subject,
}

/// A message's entry: built when it was logged, or the first time the log is read. An entry nothing prints and nobody
/// reads (most of a request's INFO entries) costs its builder, not the entry.
enum MessageEntry {
    /// Boxed: a `LogEntry` is ~500 bytes, which a deferred entry does not take.
    Built(Box<LogEntry>),
    /// `weight`: what the entry weighs against the byte budget, worked out without building it (`None`: weighed from
    /// the entry).
    Deferred { make: Box<dyn Fn() -> LogEntry + Send + Sync>, built: std::sync::OnceLock<Box<LogEntry>>, weight: Option<u64> },
}

impl Message {
    /// The entry, built now if it was deferred.
    fn entry(&self) -> &LogEntry {
        match &self.entry {
            MessageEntry::Built(entry) => entry,
            MessageEntry::Deferred { make, built, .. } => built.get_or_init(|| Box::new(make())),
        }
    }
}

/// What a log line is about, for `retrieve?type=LOGS` with a request filter (`LogEntry.matches`): lines about
/// nothing always pass.
pub enum Subject {
    None,
    /// A request the server received.
    Request(Arc<HttpRequest>),
    /// A request matcher (an expectation's `httpRequest`, a retrieve filter), treated as a request.
    Definition(Value),
    /// Several request matchers (a verification sequence): the line passes when any does, or when there are none.
    Definitions(Vec<Value>),
}

/// Upstream's event log keeps separate entries for a request's arrival (`RECEIVED_REQUEST`, read by
/// `REQUESTS` and verification) and its completion (`EXPECTATION_RESPONSE` / `FORWARDED_REQUEST`, read by
/// `REQUEST_RESPONSES` and recorded expectations).
enum Entry {
    /// With the log correlation id upstream gives the request (`None`: the request's own, not copied), and the request as
    /// the log line shows it (`None`: the entry's own; the line's text is made from it when read). The fifth is the request
    /// as logged before `maxLoggedBodyBytes` cut it, which the entry's `arguments` keep; the last the request the
    /// line's text shows, when that is neither (`httpForward` rewrote `Host` on the retained one).
    Received(Arc<HttpRequest>, DateTime<Local>, Option<String>, Option<crate::log_entry::Json>, Option<crate::log_entry::Json>, Option<crate::log_entry::Json>),
    Exchange(Arc<Exchange>),
    /// Boxed: every slot of the log is as large as its largest variant.
    Message(Box<Message>),
}

impl Entry {
    fn received_request(&self) -> Option<&HttpRequest> {
        match self {
            Entry::Received(r, ..) => Some(r),
            _ => None,
        }
    }

    /// The entry's line of `retrieve?type=LOGS` and its time, redacted under `redactSecretsInLog` (`fields`) as
    /// upstream c76143e4a renders it; an exchange must carry an entry.
    fn text(&self, fields: Option<&[String]>) -> (DateTime<Local>, String) {
        match self {
            Entry::Received(r, ts, _, text, whole, shown) => match fields {
                None => (*ts, text.as_deref().map_or_else(|| received_text_of(&logged(r)), received_text_of)),
                Some(fields) => {
                    let source = shown.as_deref().or(whole.as_deref()).cloned().unwrap_or_else(|| logged(r));
                    (*ts, received_text_of(&redact_value(&source, fields, true)))
                }
            },
            Entry::Exchange(x) => {
                let entry = x.entry().expect("an exchange with a log line");
                (x.timestamp, fields.map_or_else(|| entry.message_text().to_string(), |f| entry.redacted(f).message_text().to_string()))
            }
            Entry::Message(m) => {
                let entry = m.entry().settled();
                (m.timestamp, fields.map_or_else(|| entry.message_text().to_string(), |f| entry.redacted(f).message_text().to_string()))
            }
        }
    }

    /// The entry's log correlation id, as `LogEntry.getCorrelationId`.
    fn correlation_id(&self) -> Option<&str> {
        match self {
            Entry::Received(r, _, id, ..) => Some(received_id(r, id)),
            Entry::Exchange(x) => x
                .entry()
                .and_then(|e| e.correlation_id.as_deref())
                .or_else(|| (!x.request.log_correlation_id.is_empty()).then_some(x.request.log_correlation_id.as_str())),
            Entry::Message(m) => m.entry().correlation_id.as_deref(),
        }
    }

    /// `LogEntry.estimatedHeapSize`, which `maxEventLogSizeInBytes` budgets: for each HTTP request the entry holds
    /// (after `maxLoggedBodyBytes` cut it) and its response, a fixed overhead, the raw body bytes and the header
    /// characters plus an overhead per header value; one entry overhead when it holds any; a real (not derived)
    /// expectation's own estimate; and the matcher's `because` text. An entry with no HTTP message weighs nothing
    /// but its expectation. The bodies' decoded forms are released before an entry is retained, so they add nothing.
    fn weight(&self) -> u64 {
        let (messages, rest) = match self {
            Entry::Received(r, ..) => (weight::request(r), 0),
            Entry::Exchange(x) => (weight::request(&x.request) + response_weight(&x.response), 0),
            Entry::Message(m) => {
                if let MessageEntry::Deferred { weight: Some(weight), .. } = m.entry {
                    return weight;
                }
                let entry = m.entry();
                let requests: u64 = match &m.subject {
                    Subject::Request(r) if entry.requests.as_ref().is_some_and(|own| own.len() == 1) => weight::request(r),
                    _ => entry.requests.iter().flatten().map(|r| weight::request_json(r)).sum(),
                };
                let messages = requests + entry.response.as_deref().map_or(0, weight::response_json);
                let expectation = entry.expectation.as_deref().filter(|_| !entry.synthetic_expectation).map_or(0, weight::expectation);
                let because = entry.because.as_deref().filter(|_| messages > 0).map_or(0, weight::java_length);
                (messages, expectation + because)
            }
        };
        if messages > 0 { messages + weight::BASE_ENTRY_OVERHEAD_BYTES + rest } else { rest }
    }
}

/// [`Entry::weight`] of a message about a request (its own and only request) holding a real expectation and the
/// `because` text, with no response, from the weights of the request ([`request_weight`]) and the expectation
/// ([`expectation_weight`]).
pub fn message_weight(request: u64, expectation: u64, because: &str) -> u64 {
    match request {
        0 => expectation,
        _ => request + weight::BASE_ENTRY_OVERHEAD_BYTES + expectation + weight::java_length(because),
    }
}

/// In debug builds (every test run): the weight and console message a deferred entry was logged with are the built
/// entry's own.
#[cfg(debug_assertions)]
fn deferred_parts_check(entry: &LogEntry, request: &Arc<HttpRequest>, weight: Option<u64>, text: Option<crate::log::Text>) {
    if let Some(weight) = weight {
        let built = Entry::Message(Box::new(Message { timestamp: Local::now(), kind: entry.kind, entry: MessageEntry::Built(Box::new(entry.clone())), subject: Subject::Request(request.clone()) }));
        assert_eq!(weight, built.weight(), "a deferred entry's weight");
    }
    if let Some(text) = text {
        let (mut given, mut built, mut scratch) = (String::new(), String::new(), String::new());
        text(&mut given, &mut scratch);
        entry.write_message(&mut built, &mut scratch);
        assert_eq!(given, built, "a deferred entry's console message");
    }
}

/// The request's part of [`message_weight`].
pub fn request_weight(request: &HttpRequest) -> u64 {
    weight::request(request)
}

/// The expectation's part of [`message_weight`].
pub fn expectation_weight(expectation: &Value) -> u64 {
    weight::expectation(expectation)
}

/// `LogEntry.estimatedHeapSize` and `Expectation.estimatedHeapSize`, the weights of the event log's byte budget.
mod weight {
    use super::{HttpRequest, Value, response_body_bytes};

    pub const BASE_ENTRY_OVERHEAD_BYTES: u64 = 256;
    const PER_REQUEST_MESSAGE_OVERHEAD_BYTES: u64 = 256;
    const PER_RESPONSE_MESSAGE_OVERHEAD_BYTES: u64 = 128;
    const HEADER_ENTRY_OVERHEAD_BYTES: u64 = 128;
    const BASE_EXPECTATION_OVERHEAD_BYTES: u64 = 512;
    const EXPECTATION_HTTP_MESSAGE_OVERHEAD_BYTES: u64 = 1152;
    const EXPECTATION_HEADER_ENTRY_OVERHEAD_BYTES: u64 = 64;
    const JSON_MATCHER_TREE_EXPANSION: u64 = 20;

    /// `String.length()`: UTF-16 code units.
    pub fn java_length(text: &str) -> u64 {
        // an ASCII text has one unit per byte, and most header names and values are ASCII
        if text.is_ascii() { text.len() as u64 } else { text.encode_utf16().count() as u64 }
    }

    /// `headerBytes`: per header value, `overhead` plus its name's and value's characters.
    fn header_bytes<'a>(values: impl Iterator<Item = (&'a str, &'a str)>, overhead: u64) -> u64 {
        values.map(|(name, value)| overhead + java_length(name) + java_length(value)).sum()
    }

    /// The header values of a model's JSON `headers`, map form (`{name: [values]}`) or list form
    /// (`[{name, values}]`); a single value stands for itself.
    fn json_headers(headers: Option<&Value>) -> Vec<(&str, &str)> {
        fn values(v: &Value) -> Vec<&str> {
            match v {
                Value::Array(a) => a.iter().filter_map(text).collect(),
                other => text(other).into_iter().collect(),
            }
        }
        fn text(v: &Value) -> Option<&str> {
            match v {
                Value::String(s) => Some(s),
                Value::Object(o) => o.get("value").and_then(Value::as_str),
                _ => None,
            }
        }
        match headers {
            Some(Value::Object(map)) => map.iter().flat_map(|(name, v)| values(v).into_iter().map(move |value| (name.as_str(), value))).collect(),
            Some(Value::Array(list)) => list
                .iter()
                .filter_map(|h| Some((text(h.get("name")?)?, h.get("values")?)))
                .flat_map(|(name, v)| values(v).into_iter().map(move |value| (name, value)))
                .collect(),
            _ => Vec::new(),
        }
    }

    fn body_bytes(message: &Value) -> u64 {
        message.get("body").map_or(0, |b| response_body_len(b) as u64)
    }

    /// `response_body_bytes(body).len()`, a text body's counted without copying it.
    fn response_body_len(body: &Value) -> usize {
        let text = match body {
            Value::Null => return 0,
            Value::String(s) => s,
            Value::Object(o) => match o.get("type").and_then(Value::as_str) {
                Some("STRING") => o.get("string").and_then(Value::as_str).unwrap_or_default(),
                Some("XML") => o.get("xml").and_then(Value::as_str).unwrap_or_default(),
                Some("JSON") if o.get("json").is_none_or(Value::is_string) => o.get("json").and_then(Value::as_str).unwrap_or_default(),
                _ => return response_body_bytes(body).len(),
            },
            _ => return response_body_bytes(body).len(),
        };
        text.len()
    }

    /// A received request, as the entry retains it.
    pub fn request(r: &HttpRequest) -> u64 {
        let headers = r.headers.iter().flat_map(|(name, values)| values.iter().map(move |value| (name.as_str(), value.as_str())));
        PER_REQUEST_MESSAGE_OVERHEAD_BYTES + r.body.len() as u64 + header_bytes(headers, HEADER_ENTRY_OVERHEAD_BYTES)
    }

    /// Whether a request definition's JSON is an `HttpRequest` (not an OpenAPI, DNS, binary or conditional one).
    fn is_http_request(definition: &Value) -> bool {
        definition.as_object().is_some_and(|o| !["specUrlOrPayload", "dnsName", "dnsType", "dnsClass", "ifMatches"].iter().any(|k| o.contains_key(*k)))
    }

    /// A request in an entry's `httpRequests`; only an `HttpRequest` weighs anything.
    pub fn request_json(r: &Value) -> u64 {
        if !is_http_request(r) {
            return 0;
        }
        PER_REQUEST_MESSAGE_OVERHEAD_BYTES + body_bytes(r) + header_bytes(json_headers(r.get("headers")).into_iter(), HEADER_ENTRY_OVERHEAD_BYTES)
    }

    /// An entry's `httpResponse`.
    pub fn response_json(r: &Value) -> u64 {
        PER_RESPONSE_MESSAGE_OVERHEAD_BYTES + body_bytes(r) + header_bytes(json_headers(r.get("headers")).into_iter(), HEADER_ENTRY_OVERHEAD_BYTES)
    }

    /// `Expectation.estimatedHeapSize`: its request definition (a JSON body's matcher tree counted twenty times over),
    /// each response, and its templates' text.
    pub fn expectation(e: &Value) -> u64 {
        let message = |m: &Value, tree: bool| {
            let body = body_bytes(m);
            let json = tree && m.get("body").and_then(|b| b.get("type")).and_then(Value::as_str) == Some("JSON");
            EXPECTATION_HTTP_MESSAGE_OVERHEAD_BYTES
                + body
                + if json { body * JSON_MATCHER_TREE_EXPANSION } else { 0 }
                + header_bytes(json_headers(m.get("headers")).into_iter(), EXPECTATION_HEADER_ENTRY_OVERHEAD_BYTES)
        };
        let request = match e.get("httpRequest") {
            Some(r) if is_http_request(r) => message(r, true),
            Some(r) => r.get("specUrlOrPayload").and_then(Value::as_str).map_or(0, |spec| EXPECTATION_HTTP_MESSAGE_OVERHEAD_BYTES + java_length(spec)),
            None => 0,
        };
        let responses: u64 = e.get("httpResponse").map_or(0, |r| message(r, false))
            + e.get("httpResponses").and_then(Value::as_array).map_or(0, |rs| rs.iter().map(|r| message(r, false)).sum());
        let template = |key: &str| e.get(key).and_then(|t| t.get("template")).and_then(Value::as_str).map_or(0, java_length);
        BASE_EXPECTATION_OVERHEAD_BYTES + request + responses + template("httpResponseTemplate") + template("httpForwardTemplate")
    }
}

/// An entry in the ring with its weight (0 while no byte budget is in force), so evicting it does not weigh it again
/// under the lock.
struct Slot {
    entry: Entry,
    weight: u64,
}

/// An entry on its way into the ring, with the weight taken before the lock (see [`RequestLog::push`]).
struct Staged {
    entry: Entry,
    /// The byte budget the weight was taken under (0: none, the weight is not taken).
    weighed_for: u64,
    weight: u64,
}

/// What draining the inbox leaves to do once the ring's lock is released.
#[derive(Default)]
struct Drained {
    any: bool,
    recorded: bool,
    /// What the drain evicted: the one entry a full log drops for each push is kept without allocating under the lock.
    dropped_entry: Option<Entry>,
    dropped_entries: Vec<Entry>,
}

/// The ring under its lock (see [`RequestLog::locked`]). Releasing it finishes the drain that locking did, and drains
/// what was staged meanwhile, since the pushers that found it held went away without waiting.
struct Ring<'a> {
    log: &'a RequestLog,
    guard: Option<parking_lot::MutexGuard<'a, VecDeque<Slot>>>,
    work: Option<Drained>,
}

impl std::ops::Deref for Ring<'_> {
    type Target = VecDeque<Slot>;
    fn deref(&self) -> &VecDeque<Slot> {
        self.guard.as_ref().expect("held")
    }
}

impl std::ops::DerefMut for Ring<'_> {
    fn deref_mut(&mut self) -> &mut VecDeque<Slot> {
        self.guard.as_mut().expect("held")
    }
}

impl Ring<'_> {
    /// The entries, oldest first.
    fn entries(&self) -> impl Iterator<Item = &Entry> {
        self.iter().map(|slot| &slot.entry)
    }
}

impl Drop for Ring<'_> {
    fn drop(&mut self) {
        drop(self.guard.take());
        if let Some(work) = self.work.take() {
            self.log.finish(work);
        }
        if !self.log.inbox.is_empty() {
            self.log.drain_if_free();
        }
    }
}

pub struct RequestLog {
    entries: Mutex<VecDeque<Slot>>,
    /// Entries pushed and not yet in `entries`: see [`RequestLog::push`].
    inbox: concurrent_queue::ConcurrentQueue<Staged>,
    /// `maxLogEntries`; changed under the `entries` lock (see [`RequestLog::resize`]).
    capacity: std::sync::atomic::AtomicUsize,
    /// `maxLoggedBodyBytes`: bodies logged are cut to this many bytes (0: kept whole).
    max_logged_body_bytes: std::sync::atomic::AtomicUsize,
    /// `maxEventLogSizeInBytes`: the oldest entries go while the bodies held would exceed this (0: no budget); changed
    /// under the `entries` lock.
    max_bytes: std::sync::atomic::AtomicU64,
    /// The sum of [`Entry::weight`] over the entries, kept in step with them under the `entries` lock.
    bytes: std::sync::atomic::AtomicU64,
    /// Entries dropped to stay within `maxLogEntries` or `maxEventLogSizeInBytes` since the log was last cleared.
    evicted: std::sync::atomic::AtomicU64,
    /// Of [`RequestLog::evicted`], those dropped to stay within `maxEventLogSizeInBytes` (`getByteEvictedCount`).
    byte_evicted: std::sync::atomic::AtomicU64,
    /// Entries evicted since the server started, kept through a reset: `mock_server_evicted_log_entries`, a counter.
    evicted_since_start: std::sync::atomic::AtomicU64,
    /// `setRecordedRequestConsumer`: sees every served exchange before it is stored (`persistRecordedRequestsToDisk`).
    exchange_hook: Mutex<Option<ExchangeHook>>,
    /// Whether `exchange_hook` holds one, so an exchange does not lock it when none is installed.
    exchange_hook_set: std::sync::atomic::AtomicBool,
    /// `MockServerEventLogNotifier`: called after the recorded expectations may have changed (an exchange was
    /// added or evicted, the log was cleared or reset): `persistRecordedExpectations`.
    recorded_hook: Mutex<Option<RecordedHook>>,
    /// The console writer: sees each entry the log records that the oracle also prints at its level.
    /// Installed once, read without a lock by every entry.
    console_hook: std::sync::OnceLock<ConsoleHook>,
    /// Says whether the console would print an entry of that level and kind at all, so a line nobody reads is not
    /// built. Installed once with the hook.
    console_gate: std::sync::OnceLock<ConsoleGate>,
    /// Reads the body fields `redactSecretsInLog` redacts with, `None` when it is off.
    /// Installed once, read without a lock by every entry.
    redaction_hook: std::sync::OnceLock<RedactionHook>,
    /// Touched whenever the entries change (`MockServerLogListener`): the dashboard's push channel waits on it.
    pub changes: crate::changes::ChangeSignal,
    /// The filter matchers the log's and the expectations' `MatcherBuilder`s cache. A reset keeps them.
    pub filter_matchers: FilterMatcherCaches,
}

/// `LRUCache` as `MatcherBuilder` configures it: 250 entries, each expiring 10 minutes after it was last read.
struct Lru<K, V> {
    entries: VecDeque<(K, std::time::Instant, V)>,
}

impl<K: PartialEq, V> Default for Lru<K, V> {
    fn default() -> Self {
        Lru { entries: VecDeque::new() }
    }
}

impl<K: PartialEq, V> Lru<K, V> {
    const MAX: usize = 250;
    const TTL: std::time::Duration = std::time::Duration::from_secs(600);

    /// `getOrCompute` by `get` then `put`: whether the value was created.
    fn get_or_insert(&mut self, key: K, value: impl FnOnce() -> V) -> (&mut V, bool) {
        let now = std::time::Instant::now();
        let found = self.entries.iter().position(|(k, ..)| *k == key);
        let created = match found {
            // `get` moves a live entry to the back and extends its expiry; an expired one is deleted
            Some(i) if self.entries[i].1 > now => {
                let mut entry = self.entries.remove(i).expect("present");
                entry.1 = now + Self::TTL;
                self.entries.push_back(entry);
                false
            }
            found => {
                if let Some(i) = found {
                    self.entries.remove(i);
                }
                while self.entries.len() >= Self::MAX {
                    self.entries.pop_front();
                }
                self.entries.push_back((key, now + Self::TTL, value()));
                true
            }
        };
        (&mut self.entries.back_mut().expect("just placed").2, created)
    }
}

/// `MockServerEventLog`'s and `RequestMatchers`' `MatcherBuilder` caches of filter matchers.
#[derive(Default)]
pub struct FilterMatcherCaches {
    pub event_log: Mutex<FilterMatchers>,
    pub expectations: Mutex<FilterMatchers>,
}

/// One `MatcherBuilder`'s filter matchers, keyed by the filter. Each keeps what its own (lazily built) `MatcherBuilder`
/// built for the OpenAPI definitions it met (`HttpRequestPropertiesMatcher.matches` given an `OpenAPIDefinition`); an
/// OpenAPI filter's per-operation matchers (`Some(index)`) each keep their own.
#[derive(Default)]
pub struct FilterMatchers(Lru<Value, Vec<OperationMatchers>>);

/// A filter's matchers for the OpenAPI definitions it met: the whole filter's (`None`) or an operation's.
type OperationMatchers = (Option<usize>, Lru<Value, ()>);

impl FilterMatchers {
    /// Looks `filter`'s matcher up (built when absent), then has it meet `met` in order: whether the filter's matcher
    /// was built, and the definitions a matcher was built for (each logs `created request matcher`).
    pub fn meet(&mut self, filter: &Value, met: Vec<(Option<usize>, Value)>) -> (bool, Vec<Value>) {
        let (builders, created) = self.0.get_or_insert(filter.clone(), Vec::new);
        let mut built = Vec::new();
        for (operation, definition) in met {
            let builder = match builders.iter().position(|(o, _)| *o == operation) {
                Some(i) => &mut builders[i].1,
                None => {
                    builders.push((operation, Lru::default()));
                    &mut builders.last_mut().expect("just pushed").1
                }
            };
            if builder.get_or_insert(definition.clone(), || ()).1 {
                built.push(definition);
            }
        }
        (created, built)
    }
}

/// What [`RequestLog::clear`] removes: the entries about a request passing the first, or a matcher passing the
/// second.
pub type ClearFilter<'a> = (&'a dyn Fn(&HttpRequest) -> bool, &'a dyn Fn(&Value) -> bool);

/// A hook that sees each served exchange (`EXPECTATION_RESPONSE`, `FORWARDED_REQUEST`) once; not called for an
/// exchange re-imported from an archive.
pub type ExchangeHook = Arc<dyn Fn(&Exchange) + Send + Sync>;
/// A hook called with the log after its recorded expectations may have changed.
pub type RecordedHook = Arc<dyn Fn(&RequestLog) + Send + Sync>;
/// A hook that writes one event-log entry to the console: level, type, what writes the entry's message and whether it
/// carries no port; the compact message (`compactLogFormat`) is computed on demand.
pub type ConsoleGate = Arc<dyn Fn(Level, Kind) -> bool + Send + Sync>;
pub type ConsoleHook = Arc<dyn Fn(Level, Kind, crate::log::Text, &dyn Fn() -> String, bool) + Send + Sync>;
/// A hook that reads `redactSecretsInLog`'s body fields from the configuration in force (`None`: off).
pub type RedactionHook = Arc<dyn Fn() -> Option<Vec<String>> + Send + Sync>;

/// The types the log itself prints on the console when it records them. Entries of other types are printed by the call
/// site that logs them (`log::info_event` and friends), which also record them here.
fn console_kind(kind: Kind) -> bool {
    matches!(
        kind,
        Kind::ReceivedRequest
            | Kind::ExpectationMatched
            | Kind::ExpectationNotMatched
            | Kind::NoMatchResponse
            | Kind::ExpectationResponse
            | Kind::ForwardedRequest
            | Kind::Cleared
            | Kind::Retrieved
            | Kind::Verification
            | Kind::VerificationPassed
            | Kind::VerificationFailed
    )
}

impl RequestLog {
    pub fn new(capacity: usize) -> RequestLog {
        RequestLog {
            entries: Mutex::new(VecDeque::new()),
            inbox: concurrent_queue::ConcurrentQueue::unbounded(),
            capacity: std::sync::atomic::AtomicUsize::new(capacity),
            max_logged_body_bytes: Default::default(),
            max_bytes: Default::default(),
            bytes: Default::default(),
            evicted: Default::default(),
            byte_evicted: Default::default(),
            evicted_since_start: Default::default(),
            exchange_hook: Mutex::new(None),
            exchange_hook_set: Default::default(),
            recorded_hook: Mutex::new(None),
            console_hook: std::sync::OnceLock::new(),
            console_gate: std::sync::OnceLock::new(),
            redaction_hook: std::sync::OnceLock::new(),
            changes: Default::default(),
            filter_matchers: Default::default(),
        }
    }

    /// `MockServerEventLog.size`: the entries the log holds.
    pub fn size(&self) -> usize {
        self.locked().len()
    }

    /// The retained-log figures `Metrics.RingStats` reads (`getRetainedEntryCount`, `getRetainedBytes`,
    /// `getMaxRetainedBytes`, `getMaxRetainedEntries`): the entries held, their body bytes (the sum of their weights,
    /// tracked whether or not a byte budget is in force), the byte budget (0: none) and the entry cap.
    pub fn retained(&self) -> (usize, u64, u64, usize) {
        use std::sync::atomic::Ordering::Relaxed;
        let entries = self.locked();
        let max_bytes = self.max_bytes.load(Relaxed);
        let bytes = if max_bytes > 0 { self.bytes.load(Relaxed) } else { entries.entries().map(Entry::weight).sum() };
        (entries.len(), bytes, max_bytes, self.capacity.load(Relaxed))
    }

    /// The limits `maxLoggedBodyBytes` and `maxEventLogSizeInBytes` put on what the log retains (0: none).
    pub fn with_limits(self, max_logged_body_bytes: usize, max_event_log_size_in_bytes: u64) -> RequestLog {
        self.max_logged_body_bytes.store(max_logged_body_bytes, std::sync::atomic::Ordering::Relaxed);
        self.max_bytes.store(max_event_log_size_in_bytes, std::sync::atomic::Ordering::Relaxed);
        self
    }

    /// `MockServerEventLog.applyConfigurationCapacity` (`setMaxSize(maxLogEntries)`, `setMaxBytes(maxEventLogSizeInBytes)`)
    /// and the `maxLoggedBodyBytes` the next entries are cut to, after a configuration update: a shrink evicts the
    /// oldest entries at once, counted as evictions. On the 8.0.0 process these read the startup copy and changed
    /// nothing (upstream 0e8566814).
    pub fn resize(&self, max_entries: usize, max_bytes: u64, max_logged_body_bytes: usize) {
        use std::sync::atomic::Ordering::Relaxed;
        self.max_logged_body_bytes.store(max_logged_body_bytes, Relaxed);
        let evicted_recorded = {
            let mut entries = self.locked();
            // a budget newly in force starts from what the log holds
            if max_bytes > 0 && self.max_bytes.load(Relaxed) == 0 {
                for slot in entries.iter_mut() {
                    slot.weight = slot.entry.weight();
                }
                self.bytes.store(entries.iter().map(|slot| slot.weight).sum(), Relaxed);
            }
            self.capacity.store(max_entries, Relaxed);
            self.max_bytes.store(max_bytes, Relaxed);
            let mut evicted_recorded = false;
            let mut evict = |entries: &mut VecDeque<Slot>, by_bytes: bool| {
                let Some(dropped) = entries.pop_front() else { return };
                if by_bytes {
                    self.byte_evicted.fetch_add(1, Relaxed);
                }
                if max_bytes > 0 {
                    self.bytes.fetch_sub(dropped.weight, Relaxed);
                }
                evicted_recorded |= matches!(dropped.entry, Entry::Exchange(ref x) if x.recorded.is_some());
                self.evicted.fetch_add(1, Relaxed);
                self.evicted_since_start.fetch_add(1, Relaxed);
            };
            while entries.len() > max_entries {
                evict(&mut entries, false);
            }
            if max_bytes > 0 {
                while self.bytes.load(Relaxed) > max_bytes && !entries.is_empty() {
                    evict(&mut entries, true);
                }
            }
            evicted_recorded
        };
        self.changes.touch();
        if evicted_recorded {
            self.notify_recorded();
        }
    }

    /// Installs the per-exchange hook (replacing any earlier one).
    pub fn set_exchange_hook(&self, hook: ExchangeHook) {
        let mut slot = self.exchange_hook.lock();
        *slot = Some(hook);
        self.exchange_hook_set.store(true, std::sync::atomic::Ordering::Release);
    }

    /// Installs the recorded-expectations hook (replacing any earlier one).
    pub fn set_recorded_hook(&self, hook: RecordedHook) {
        *self.recorded_hook.lock() = Some(hook);
    }

    /// Installs the console writer; a log has one, and a second call changes nothing.
    pub fn set_console_hook(&self, hook: ConsoleHook) {
        let _ = self.console_hook.set(hook);
    }

    /// Installs what says whether the console prints an entry of a level and kind; a log has one.
    pub fn set_console_gate(&self, gate: ConsoleGate) {
        let _ = self.console_gate.set(gate);
    }

    /// Whether an entry of `level` and `kind` can reach the console: a hook is installed, the kind is one the console
    /// shows and the gate (when installed) lets it through.
    fn console_wanted(&self, level: Level, kind: Kind) -> bool {
        console_kind(kind) && self.console_hook.get().is_some() && self.console_gate.get().is_none_or(|gate| gate(level, kind))
    }

    /// Installs what reads `redactSecretsInLog` (and `fixtureBodyRedactFields`) as they are in force.
    /// A log has one; a second call changes nothing.
    pub fn set_redaction_hook(&self, hook: RedactionHook) {
        let _ = self.redaction_hook.set(hook);
    }

    /// The body fields `redactSecretsInLog` redacts with, when it is on.
    pub fn redaction_fields(&self) -> Option<Vec<String>> {
        self.redaction_hook.get().and_then(|h| h())
    }

    /// An entry's console line, redacted under `redactSecretsInLog` (upstream c76143e4a).
    fn console_entry(&self, entry: &LogEntry) {
        if !self.console_wanted(entry.level, entry.kind) {
            return;
        }
        let redacted = self.redaction_fields().map(|f| entry.redacted(&f));
        let entry = redacted.as_ref().unwrap_or(entry);
        // the message is rendered onto the console's line, not kept on the entry
        self.console(entry.level, entry.kind, &|out, scratch| entry.write_message(out, scratch), &|| entry.compact_text(), entry.portless);
    }

    fn console(&self, level: Level, kind: Kind, text: crate::log::Text, compact: &dyn Fn() -> String, portless: bool) {
        if !console_kind(kind) {
            return;
        }
        if let Some(hook) = self.console_hook.get() {
            hook(level, kind, text, compact, portless);
        }
    }

    /// Removes both hooks (`stop`).
    pub fn clear_hooks(&self) {
        let mut slot = self.exchange_hook.lock();
        *slot = None;
        self.exchange_hook_set.store(false, std::sync::atomic::Ordering::Release);
        drop(slot);
        *self.recorded_hook.lock() = None;
    }

    fn notify_recorded(&self) {
        let hook = self.recorded_hook.lock().clone();
        if let Some(hook) = hook {
            hook(self);
        }
    }

    /// The recorded expectations (canonical form), oldest first: what `retrieveRecordedExpectations(null)` returns.
    pub fn recorded_expectations(&self) -> Vec<Value> {
        self.locked()
            .entries()
            .filter_map(|e| match e {
                Entry::Exchange(x) => x.recorded.as_ref().map(|r| {
                    let mut r = r.clone();
                    crate::transport_headers::strip_expectation(&mut r, false);
                    persisted_expectation(&r)
                }),
                _ => None,
            })
            .collect()
    }

    /// `MockServerEventLog.truncateBodiesForLog`, request side: the copy of `request` the log retains when its body is
    /// longer than `maxLoggedBodyBytes` (a binary body of the first bytes, the original length in
    /// `x-mockserver-body-truncated`); `None` when the request is kept as it is. The live request is never changed.
    fn truncated_request(&self, request: &HttpRequest) -> Option<HttpRequest> {
        let max = self.max_logged_body_bytes.load(std::sync::atomic::Ordering::Relaxed);
        if max == 0 || request.body.len() <= max {
            return None;
        }
        let mut cut = request.clone();
        cut.body = request.body.slice(..max);
        cut.original_body = None;
        cut.body_kind = BodyKind::Binary;
        let length = vec![request.body.len().to_string()];
        match cut.headers.iter_mut().find(|(k, _)| k.eq_ignore_ascii_case(TRUNCATED_BODY_HEADER)) {
            Some((_, values)) => *values = length,
            None => cut.headers.push((TRUNCATED_BODY_HEADER.to_string(), length)),
        }
        Some(cut)
    }

    /// As [`RequestLog::truncated_request`] for a response (canonical `httpResponse` JSON).
    fn truncated_response(&self, response: &Value) -> Option<Value> {
        let max = self.max_logged_body_bytes.load(std::sync::atomic::Ordering::Relaxed);
        let bytes = response_body_bytes(response.get("body")?);
        if max == 0 || bytes.len() <= max {
            return None;
        }
        let mut cut = response.clone();
        cut["body"] = json!({"type": "BINARY", "base64Bytes": B64.encode(&bytes[..max])});
        let mut headers = cut.get("headers").and_then(Value::as_object).cloned().unwrap_or_default();
        headers.retain(|k, _| !k.eq_ignore_ascii_case(TRUNCATED_BODY_HEADER));
        headers.insert(TRUNCATED_BODY_HEADER.into(), json!([bytes.len().to_string()]));
        cut["headers"] = Value::Object(headers);
        // The model's own order: its fields, the headers sorted as every logged map is.
        Some(canonical::response(&cut))
    }

    /// What the log retains of a completed exchange once its disk-capture hook has seen it whole: the request and
    /// response cut to `maxLoggedBodyBytes`, in the entry's `httpRequest`/`httpResponse`, the arguments that are
    /// them and the recorded expectation too (derived from the retained copies), and every other body or text the
    /// entry quotes bounded (`truncateBodiesForLog`).
    fn truncate_exchange(&self, x: &mut Exchange) {
        let max = self.max_logged_body_bytes.load(std::sync::atomic::Ordering::Relaxed);
        if max == 0 {
            return;
        }
        let request = self.truncated_request(&x.request);
        let response = self.truncated_response(&x.response);
        if let ExchangeEntry::Built(entry) = &mut x.entry {
            let mut swaps = Vec::new();
            if let Some(cut) = &request && let Some(own) = entry.requests.as_mut().filter(|own| own.len() == 1 && *own[0] == logged(&x.request)) {
                let retained = logged(cut);
                swaps.push((Value::clone(&own[0]), retained.clone()));
                own[0] = crate::log_entry::Json::new(retained);
            }
            if let Some(cut) = &response {
                // A forward's entry carries the client's `timing` too (`forwarded_message`); it stays on the cut copy.
                let before = entry.response.as_deref().cloned();
                let mut own = before.clone();
                let timing = own.as_mut().and_then(Value::as_object_mut).and_then(|o| o.remove("timing"));
                if own.as_ref() == Some(&logged_response(&x.response)) {
                    let mut retained = logged_response(cut);
                    if let (Some(timing), Some(o)) = (timing, retained.as_object_mut()) {
                        o.insert("timing".into(), timing);
                    }
                    swaps.extend(before.map(|before| (before, retained.clone())));
                    entry.response = Some(crate::log_entry::Json::new(retained));
                }
            }
            entry.bound_quoted_bodies(max, &swaps);
        }
        if let Some(recorded) = x.recorded.as_mut() {
            if let Some(cut) = &request {
                recorded["httpRequest"] = ordered_with(cut, BodyForm::Recorded);
            }
            if let (Some(cut), Some(own)) = (&response, recorded.get_mut("httpResponse").and_then(Value::as_object_mut)) {
                let bytes = cut.get("body").map(response_body_bytes).unwrap_or_default();
                own.insert("headers".into(), cut.get("headers").cloned().unwrap_or_default());
                own.insert("body".into(), json!({"type": "BINARY", "base64Bytes": B64.encode(&bytes)}));
            }
        }
        if let Some(input) = x.recorded_input.as_mut() {
            if let Some(cut) = &request {
                let mut retained = input_request(cut);
                if let Some(o) = retained.as_object_mut().filter(|o| o.contains_key("body")) {
                    o.insert("body".into(), json!({"type": "BINARY", "base64Bytes": B64.encode(&cut.body)}));
                }
                input["httpRequest"] = retained;
            }
            if let (Some(cut), Some(own)) = (&response, input.get_mut("httpResponse").and_then(Value::as_object_mut)) {
                let bytes = cut.get("body").map(response_body_bytes).unwrap_or_default();
                let length = cut.pointer(&format!("/headers/{TRUNCATED_BODY_HEADER}")).cloned().unwrap_or_default();
                // the input form lists the headers in the order they were added: the marker last
                match own.get_mut("headers") {
                    Some(Value::Array(headers)) => headers.push(json!({"name": TRUNCATED_BODY_HEADER, "values": length})),
                    Some(Value::Object(headers)) => {
                        headers.insert(TRUNCATED_BODY_HEADER.into(), length);
                    }
                    _ => {
                        own.insert("headers".into(), json!([{"name": TRUNCATED_BODY_HEADER, "values": length}]));
                    }
                }
                own.insert("body".into(), json!({"type": "BINARY", "base64Bytes": B64.encode(&bytes)}));
            }
        }
        if let Some(cut) = request {
            x.request = Arc::new(cut);
        }
        if let Some(cut) = response {
            x.response = Arc::new(cut);
        }
    }

    /// Stages `entry` for the ring. A request's entries (received, exchange, messages) used to take the
    /// one `entries` mutex each, and request workers spun on it. Now an entry joins a lock-free inbox, and whoever finds
    /// the ring free drains the inbox into it in arrival order, so the lock is taken once for a burst of entries and
    /// nobody waits for it. Every reader drains the inbox under the lock before it looks, so none sees a log without an
    /// entry pushed before its call.
    fn push(&self, entry: Entry) {
        // `CircularConcurrentLinkedDeque.add` with `maxSize` 0: the entry is refused, not counted as an
        // eviction, and nothing is retained
        if self.capacity.load(std::sync::atomic::Ordering::Relaxed) == 0 {
            return;
        }
        // The incoming entry is weighed before the lock is taken: its header characters are counted in UTF-16 units, and
        // every request worker queued behind one push's count. A budget switched on meanwhile is weighed
        // under the lock, below.
        let weighed_for = self.max_bytes.load(std::sync::atomic::Ordering::Relaxed);
        let weight = if weighed_for > 0 { entry.weight() } else { 0 };
        let staged = Staged { entry, weighed_for, weight };
        // The ring free: the entry goes straight in, after what was staged before it, without passing through the
        // inbox (whose push and pop were most of a push's cost).
        if let Some(mut entries) = self.entries.try_lock() {
            let mut work = self.drain(&mut entries);
            self.admit(&mut entries, staged, &mut work);
            drop(entries);
            self.finish(work);
            if !self.inbox.is_empty() {
                self.drain_if_free();
            }
            return;
        }
        let _ = self.inbox.push(staged);
        self.drain_if_free();
    }

    /// Drains the inbox into the ring when no one holds it; the holder drains what arrives while it works.
    fn drain_if_free(&self) {
        loop {
            let Some(mut entries) = self.entries.try_lock() else { return };
            let work = self.drain(&mut entries);
            drop(entries);
            self.finish(work);
            if self.inbox.is_empty() {
                return;
            }
        }
    }

    /// The ring, locked, with everything staged before the call in it.
    fn locked(&self) -> Ring<'_> {
        let mut guard = self.entries.lock();
        let work = self.drain(&mut guard);
        Ring { log: self, guard: Some(guard), work: Some(work) }
    }

    /// Moves the staged entries into the ring, evicting as each one is admitted. What the caller does after releasing
    /// the lock (the destructors, the change signal, the recorded hook) comes back as [`Drained`].
    fn drain(&self, entries: &mut std::collections::VecDeque<Slot>) -> Drained {
        let mut work = Drained::default();
        // nothing staged (the common case): no pop, whose fence every push paid
        if self.inbox.is_empty() {
            return work;
        }
        while let Ok(staged) = self.inbox.pop() {
            self.admit(entries, staged, &mut work);
        }
        work
    }

    /// Admits one staged entry into the ring, evicting as it goes; what the caller does once the lock is released is
    /// added to `work`.
    fn admit(&self, entries: &mut std::collections::VecDeque<Slot>, staged: Staged, work: &mut Drained) {
        use std::sync::atomic::Ordering::Relaxed;
        let Staged { entry, weighed_for, weight: early_weight } = staged;
        {
            // the capacity can have changed to 0 since the entry was staged (a `resize`)
            if self.capacity.load(Relaxed) == 0 {
                return;
            }
            work.any = true;
            work.recorded |= matches!(&entry, Entry::Exchange(x) if x.recorded.is_some());
            let max_bytes = self.max_bytes.load(Relaxed);
            let weight = match max_bytes {
                0 => 0,
                _ if weighed_for > 0 => early_weight,
                _ => entry.weight(),
            };
            // `CircularConcurrentLinkedDeque.evictExcessElements`: first the count, then (with a budget) the bytes, until
            // the incoming entry fits or nothing is left to drop; an entry over the whole budget is kept alone.
            let mut evict = |entries: &mut std::collections::VecDeque<Slot>, by_bytes: bool| {
                if let Some(dropped) = entries.pop_front() {
                    if by_bytes {
                        self.byte_evicted.fetch_add(1, Relaxed);
                    }
                    if max_bytes > 0 {
                        self.bytes.fetch_sub(dropped.weight, Relaxed);
                    }
                    work.recorded |= matches!(dropped.entry, Entry::Exchange(ref x) if x.recorded.is_some());
                    self.evicted.fetch_add(1, Relaxed);
                    self.evicted_since_start.fetch_add(1, Relaxed);
                    // what the push evicts is freed after the lock is released: freeing an entry under the lock
                    // serialised every request worker behind one destructor once the log was full
                    match work.dropped_entry {
                        None => work.dropped_entry = Some(dropped.entry),
                        Some(_) => work.dropped_entries.push(dropped.entry),
                    }
                }
            };
            if entries.len() >= self.capacity.load(Relaxed) {
                evict(entries, false);
            }
            if max_bytes > 0 {
                while self.bytes.load(Relaxed) + weight > max_bytes && !entries.is_empty() {
                    evict(entries, true);
                }
                self.bytes.fetch_add(weight, Relaxed);
            }
            entries.push_back(Slot { entry, weight });
        }
    }

    /// What a drain leaves for after the lock is released.
    fn finish(&self, work: Drained) {
        let Drained { any, recorded, dropped_entry, dropped_entries } = work;
        // freed here, on the evicting thread: a thread of their own freed them at the same CPU cost plus mimalloc's
        // cross-thread frees, and a container's CPU quota counts both
        drop(dropped_entry);
        drop(dropped_entries);
        if any {
            self.changes.touch();
        }
        if recorded {
            self.notify_recorded();
        }
    }

    /// A request's arrival.
    pub fn received(&self, request: HttpRequest) {
        let shown = request.clone();
        self.received_as(request, &shown);
    }

    /// A request's arrival whose log line shows `shown`: `httpForward` rewrites `Host` on the recorded request
    /// before `REQUESTS` serialises it, after the line was formatted.
    pub fn received_as(&self, request: HttpRequest, shown: &HttpRequest) {
        self.received_shared(Arc::new(request), shown, &LoggedRequest::of(shown).json, true);
    }

    /// A request's arrival as the data plane logs it: the entry holds `logged`'s request, not a copy, and its line
    /// shows `logged`'s JSON, which the request's other entries share; `shown` is the request as it arrived, before
    /// `httpForward` rewrote `Host` on the retained one.
    pub fn received_logged(&self, logged: &LoggedRequest, shown: &HttpRequest) {
        self.received_shared(logged.request.clone(), shown, &logged.json, false);
    }

    /// `line` is the request the line shows; the entry keeps it when `keep_line`, else (the line is `request`'s own
    /// logged form) renders the line from `request` when read.
    fn received_shared(&self, request: Arc<HttpRequest>, shown: &HttpRequest, line: &crate::log_entry::Json, keep_line: bool) {
        // `CredentialRedaction.forLog`: a control-plane request's entry holds it without its credentials
        if let Some(masked) = crate::credential_redaction::for_log(&request) {
            let shown = crate::credential_redaction::for_log(shown).unwrap_or_else(|| shown.clone());
            let shown_json = LoggedRequest::of(&shown).json;
            return self.received_shared(Arc::new(masked), &shown, &shown_json, true);
        }
        // nothing is built for a log that keeps nothing and a console that prints nothing
        if self.capacity.load(std::sync::atomic::Ordering::Relaxed) == 0 && !self.console_wanted(Level::Info, Kind::ReceivedRequest) {
            return;
        }
        let id = request.log_correlation_id.is_empty().then(|| crate::breakpoint::correlation(&request));
        let shown_request = shown;
        let text = keep_line.then(|| line.clone());
        // the request itself, as the data plane logs one nothing rewrote, has its own headers without comparing them
        let shown = (!std::ptr::eq(shown, &*request) && shown.headers != request.headers).then(|| line.clone());
        if self.console_wanted(Level::Info, Kind::ReceivedRequest) {
            let redacted = self.redaction_fields().map(|fields| crate::log_entry::Json::new(redact_value(shown.as_deref().unwrap_or(&logged(&request)), &fields, true)));
            let shown_line = redacted.as_ref().unwrap_or(line);
            self.console(Level::Info, Kind::ReceivedRequest, &|out, scratch| received_text_into(out, scratch, shown_line), &|| format!("received request: {}", crate::log_entry::compact_argument("received request:", &logged(&request), "")), in_portless_scope());
        }
        match self.truncated_request(&request) {
            // `replaceQuoted`: the log line and `arguments` show the cut copy the entry retains too.
            Some(cut) => {
                let shown_cut = self.truncated_request(shown_request).unwrap_or_else(|| shown_request.clone());
                let shown_logged = LoggedRequest::of(&shown_cut);
                let text = Some(shown_logged.json.clone());
                let shown = (shown_cut.headers != cut.headers).then(|| shown_logged.json.clone());
                self.push(Entry::Received(Arc::new(cut), Local::now(), id, text, None, shown));
            }
            None => self.push(Entry::Received(request, Local::now(), id, text, None, shown)),
        }
    }

    /// A request's completion; `response` is `Null` when none was written.
    pub fn record(&self, request: HttpRequest, response: Value, expectation_id: Option<String>) {
        self.record_forwarded(request, response, None, expectation_id, None);
    }

    /// [`RequestLog::record`] with the completion's log line.
    pub fn record_with_message(&self, request: impl Into<Arc<HttpRequest>>, response: Value, expectation_id: Option<String>, message: impl Into<LogEntry>) {
        self.push_exchange(Exchange::new(request.into(), response, expectation_id).with_entry(Some(message.into())));
    }

    /// A served request's completion whose entry `make` builds from the exchange (its request, its response). The
    /// entry is built when the log is first read unless something needs it kept as built (a disk-capture hook sees it,
    /// `maxLoggedBodyBytes` cuts what it quotes, a control-plane request is masked); one the console prints is built
    /// for it and let go. `kind` is its type. Nothing is built for a log that keeps nothing.
    pub fn record_served(
        &self,
        logged: &LoggedRequest,
        response: Value,
        expectation_id: Option<String>,
        kind: Kind,
        make: impl Fn(&Exchange, &LoggedRequest) -> LogEntry + Send + Sync + 'static,
    ) {
        use std::sync::atomic::Ordering::{Acquire, Relaxed};
        let hooked = self.exchange_hook_set.load(Acquire);
        let printed = self.console_wanted(Level::Info, kind);
        if self.capacity.load(Relaxed) == 0 && !hooked && !printed {
            return;
        }
        let mut x = Exchange::new(logged.request.clone(), interned(response), expectation_id);
        if hooked || self.max_logged_body_bytes.load(Relaxed) > 0 || crate::credential_redaction::for_log(&x.request).is_some() {
            x.entry = ExchangeEntry::Built(Box::new(make(&x, logged)));
            return self.push_exchange(x);
        }
        let portless = in_portless_scope();
        if printed {
            // the console's copy is built now, from the logged form the request's other lines rendered, and let go:
            // the log keeps what builds it again
            self.console_entry(&completed_entry(make(&x, logged), &x, portless));
        }
        let kind = if kind == Kind::Info { x.completion_kind() } else { kind };
        let make = move |x: &Exchange| make(x, &LoggedRequest::shared(x.request.clone()));
        x.entry = ExchangeEntry::Deferred(Box::new(Deferred { kind, portless, make: Box::new(make), built: Default::default() }));
        self.push(Entry::Exchange(Arc::new(x)));
    }

    /// A completion's entry takes the exchange's type (`EXPECTATION_RESPONSE`, `NO_MATCH_RESPONSE`,
    /// `FORWARDED_REQUEST`) and attachments unless its call site set them.
    fn push_exchange(&self, mut x: Exchange) {
        // `CredentialRedaction.forLog`: a control-plane request's entry holds it without its credentials
        if let Some(masked) = crate::credential_redaction::for_log(&x.request) {
            x.request = Arc::new(masked);
            if let Some((shown, _)) = x.shown_request.as_ref().and_then(crate::credential_redaction::json_for_log) {
                x.shown_request = Some(shown);
            }
        }
        if let Some(entry) = x.take_entry() {
            let entry = completed_entry(entry, &x, in_portless_scope());
            self.console_entry(&entry);
            x.entry = ExchangeEntry::Built(Box::new(entry));
        }
        // Disk capture runs first, with the exchange as served; an archive's own re-import is never appended back.
        if !x.no_match && x.shown_request.is_none() && self.exchange_hook_set.load(std::sync::atomic::Ordering::Acquire) {
            let hook = self.exchange_hook.lock().clone();
            if let Some(hook) = hook {
                hook(&x);
            }
        }
        self.truncate_exchange(&mut x);
        self.push(Entry::Exchange(Arc::new(x)));
    }

    /// A `NO_MATCH_RESPONSE`: the request no expectation matched, its 404 and (with INFO) its log line.
    pub fn record_no_match(&self, request: impl Into<Arc<HttpRequest>>, response: Value, message: Option<LogEntry>) {
        // Below INFO the `NO_MATCH_RESPONSE` entry is not logged (`MockServerLogger`), and the exchange lives in that
        // entry: `REQUEST_RESPONSES`, `explainUnmatched` and the verifications read none of it (oracle).
        if message.is_none() {
            return;
        }
        let mut x = Exchange::new(request.into(), response, None).with_entry(message);
        x.no_match = true;
        self.push_exchange(x);
    }

    /// `retrieveUnmatchedRequests`: the most recent no-match exchanges, newest first, at most `limit` (1 to 100).
    pub fn unmatched(&self, limit: i64) -> Vec<Arc<Exchange>> {
        let limit = limit.clamp(1, 100) as usize;
        self.exchanges().into_iter().rev().filter(|x| x.no_match).take(limit).collect()
    }

    /// `recorded` is the recorded expectation, canonical and in input form; `message` the completion's log line.
    pub fn record_forwarded(
        &self,
        request: HttpRequest,
        response: Value,
        recorded: Option<(Value, Value)>,
        expectation_id: Option<String>,
        message: Option<LogEntry>,
    ) {
        let (recorded, recorded_input) = recorded.map(|(c, i)| (Some(c), Some(i))).unwrap_or_default();
        let mut x = Exchange::new(Arc::new(request), response, expectation_id).with_entry(message);
        (x.recorded, x.recorded_input) = (recorded, recorded_input);
        self.push_exchange(x);
    }

    /// `importRecordedRequestResponse`: a forwarded exchange read back from an archive; `shown` is the request as
    /// `REQUEST_RESPONSES` writes it.
    pub fn record_reimported(&self, request: HttpRequest, shown: Value, response: Value, recorded: (Value, Value), message: impl Into<LogEntry>) {
        let (recorded, recorded_input) = (Some(recorded.0), Some(recorded.1));
        let mut x = Exchange::new(Arc::new(request), response, None).with_entry(Some(message.into()));
        (x.recorded, x.recorded_input, x.shown_request) = (recorded, recorded_input, Some(shown));
        self.push_exchange(x);
    }

    /// Requests served by an expectation (optionally only by `id`), oldest first.
    pub fn served_by(&self, id: Option<&str>) -> Vec<Arc<Exchange>> {
        self.exchanges()
            .into_iter()
            .filter(|x| x.expectation_id.as_deref().is_some_and(|e| id.is_none_or(|id| id == e)))
            .collect()
    }

    pub fn message(&self, entry: impl Into<LogEntry>) {
        self.message_about(entry, Subject::None);
    }

    /// An entry about `subject`; one whose call site attached no request gets the subject as its request(s),
    /// which is what upstream filters entries by.
    pub fn message_about(&self, entry: impl Into<LogEntry>, subject: Subject) {
        let mut entry = entry.into();
        entry.portless |= in_portless_scope();
        let mut swaps = Vec::new();
        // `CredentialRedaction.forLog`: the request the entry is about, as it holds it
        let subject = match subject {
            Subject::Request(r) => Subject::Request(crate::credential_redaction::for_log(&r).map(Arc::new).unwrap_or(r)),
            other => other,
        };
        let subject = match subject {
            // `truncateBodiesForLog`: the entry's retained request is the cut copy, whoever attached it.
            Subject::Request(r) => match self.truncated_request(&r) {
                Some(cut) => {
                    let (whole, retained) = (logged(&r), logged(&cut));
                    if let Some(own) = entry.requests.as_mut().filter(|own| own.len() == 1 && *own[0] == whole) {
                        own[0] = crate::log_entry::Json::new(retained.clone());
                    }
                    swaps.push((whole, retained));
                    Subject::Request(Arc::new(cut))
                }
                None => Subject::Request(r),
            },
            other => other,
        };
        let max = self.max_logged_body_bytes.load(std::sync::atomic::Ordering::Relaxed);
        if max > 0 {
            entry.bound_quoted_bodies(max, &swaps);
        }
        if entry.requests.is_none() {
            entry = match &subject {
                Subject::None => entry,
                Subject::Request(r) => entry.request(r),
                Subject::Definition(d) => entry.request_json(d.clone()),
                Subject::Definitions(ds) => entry.requests(ds.clone()),
            };
        }
        self.console_entry(&entry);
        share_expectation(&mut entry);
        let kind = entry.kind;
        self.push(Entry::Message(Box::new(Message { timestamp: Local::now(), kind, entry: MessageEntry::Built(Box::new(entry)), subject })));
    }

    /// [`RequestLog::message_about`] `request` of the entry `make` builds, of type `kind` at `level`, with `request`
    /// (as its logged form) attached. The entry is built when the log is first read, unless something needs it kept as
    /// built: `maxLoggedBodyBytes` cuts what it quotes, a byte budget weighs it (and its weight was not given), or the
    /// request is a control-plane one whose credentials the log masks. One the console prints is built for it and let go. `make` builds the same
    /// entry each time it is called.
    pub fn message_about_deferred(&self, level: Level, kind: Kind, request: Arc<HttpRequest>, make: impl Fn() -> LogEntry + Send + Sync + 'static) {
        self.message_about_deferred_with(level, kind, request, None, None, make)
    }

    /// [`RequestLog::message_about_deferred`] given what the entry weighs (`weight`, asked only under a byte budget) and
    /// its console message (`text`, written as [`LogEntry::write_message`] writes it), so that neither builds it.
    pub fn message_about_deferred_with(
        &self,
        level: Level,
        kind: Kind,
        request: Arc<HttpRequest>,
        weight: Option<&dyn Fn() -> u64>,
        text: Option<crate::log::Text>,
        make: impl Fn() -> LogEntry + Send + Sync + 'static,
    ) {
        use std::sync::atomic::Ordering::Relaxed;
        let printed = self.console_wanted(level, kind);
        let capacity = self.capacity.load(Relaxed);
        if capacity == 0 && !printed {
            return;
        }
        let budget = self.max_bytes.load(Relaxed) > 0;
        if capacity == 0 || self.max_logged_body_bytes.load(Relaxed) > 0 || (budget && weight.is_none()) || crate::credential_redaction::for_log(&request).is_some() {
            return self.message_about(make(), Subject::Request(request));
        }
        let portless = in_portless_scope();
        let make = move || {
            let mut entry = make();
            entry.portless |= portless;
            entry
        };
        if printed {
            // a redacted line is rendered from the redacted entry
            match text.filter(|_| self.redaction_fields().is_none()) {
                Some(text) => self.console(level, kind, text, &|| make().compact_text(), portless),
                None => self.console_entry(&make()),
            }
        }
        let weight = weight.filter(|_| budget).map(|weight| weight());
        #[cfg(debug_assertions)]
        if weight.is_some() || text.is_some() {
            deferred_parts_check(&make(), &request, weight, text);
        }
        let entry = MessageEntry::Deferred { make: Box::new(make), built: Default::default(), weight };
        self.push(Entry::Message(Box::new(Message { timestamp: Local::now(), kind, entry, subject: Subject::Request(request) })));
    }

    /// Completed exchanges, oldest first.
    pub fn exchanges(&self) -> Vec<Arc<Exchange>> {
        self.locked()
            .entries()
            .filter_map(|e| match e {
                Entry::Exchange(x) => Some(x.clone()),
                _ => None,
            })
            .collect()
    }

    /// Received requests, oldest first.
    pub fn requests(&self) -> Vec<Arc<HttpRequest>> {
        self.locked()
            .entries()
            .filter_map(|e| match e {
                Entry::Received(r, ..) => Some(r.clone()),
                _ => None,
            })
            .collect()
    }

    /// The requests verification counts, oldest first: every received one, HTTP, DNS or binary (`requestLogPredicate`),
    /// or with `answered` only those an expectation answered (`answeredRequestLogPredicate`: the completed exchanges an
    /// expectation served, and the DNS and binary received entries naming the expectation that answered them).
    pub fn recorded_requests(&self, answered: bool) -> Vec<RecordedRequest> {
        self.locked()
            .entries()
            .filter_map(|e| match e {
                Entry::Received(r, ts, ..) if !answered => Some(RecordedRequest { request: Received::Http(r.clone()), expectation_id: None, millis: ts.timestamp_millis() }),
                Entry::Exchange(x) if answered && x.expectation_id.is_some() => Some(RecordedRequest {
                    request: Received::Http(x.request.clone()),
                    expectation_id: x.expectation_id.clone(),
                    millis: x.timestamp.timestamp_millis(),
                }),
                Entry::Message(m) if m.kind == Kind::ReceivedRequest && (!answered || m.entry().expectation_id.is_some()) => match &m.subject {
                    Subject::Definition(d) if canonical::is_dns_request(d) || canonical::is_binary_request(d) => {
                        Some(RecordedRequest { request: Received::Definition(d.clone()), expectation_id: m.entry().expectation_id.clone(), millis: m.timestamp.timestamp_millis() })
                    }
                    _ => None,
                },
                _ => None,
            })
            .collect()
    }

    /// The definitions of the DNS queries and binary messages received whose definition passes `definition`
    /// (`retrieveRequests` by a DNS or binary filter), oldest first.
    pub fn received_definitions(&self, definition: impl Fn(&Value) -> bool) -> Vec<Value> {
        self.recorded_requests(false)
            .into_iter()
            .filter_map(|r| match r.request {
                Received::Definition(d) if definition(&d) => Some(d),
                _ => None,
            })
            .collect()
    }

    /// Received requests logged after `epoch_millis` (`RecordedRequest.arrivedAtMillis > verificationStartedAtMillis`),
    /// the arrivals a failed verification's summary counts.
    pub fn received_after(&self, epoch_millis: i64) -> usize {
        self.locked().entries().filter(|e| matches!(e, Entry::Received(_, ts, ..) if ts.timestamp_millis() > epoch_millis)).count()
    }

    /// `RECEIVED_REQUEST` entries whose request matches `filter`, as `retrieve?format=LOG_ENTRIES` serialises them
    /// (`LogEntrySerializer`). `redactSecretsInLog` (`config`) masks the top-level `httpRequest` field only — the
    /// `message`/`arguments` keep the raw request, matching the oracle (see [`redact_entry_json`]).
    pub fn received_log_entries(&self, filter: Option<&RequestMatcher>, config: &Config) -> Vec<Value> {
        let fields = redact_fields(config);
        self.locked()
            .entries()
            .filter_map(|e| match e {
                Entry::Received(r, ts, id, _, whole, _) if filter.is_none_or(|f| crate::matcher::as_received(|| f.matches(r, Mode::ControlPlane))) => {
                    Some(redact_entry_json(received_log_entry(r, ts, received_id(r, id), whole.as_deref(), fields.as_deref(), false), fields.as_deref()))
                }
                _ => None,
            })
            .collect()
    }

    /// Received requests matching `filter` (all of them for `None`).
    pub fn matching_requests(&self, filter: Option<&RequestMatcher>) -> Vec<Arc<HttpRequest>> {
        self.requests().into_iter().filter(|r| filter.is_none_or(|f| crate::matcher::as_received(|| f.matches(r, Mode::ControlPlane)))).collect()
    }

    /// How many entries of `kind` (`EXPECTATION_RESPONSE` or `FORWARDED_REQUEST`) hold a request that matches
    /// `filter`: what a verification by disposition counts (`mockedRequestLogPredicate`,
    /// `forwardedRequestLogPredicate`).
    pub fn handled(&self, kind: Kind, filter: &RequestMatcher) -> usize {
        // Collected first: the matcher may log (a regex timeout), which takes the log's lock.
        let (mut exchanges, mut messages) = (Vec::new(), Vec::new());
        for e in self.locked().entries() {
            match e {
                Entry::Exchange(x) if x.entry_kind() == Some(kind) => exchanges.push(x.clone()),
                Entry::Message(m) if m.kind == kind => {
                    if let Subject::Request(r) = &m.subject {
                        messages.push(r.clone());
                    }
                }
                _ => {}
            }
        }
        let matches = |r: &HttpRequest| crate::matcher::as_received(|| filter.matches(r, Mode::ControlPlane));
        exchanges.iter().filter(|x| matches(&x.request)).count() + messages.iter().filter(|r| matches(r)).count()
    }

    /// Completed exchanges whose request matches `filter`.
    pub fn matching(&self, filter: Option<&RequestMatcher>) -> Vec<Arc<Exchange>> {
        self.exchanges().into_iter().filter(|x| filter.is_none_or(|f| f.matches(&x.request, Mode::ControlPlane))).collect()
    }

    /// Log lines, oldest first, keeping those whose request passes `request` and whose request matcher passes
    /// `definition`.
    pub fn messages(&self, request: impl Fn(&HttpRequest) -> bool, definition: impl Fn(&Value) -> bool) -> Vec<(DateTime<Local>, String)> {
        let fields = self.redaction_fields();
        let fields = fields.as_deref();
        self.locked()
            .entries()
            .filter_map(|e| match e {
                Entry::Received(..) => e.received_request().filter(|r| crate::matcher::as_received(|| request(r))).map(|_| e.text(fields)),
                Entry::Exchange(x) => x.entry_kind().filter(|_| request(&x.request)).map(|_| e.text(fields)),
                Entry::Message(m) => {
                    let keep = match &m.subject {
                        Subject::None => true,
                        Subject::Request(r) => request(r),
                        Subject::Definition(d) => definition(d),
                        Subject::Definitions(ds) => ds.is_empty() || ds.iter().any(&definition),
                    };
                    keep.then(|| e.text(fields))
                }
            })
            .collect()
    }

    /// Entries as `retrieve?format=LOG_ENTRIES` serialises them (`LogEntrySerializer`), oldest first: every entry
    /// passing the same filters as [`RequestLog::messages`] (`retrieveMessageLogEntries`), or only the completions
    /// (`retrieveRequestResponseMessageLogEntries`) or only the forwarded ones (`retrieveRecordedExpectationLogEntries`).
    /// `port` is the server's own. `redactSecretsInLog` (`config`) masks each entry's top-level
    /// `httpRequest(s)`/`httpResponse` field only — see [`redact_entry_json`].
    pub fn log_entries(
        &self,
        scope: EntryScope,
        request: impl Fn(&HttpRequest) -> bool,
        definition: impl Fn(&Value) -> bool,
        port: Option<u16>,
        config: &Config,
    ) -> Vec<Value> {
        self.log_entries_as(scope, request, definition, port, config, false)
    }

    /// [`RequestLog::log_entries`] for the dashboard (`dashboard`): each entry also carries what
    /// [`LogEntry::to_dashboard_json`] adds.
    pub fn log_entries_as(
        &self,
        scope: EntryScope,
        request: impl Fn(&HttpRequest) -> bool,
        definition: impl Fn(&Value) -> bool,
        port: Option<u16>,
        config: &Config,
        dashboard: bool,
    ) -> Vec<Value> {
        self.log_entries_filtered(scope, request, definition, port, config, dashboard, None)
    }

    /// `retrieveLogEntriesByCorrelationId` as `retrieve?type=LOGS&format=LOG_ENTRIES&correlationId=` serialises it:
    /// every entry, of any kind, whose correlation id equals `correlation_id`, oldest first. No request filter applies.
    pub fn log_entries_correlated(&self, correlation_id: &str, port: Option<u16>, config: &Config) -> Vec<Value> {
        self.log_entries_filtered(EntryScope::Messages, |_| true, |_| true, port, config, false, Some(correlation_id))
    }

    /// The log lines of [`RequestLog::log_entries_correlated`].
    pub fn messages_correlated(&self, correlation_id: &str) -> Vec<(DateTime<Local>, String)> {
        let fields = self.redaction_fields();
        self.locked()
            .entries()
            .filter(|e| e.correlation_id() == Some(correlation_id))
            .filter(|e| !matches!(e, Entry::Exchange(x) if x.entry_kind().is_none()))
            .map(|e| e.text(fields.as_deref()))
            .collect()
    }

    /// `HttpState.explain`'s read of one correlation id: its `RECEIVED_REQUEST`, `EXPECTATION_RESPONSE`,
    /// `FORWARDED_REQUEST` and `NO_MATCH_RESPONSE` entries (`EXPLAINABLE_REQUEST_TYPES`), oldest first. A completion
    /// logged without an entry (below INFO) is no entry upstream either.
    pub fn explainable(&self, correlation_id: &str) -> Vec<Explainable> {
        self.locked()
            .entries()
            .filter(|e| e.correlation_id() == Some(correlation_id))
            .filter_map(|e| match e {
                Entry::Received(r, ts, ..) => {
                    Some(Explainable { kind: Kind::ReceivedRequest, request: Some(HttpRequest::clone(r)), timestamp: *ts, entry: None })
                }
                Entry::Exchange(x) => {
                    let entry = x.entry()?;
                    Some(Explainable { kind: entry.kind, request: Some(HttpRequest::clone(&x.request)), timestamp: x.timestamp, entry: Some(entry.clone()) })
                }
                Entry::Message(m) => {
                    let request = match &m.subject {
                        Subject::Request(r) => Some(HttpRequest::clone(r)),
                        _ => None,
                    };
                    Some(Explainable { kind: m.kind, request, timestamp: m.timestamp, entry: Some(m.entry().clone()) })
                }
            })
            .filter(|e| matches!(e.kind, Kind::ReceivedRequest | Kind::ExpectationResponse | Kind::ForwardedRequest | Kind::NoMatchResponse))
            .collect()
    }

    #[allow(clippy::too_many_arguments)]
    fn log_entries_filtered(
        &self,
        scope: EntryScope,
        request: impl Fn(&HttpRequest) -> bool,
        definition: impl Fn(&Value) -> bool,
        port: Option<u16>,
        config: &Config,
        dashboard: bool,
        correlation: Option<&str>,
    ) -> Vec<Value> {
        let fields = redact_fields(config);
        let render = |entry: &LogEntry, timestamp: &DateTime<Local>| {
            let entry = entry.settled();
            let entry = &*entry;
            // `redactSecretsInLog`: message, arguments, `because` and throwable too (upstream cc7d7d185, c76143e4a)
            let redacted = fields.as_deref().map(|f| entry.redacted(f));
            let entry = redacted.as_ref().unwrap_or(entry);
            if dashboard { entry.to_dashboard_json(timestamp, port) } else { entry.to_json(timestamp, port) }
        };
        let exchange = |x: &Exchange| -> Value {
            let fallback;
            let entry = match x.entry() {
                Some(e) => e,
                None => {
                    fallback = LogEntry::new(x.completion_kind(), "").request(&x.request);
                    &fallback
                }
            };
            redact_entry_json(render(entry, &x.timestamp), fields.as_deref())
        };
        self.locked()
            .entries()
            .filter(|e| correlation.is_none_or(|c| e.correlation_id() == Some(c)))
            .filter_map(|e| match (scope, e) {
                (EntryScope::Messages, Entry::Received(r, ts, id, _, whole, _)) => {
                    crate::matcher::as_received(|| request(r)).then(|| redact_entry_json(received_log_entry(r, ts, received_id(r, id), whole.as_deref(), fields.as_deref(), dashboard), fields.as_deref()))
                }
                (EntryScope::Messages, Entry::Exchange(x)) => {
                    x.entry_kind().filter(|_| request(&x.request)).and_then(|_| x.entry()).map(|m| redact_entry_json(render(m, &x.timestamp), fields.as_deref()))
                }
                (EntryScope::Messages, Entry::Message(m)) => {
                    let keep = match &m.subject {
                        Subject::None => true,
                        Subject::Request(r) => request(r),
                        Subject::Definition(d) => definition(d),
                        Subject::Definitions(ds) => ds.is_empty() || ds.iter().any(&definition),
                    };
                    keep.then(|| redact_entry_json(render(m.entry(), &m.timestamp), fields.as_deref()))
                }
                (EntryScope::ReceivedDefinitions, Entry::Message(m)) if m.kind == Kind::ReceivedRequest => match &m.subject {
                    Subject::Definition(d) if (canonical::is_dns_request(d) || canonical::is_binary_request(d)) && definition(d) => {
                        Some(redact_entry_json(render(m.entry(), &m.timestamp), fields.as_deref()))
                    }
                    _ => None,
                },
                (EntryScope::RequestResponses, Entry::Exchange(x)) => request(&x.request).then(|| exchange(x)),
                (EntryScope::RecordedExpectations, Entry::Exchange(x)) if x.recorded.is_some() => request(&x.request).then(|| exchange(x)),
                _ => None,
            })
            .collect()
    }

    /// `getEvictedCount`.
    pub fn evicted(&self) -> u64 {
        self.evicted.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// `Metrics.getEvictedLogEntryCount`: the evictions since the server started, which a reset does not forget.
    pub fn evicted_since_start(&self) -> u64 {
        self.evicted_since_start.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// `getByteEvictedCount`: the evictions `maxEventLogSizeInBytes` caused.
    pub fn byte_evicted(&self) -> u64 {
        self.byte_evicted.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// `reset`: every entry goes, and past evictions are forgotten.
    pub fn reset(&self) {
        self.locked().clear();
        self.bytes.store(0, std::sync::atomic::Ordering::Relaxed);
        self.evicted.store(0, std::sync::atomic::Ordering::Relaxed);
        self.byte_evicted.store(0, std::sync::atomic::Ordering::Relaxed);
        self.changes.touch();
        self.notify_recorded();
    }

    /// `MockServerEventLog.clear`: removes the entries about a request passing `request` or a request matcher
    /// passing `definition`. `None` removes every entry about a request or matcher (and forgets past evictions);
    /// entries about neither (`cleared expectations that have id`, startup lines) survive both.
    pub fn clear(&self, filter: Option<ClearFilter>) {
        let (request, definition): ClearFilter = match filter {
            Some(f) => f,
            None => {
                self.evicted.store(0, std::sync::atomic::Ordering::Relaxed);
                self.byte_evicted.store(0, std::sync::atomic::Ordering::Relaxed);
                (&|_| true, &|_| true)
            }
        };
        let mut entries = self.locked();
        entries.retain(|slot| match &slot.entry {
            Entry::Received(r, ..) => !request(r),
            Entry::Exchange(x) => !request(&x.request),
            Entry::Message(m) => match &m.subject {
                Subject::None => true,
                Subject::Request(r) => !request(r),
                Subject::Definition(d) => !definition(d),
                Subject::Definitions(ds) => !ds.iter().any(definition),
            },
        });
        if self.max_bytes.load(std::sync::atomic::Ordering::Relaxed) > 0 {
            self.bytes.store(entries.iter().map(|slot| slot.weight).sum(), std::sync::atomic::Ordering::Relaxed);
        }
        drop(entries);
        self.changes.touch();
        self.notify_recorded();
    }
}

// --- `redactSecretsInLog` / `fixtureBodyRedactFields` (`FixtureRedactor`) ---------------------------
//
// Upstream's `LogEntry.getRedactedHttpRequests`/`getRedactedHttpResponse` and `LogEntrySerializer` mask sensitive
// header/query-string values and configured JSON body fields on the *retrieved* views of the event log only — the
// live log entry (and everything matching/verification reads) is never mutated. Verified against the oracle
// (`mockserver/mockserver:8.0.0`, see PLAN.md): `REQUESTS` and `REQUEST_RESPONSES`, every format, are redacted
// (they all derive from the same redacted list); `RECORDED_EXPECTATIONS` in its own JSON/JAVA/… forms is not
// (gated by the separate, unimplemented `redactSecretsInRecordedExpectations`); `LOG_ENTRIES` format redacts only
// the top-level `httpRequest`/`httpRequests`/`httpResponse` field of each entry, never `message`/`arguments`;
// plain-text `LOGS` is not redacted at all.

/// `FixtureRedactor.REDACTED_PLACEHOLDER`.
pub const LOG_REDACTED: &str = "***REDACTED***";
/// `FixtureRedactor.UNPARSEABLE_BODY_PLACEHOLDER`.
const LOG_REDACT_UNPARSEABLE: &str = "<redacted: body could not be parsed for field redaction>";
/// `FixtureRedactor.DEFAULT_SENSITIVE_HEADERS`, case-insensitive.
pub(crate) const LOG_REDACT_HEADERS: &[&str] = &["Authorization", "x-api-key", "api-key", "Cookie", "Set-Cookie", "Proxy-Authorization"];
/// `FixtureRedactor.DEFAULT_SENSITIVE_QUERY_PARAMS`, case-insensitive.
pub(crate) const LOG_REDACT_QUERY: &[&str] = &["key", "api_key", "apikey", "access_token", "token", "signature", "x-amz-signature", "x-amz-security-token", "sig"];

/// `Some(fixtureBodyRedactFields)` when `redactSecretsInLog` is on (see [`Config::redact_secrets_in_log`]),
/// else `None` (nothing to redact, the byte-for-byte-unchanged fast path).
pub(crate) fn redact_fields(config: &Config) -> Option<Vec<String>> {
    config.redact_secrets_in_log().then(|| config.fixture_body_redact_fields())
}

/// Masks every entry whose name is in `names` (case-insensitive) on a native `MultiMap`; `true` when at least
/// one entry was masked.
fn redact_multimap(map: &mut MultiMap, names: &[&str]) -> bool {
    let mut changed = false;
    for (name, values) in map.iter_mut() {
        if names.iter().any(|n| n.eq_ignore_ascii_case(name)) {
            *values = vec![LOG_REDACTED.to_string()];
            changed = true;
        }
    }
    changed
}

/// As [`redact_multimap`], on the JSON object form (`{"Name": ["v1", …]}`) `map_value`/`bare_body` produce.
fn redact_multimap_json(map: &mut Value, names: &[&str]) {
    let Some(o) = map.as_object_mut() else { return };
    let keys: Vec<String> = o.keys().cloned().collect();
    for k in keys {
        if names.iter().any(|n| n.eq_ignore_ascii_case(&k)) {
            o.insert(k, json!([LOG_REDACTED]));
        }
    }
}

/// `FixtureRedactor.redactCookies` on a `cookies` field in either JSON form (`{"name": "value"}` or
/// `[{"name": …, "value": …}]`).
pub(crate) fn redact_cookies_json(cookies: &mut Value) {
    match cookies {
        Value::Object(o) => o.values_mut().for_each(|v| *v = Value::String(LOG_REDACTED.into())),
        Value::Array(items) => {
            for item in items.iter_mut().filter_map(Value::as_object_mut) {
                if item.contains_key("value") {
                    item.insert("value".into(), Value::String(LOG_REDACTED.into()));
                }
            }
        }
        _ => {}
    }
}

fn redact_headers_json(headers: &mut Value) {
    redact_multimap_json(headers, LOG_REDACT_HEADERS);
}

fn redact_query_json(query: &mut Value) {
    redact_multimap_json(query, LOG_REDACT_QUERY);
}

/// `FixtureRedactor.redactJsonNode`: replaces the value of any field in `fields` (case-insensitive) with the
/// placeholder, at any depth; does not descend into a redacted field's own (now-discarded) value.
fn redact_json_fields(v: &mut Value, fields: &[String]) {
    match v {
        Value::Object(o) => {
            let keys: Vec<String> = o.keys().cloned().collect();
            for k in keys {
                if fields.iter().any(|f| f.eq_ignore_ascii_case(&k)) {
                    o.insert(k, Value::String(LOG_REDACTED.to_string()));
                } else if let Some(child) = o.get_mut(&k) {
                    redact_json_fields(child, fields);
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(|c| redact_json_fields(c, fields)),
        _ => {}
    }
}

/// An SSE / streamed body: at least one line (tolerating a `\r\n` separator) starts with `data:`.
pub(crate) fn is_sse_body(body: &str) -> bool {
    body.split('\n').any(|segment| segment.strip_suffix('\r').unwrap_or(segment).starts_with("data:"))
}

/// `FixtureRedactor.mentionsSensitiveBodyField`: whether the raw text names any configured field, case-insensitive.
pub(crate) fn mentions_field(text: &str, fields: &[String]) -> bool {
    let lower = text.to_lowercase();
    fields.iter().any(|f| lower.contains(&f.to_lowercase()))
}

/// `FixtureRedactor.redactSseBody`: redacts each `data:` JSON payload, preserving the line structure.
fn redact_sse_body(body: &str, fields: &[String]) -> String {
    body.split('\n')
        .map(|segment| {
            let (line, cr) = match segment.strip_suffix('\r') {
                Some(l) => (l, "\r"),
                None => (segment, ""),
            };
            let rewritten = match line.strip_prefix("data:") {
                Some(after) => {
                    let space = if after.starts_with(' ') { " " } else { "" };
                    format!("data:{space}{}", redact_sse_payload(&after[space.len()..], fields))
                }
                None => line.to_string(),
            };
            format!("{rewritten}{cr}")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// `FixtureRedactor.redactJsonPayloadOrSelf`.
fn redact_sse_payload(payload: &str, fields: &[String]) -> String {
    let trimmed = payload.trim();
    if trimmed.is_empty() {
        return payload.to_string();
    }
    if let Ok(mut v) = serde_json::from_str::<Value>(trimmed) && (v.is_object() || v.is_array()) {
        redact_json_fields(&mut v, fields);
        return serde_json::to_string(&v).unwrap_or_default();
    }
    if mentions_field(payload, fields) { LOG_REDACT_UNPARSEABLE.to_string() } else { payload.to_string() }
}

/// `FixtureRedactor.redactBodyIfNeeded`: `text` redacted to its new plain-text form, or `None` when nothing
/// changes (no fields configured, empty text, a scalar JSON value, or unstructured text naming no configured
/// field). A single JSON document (object/array) is always re-emitted once any field is configured — matching
/// upstream, which does not skip the type-to-string collapse just because no field in it actually matched.
fn redact_body_text(text: &str, fields: &[String]) -> Option<String> {
    if fields.is_empty() || text.is_empty() {
        return None;
    }
    if let Ok(mut v) = serde_json::from_str::<Value>(text) {
        if v.is_object() || v.is_array() {
            redact_json_fields(&mut v, fields);
            return Some(serde_json::to_string(&v).unwrap_or_default());
        }
        return None;
    }
    if is_sse_body(text) {
        return Some(redact_sse_body(text, fields));
    }
    if mentions_field(text, fields) { Some(LOG_REDACT_UNPARSEABLE.to_string()) } else { None }
}

/// A redacted clone of `request` (sensitive headers, query-string values and, with `fields`, JSON body fields),
/// matching `FixtureRedactor.redactRequest`. Used by every format built from `retrieve?type=REQUESTS`'s redacted
/// list (JSON, JAVA, CURL, HAR, OPENAPI, POSTMAN, BRUNO all share one redacted source, verified against the
/// oracle) and by `REQUEST_RESPONSES`'s request side.
fn redact_request(request: &HttpRequest, fields: &[String]) -> HttpRequest {
    let mut r = request.clone();
    redact_multimap(&mut r.headers, LOG_REDACT_HEADERS);
    // `redactCookies` (upstream c76143e4a): the parsed cookies too, which `cookies`, HAR and the cURL form's
    // rebuilt `Cookie` header show
    r.cookies.iter_mut().for_each(|(_, v)| *v = LOG_REDACTED.to_string());
    if redact_multimap(&mut r.query, LOG_REDACT_QUERY) {
        // `raw_query`, when present, otherwise wins over `query` for the URL's query string (`uri()`) — stale
        // once a value in `query` has changed, like every other in-place query edit in this codebase (`forward.rs`).
        r.raw_query = None;
    }
    if let Some(new_text) = redact_body_text(&request.body_str(), fields) {
        r.body = Bytes::from(new_text.into_bytes());
        r.body_kind = BodyKind::PlainString;
        // The pre-decompression bytes would otherwise still show the un-redacted secret under `originalBody`.
        r.original_body = None;
    }
    r
}

/// `retrieve?type=REQUESTS`: `requests` redacted under `redactSecretsInLog` (a no-op, returned unchanged, when
/// it is off).
pub fn redact_requests(requests: Vec<Arc<HttpRequest>>, config: &Config) -> Vec<Arc<HttpRequest>> {
    let Some(fields) = redact_fields(config) else { return requests };
    requests.iter().map(|r| Arc::new(redact_request(r, &fields))).collect()
}

/// The body text to attempt field redaction on, from either shape a response/request `Value` carries a body in:
/// the typed wrapper [`body_json`] produces (`{"type": …}`, [`ordered`]'s and a re-imported `shown_request`'s
/// form), or an already-bare value ([`bare_body`]'s output — `Exchange.response` for ordinary traffic is built
/// from [`logged_response`], so it is bare, not typed; the two shapes are not used consistently, so both are
/// tried here). `BINARY`'s base64 text is included too — upstream's `getBodyAsString()` returns a binary body's
/// base64 text as well, so a configured field name that merely appears in it still fails closed.
pub(crate) fn response_body_text(body: &Value) -> Option<String> {
    match body {
        Value::String(s) => Some(s.clone()),
        Value::Object(o) => match o.get("type").and_then(Value::as_str) {
            Some("JSON") => serde_json::to_string(o.get("json").unwrap_or(&Value::Null)).ok(),
            Some("STRING") => o.get("string").and_then(Value::as_str).map(str::to_string),
            Some("XML") => o.get("xml").and_then(Value::as_str).map(str::to_string),
            Some("BINARY") => o.get("base64Bytes").and_then(Value::as_str).map(str::to_string),
            // No recognised wrapper: a bare JSON object/array body (or one with an unrelated "type" field) —
            // treat the whole thing as the value to redact fields in.
            _ => serde_json::to_string(body).ok(),
        },
        Value::Array(_) => serde_json::to_string(body).ok(),
        _ => None,
    }
}

/// Redacts a `Value` shaped like [`ordered`]/[`exchange_json`]/[`logged`]/[`logged_response`] build it
/// (`headers`/`queryStringParameters` as `{"Name": […]}`, `body` in either shape [`response_body_text`] reads):
/// `Exchange.response`, `shown_request`, and a `LOG_ENTRIES` entry's top-level `httpRequest(s)`/`httpResponse`.
pub(crate) fn redact_value(v: &Value, fields: &[String], has_query: bool) -> Value {
    let Some(obj) = v.as_object() else { return v.clone() };
    let mut o = obj.clone();
    if let Some(h) = o.get_mut("headers") {
        redact_headers_json(h);
    }
    if has_query && let Some(q) = o.get_mut("queryStringParameters") {
        redact_query_json(q);
    }
    if let Some(cookies) = o.get_mut("cookies") {
        // `redactCookies` (upstream c76143e4a): the parsed cookies as well as the `Cookie` / `Set-Cookie`
        // header they came from; 8.0.0 left them readable
        redact_cookies_json(cookies);
    }
    if let Some(body) = o.get("body").cloned() && let Some(new_text) = response_body_text(&body).and_then(|t| redact_body_text(&t, fields)) {
        o.insert("body".into(), Value::String(new_text));
    }
    Value::Object(o)
}

/// `retrieve?type=REQUEST_RESPONSES`: `exchanges` redacted (request, response and — for a re-imported exchange —
/// `shown_request`) under `redactSecretsInLog`.
pub fn redact_exchanges(exchanges: Vec<Arc<Exchange>>, config: &Config) -> Vec<Arc<Exchange>> {
    let Some(fields) = redact_fields(config) else { return exchanges };
    exchanges
        .iter()
        .map(|x| {
            let mut e = (**x).clone();
            e.request = Arc::new(redact_request(&x.request, &fields));
            e.response = Arc::new(redact_value(&e.response, &fields, false));
            // The recorded expectation's original JSON text, which the HAR export prefers to the model's, still quotes
            // the redacted fields: the export renders the redacted model instead.
            let body_redacted = e.response.get("body") != x.response.get("body");
            if let Some(body) = e.recorded_input.as_mut().and_then(|i| i.pointer_mut("/httpResponse/body")).and_then(Value::as_object_mut).filter(|_| body_redacted) && body.get("json").is_some_and(Value::is_string) {
                body.remove("json");
            }
            if let Some(shown) = &e.shown_request {
                e.shown_request = Some(redact_value(shown, &fields, true));
            }
            Arc::new(e)
        })
        .collect()
}

/// `LogEntrySerializer.serialize`'s redaction: overwrites a `LOG_ENTRIES` entry's top-level `httpRequest`/
/// `httpRequests`/`httpResponse` field(s) with their redacted form — `message` and `arguments` are left exactly
/// as built (verified against the oracle: they keep the entry's original, un-redacted values even when the
/// top-level field is masked). `None` fields (redaction off) is a no-op, returned unchanged.
/// `EventLogRedactor.redactRequestDefinition` under `redactSecretsInLog`: a binary definition with bytes gets
/// `***REDACTED***`'s bytes in their place (`None` for anything else).
pub fn masked_binary_definition(v: &Value) -> Option<Value> {
    let o = v.as_object().filter(|o| o.get("binaryData").and_then(Value::as_str).is_some_and(|d| !d.is_empty()))?;
    let mut out = o.clone();
    out.insert("binaryData".into(), Value::String(B64.encode(LOG_REDACTED)));
    Some(Value::Object(out))
}

fn redact_entry_json(mut v: Value, fields: Option<&[String]>) -> Value {
    let Some(fields) = fields else { return v };
    let Some(o) = v.as_object_mut() else { return v };
    let redact_request = |r: &Value| masked_binary_definition(r).unwrap_or_else(|| redact_value(r, fields, true));
    if let Some(r) = o.get("httpRequest").cloned() {
        o.insert("httpRequest".into(), redact_request(&r));
    }
    if let Some(Value::Array(rs)) = o.get("httpRequests").cloned() {
        o.insert("httpRequests".into(), Value::Array(rs.iter().map(redact_request).collect()));
    }
    if let Some(resp) = o.get("httpResponse").cloned() {
        o.insert("httpResponse".into(), redact_value(&resp, fields, false));
    }
    v
}

// --- `redactSecretsInRecordedExpectations` ----------------------------------------------------------
//
// A separate, startup-only property from `redactSecretsInLog` above (same class of oracle-vs-Java-source
// divergence, confirmed the same way: a `PUT /mockserver/configuration` change the control-plane configuration
// listing echoes back as applied still has no effect on the next retrieve, for an expectation recorded before
// *or* after the change — only an env var present at container start does). Upstream applies a no-arg
// `new FixtureRedactor()` (default sensitive headers and query-string values — the *same* lists as
// `LOG_REDACT_HEADERS`/`LOG_REDACT_QUERY` above; never a JSON body field, since the no-arg constructor's
// body-field set is empty) to `retrieve?type=RECORDED_EXPECTATIONS`'s own JSON, JAVA, JAVASCRIPT, PYTHON, GO,
// CSHARP, RUBY, RUST, PHP, OPENAPI, POSTMAN, BRUNO and HAR forms, all built from the one redacted `recorded`
// (canonical, map-form headers/query) and `recorded_input` (list-form) pair — never `LOG_ENTRIES` (its own,
// untouched event-log path) or `CURL` ("not supported for RECORDED_EXPECTATIONS"), both verified against the
// oracle. Query-string redaction is request-only, matching `FixtureRedactor.redactQueryStringIfNeeded`. The
// 8.0.0 oracle left a parsed `cookies` field unredacted even when the `Cookie`/`Set-Cookie` *header* carrying the
// same value was masked (`redactRequest`/`redactResponse` only rewrote `headers`); upstream c76143e4a masks them too
// (`redactCookies`), adopted after 8.0.0.

/// Masks every entry named in `names` (case-insensitive) on the list form (`[{"name", "values"}]`)
/// `recorded_input` carries headers/query-string parameters in — the [`redact_multimap_json`] equivalent for
/// that shape.
fn redact_list_form_json(v: &mut Value, names: &[&str]) {
    let Some(items) = v.as_array_mut() else { return };
    for item in items.iter_mut() {
        let Some(o) = item.as_object_mut() else { continue };
        let matches = o.get("name").and_then(Value::as_str).is_some_and(|n| names.iter().any(|w| w.eq_ignore_ascii_case(n)));
        if matches {
            o.insert("values".into(), json!([LOG_REDACTED]));
        }
    }
}

/// A canonical (map-form headers/query) `httpRequest`/`httpResponse` object from `recorded`, redacted in place.
fn redact_recorded_map(v: &mut Value, is_request: bool) {
    let Some(o) = v.as_object_mut() else { return };
    if let Some(h) = o.get_mut("headers") {
        redact_headers_json(h);
    }
    if let Some(c) = o.get_mut("cookies") {
        redact_cookies_json(c);
    }
    if is_request && let Some(q) = o.get_mut("queryStringParameters") {
        redact_query_json(q);
    }
}

/// As [`redact_recorded_map`], for the list form `recorded_input` carries its `httpRequest`/`httpResponse` in.
fn redact_recorded_list(v: &mut Value, is_request: bool) {
    let Some(o) = v.as_object_mut() else { return };
    if let Some(h) = o.get_mut("headers") {
        redact_list_form_json(h, LOG_REDACT_HEADERS);
    }
    if let Some(c) = o.get_mut("cookies") {
        redact_cookies_json(c);
    }
    if is_request && let Some(q) = o.get_mut("queryStringParameters") {
        redact_list_form_json(q, LOG_REDACT_QUERY);
    }
}

/// `HttpState.postProcessRecordedExpectations`'s `redactSecretsInRecordedExpectations` step: every non-
/// `LOG_ENTRIES`/`CURL` format built from `retrieve?type=RECORDED_EXPECTATIONS` shares this redacted `recorded`/
/// `recorded_input` pair (a no-op, the input returned unchanged, when the property is off — the
/// byte-for-byte-unchanged fast path, and the default).
pub fn redact_recorded_expectations(exchanges: Vec<Arc<Exchange>>, config: &Config) -> Vec<Arc<Exchange>> {
    if !config.redact_secrets_in_recorded_expectations() {
        return exchanges;
    }
    exchanges
        .into_iter()
        .map(|x| {
            let mut e = (*x).clone();
            if let Some(mut canonical) = e.recorded.take() {
                if let Some(req) = canonical.get_mut("httpRequest") {
                    redact_recorded_map(req, true);
                }
                if let Some(resp) = canonical.get_mut("httpResponse") {
                    redact_recorded_map(resp, false);
                }
                e.recorded = Some(canonical);
            }
            if let Some(mut input) = e.recorded_input.take() {
                if let Some(req) = input.get_mut("httpRequest") {
                    redact_recorded_list(req, true);
                }
                if let Some(resp) = input.get_mut("httpResponse") {
                    redact_recorded_list(resp, false);
                }
                e.recorded_input = Some(input);
            }
            Arc::new(e)
        })
        .collect()
}

/// The exception a generator endpoint (wsdl, graphql, scim, oidc, saml) fails with: its message, the 400 text, and
/// the throwable HttpState logs with it, as Jackson's bean (`stackTrace` empty: JVM frames cannot be reproduced) and
/// the classes of its cause chain, outermost first, for the console.
#[derive(Debug, Clone)]
pub struct Failure {
    pub message: String,
    pub bean: Value,
    pub classes: Vec<&'static str>,
}

pub const ILLEGAL_ARGUMENT: &str = "java.lang.IllegalArgumentException";

impl Failure {
    /// An exception of `class` whose bean has `fields` besides `localizedMessage`, `message` and `stackTrace` (a
    /// `cause` among them names its own classes in `cause_classes`). Jackson writes the properties alphabetically.
    pub fn of(class: &'static str, message: impl Into<String>, fields: Vec<(&str, Value)>, cause_classes: &[&'static str]) -> Failure {
        let message = message.into();
        let mut properties: Vec<(String, Value)> = fields.into_iter().map(|(k, v)| (k.to_string(), v)).collect();
        properties.push(("localizedMessage".into(), message.clone().into()));
        properties.push(("message".into(), message.clone().into()));
        properties.push(("stackTrace".into(), Value::Array(Vec::new())));
        properties.sort_by(|a, b| a.0.cmp(&b.0));
        let mut classes = vec![class];
        classes.extend_from_slice(cause_classes);
        Failure { message, bean: Value::Object(properties.into_iter().collect()), classes }
    }

    /// The generators' own `IllegalArgumentException`, with no cause.
    pub fn illegal(message: impl Into<String>) -> Failure {
        Failure::of(ILLEGAL_ARGUMENT, message, Vec::new(), &[])
    }

    /// An `IllegalArgumentException` wrapping `cause` (`new IllegalArgumentException(message, cause)`).
    pub fn illegal_caused(message: impl Into<String>, cause: Failure) -> Failure {
        Failure::of(ILLEGAL_ARGUMENT, message, vec![("cause", cause.bean)], &cause.classes)
    }
}

impl From<String> for Failure {
    fn from(message: String) -> Failure {
        Failure::illegal(message)
    }
}

impl From<&str> for Failure {
    fn from(message: &str) -> Failure {
        Failure::illegal(message)
    }
}

/// An entry's expectation (and the arguments that are the same value) replaced by an equal one an earlier entry holds:
/// each matching or not-matching entry carries the expectation as it was then, which stays the same from request to
/// request until its remaining times or its definition change, and was ~2.4 KB of the log per request.
/// The earlier entries are remembered per thread, by expectation id, up to [`SHARED_EXPECTATIONS`] of them.
fn share_expectation(entry: &mut LogEntry) {
    use std::cell::RefCell;
    use std::collections::HashMap;
    use crate::log_entry::Json;
    thread_local! {
        static SEEN: RefCell<HashMap<String, Json>> = RefCell::new(HashMap::new());
    }
    let Some(expectation) = entry.expectation.clone() else { return };
    let Some(id) = expectation.get("id").and_then(Value::as_str) else { return };
    let earlier = SEEN.with(|seen| {
        let mut seen = seen.borrow_mut();
        match seen.get(id) {
            Some(earlier) if crate::log_entry::Json::ptr_eq(earlier, &expectation) => None,
            Some(earlier) if **earlier == *expectation => Some(earlier.clone()),
            _ => {
                if seen.len() >= SHARED_EXPECTATIONS {
                    seen.clear();
                }
                seen.insert(id.to_string(), expectation.clone());
                None
            }
        }
    });
    let Some(earlier) = earlier else { return };
    for argument in entry.arguments.iter_mut().flatten() {
        if crate::log_entry::Json::ptr_eq(argument, &expectation) {
            *argument = earlier.clone();
        }
    }
    entry.expectation = Some(earlier);
}

/// How many expectations [`share_expectation`] remembers on each thread.
const SHARED_EXPECTATIONS: usize = 256;

/// A request as log lines show it, built once for all of its entries: [`logged`] and its text in a
/// message ([`log_value`]).
#[derive(Clone)]
pub struct LoggedRequest {
    /// Shared by every entry that attaches the request or takes it as an argument.
    pub json: crate::log_entry::Json,
    /// The request the JSON is rendered from, which an entry may hold instead of a copy.
    pub request: Arc<HttpRequest>,
}

impl LoggedRequest {
    /// Rendered when an entry first needs it: the request is kept, not its JSON.
    pub fn of(request: &HttpRequest) -> LoggedRequest {
        LoggedRequest::shared(Arc::new(request.clone()))
    }

    /// [`LoggedRequest::of`] a request held already.
    pub fn shared(request: Arc<HttpRequest>) -> LoggedRequest {
        // `CredentialRedaction.forLog` reads only a control-plane request (its JSON `path`, or a preflight's): any
        // other is attached to an entry without rendering it to look
        let path = request.path.as_str();
        let credential_free = !crate::cors_origin::is_control_plane_route(Some(&request.method), path) && !crate::cors_origin::is_control_plane_path_candidate(path);
        LoggedRequest { json: crate::log_entry::Json::logged_request(request.clone(), credential_free), request }
    }

    /// The request as a message argument: what `Arg::from(logged(request))` gives, without rendering it again.
    pub fn arg(&self) -> Arg {
        Arg { json: self.json.clone(), object: None, shape: crate::log_entry::ArgText::Json }
    }
}

/// A received entry's correlation id: its own, or its request's.
fn received_id<'a>(request: &'a HttpRequest, id: &'a Option<String>) -> &'a str {
    id.as_deref().unwrap_or(&request.log_correlation_id)
}

/// The `received request` log line of a request already in its logged JSON form.
fn received_text_of(logged: &Value) -> String {
    crate::matcher::format_log_message(0, "received request:{}", &[&log_value(logged)])
}

/// [`received_text_of`] appended to `out`, the request rendered into `scratch` on the way (from the request itself
/// while nothing has rendered its JSON).
fn received_text_into(out: &mut String, scratch: &mut String, logged: &crate::log_entry::Json) {
    crate::matcher::format_log_message_into(out, 0, "received request:{}", 1, |_, write| {
        scratch.clear();
        logged.write_text(scratch);
        write(scratch);
    });
}

/// A received request as its `RECEIVED_REQUEST` log entry prints it: the ordered form, a JSON body as its bare
/// value (the decoded body carries no content type of its own).
/// A request as log lines print it (`received request`, `request … didn't match`, …): the ordered form with the
/// body as its bare value — JSON as JSON, text as a string, binary as its base64.
pub fn logged(request: &HttpRequest) -> Value {
    let mut logged = bare_body(ordered(request));
    // The log's request printer leaves out the wire bytes of a decoded body (oracle, scenario request_decoding_codings).
    if let Some(o) = logged.as_object_mut() {
        o.remove("originalBody");
    }
    logged
}

/// A forwarded response (as `REQUEST_RESPONSES` shows it) as log lines print it: its body bare, as [`logged`] does.
pub fn logged_response(response: &Value) -> Value {
    bare_body(response.clone())
}

/// A log entry's request (`httpRequest`/`httpRequests` of `LOG_ENTRIES`) as `LogEntry.updateBody` leaves it: a JSON
/// body as its parsed value, a parameter, string, XML or binary body as its `toString` (form-encoded, the text, the
/// base64), any other body (regex, XPath, schemas, …) as it is.
pub fn log_entry_request(request: &Value) -> Value {
    let mut out = request.clone();
    let Some(Value::Object(body)) = out.get("body") else { return out };
    let bare = match body.get("type").and_then(Value::as_str) {
        Some("JSON") => match body.get("json") {
            Some(Value::String(s)) => serde_json::from_str::<Value>(s).unwrap_or_else(|_| Value::String(s.clone())),
            Some(json) => json.clone(),
            None => return out,
        },
        Some("PARAMETERS" | "STRING" | "XML" | "BINARY") => Value::String(crate::matcher::body_to_string(&Value::Object(body.clone()))),
        _ => return out,
    };
    out["body"] = bare;
    out
}

/// A request or response JSON with its body bare, as the model's serialiser writes it in log entries.
pub fn with_bare_body(v: &Value) -> Value {
    bare_body(v.clone())
}

fn bare_body(mut logged: Value) -> Value {
    if let Some(body) = logged.get_mut("body") {
        *body = bare(std::mem::take(body));
    }
    logged
}

/// A body as [`bare_body`] leaves it: a typed JSON, XML, string or binary body as its payload, any other as it is.
fn bare(body: Value) -> Value {
    let field = match body.get("type").and_then(Value::as_str) {
        Some("JSON") => "json",
        Some("XML") => "xml",
        Some("STRING") => "string",
        Some("BINARY") => "base64Bytes",
        _ => return body,
    };
    match body {
        Value::Object(mut o) if o.contains_key(field) => o.swap_remove(field).unwrap_or_default(),
        other => other,
    }
}

/// [`log_value`] of [`logged`]`(request)`, appended to `out` straight from the request: the text a log line quoting the
/// request prints, without building the request's JSON. Only a body, path parameters, and headers, query parameters or
/// cookies with a name that is blank or starts with a marker are built as [`logged`] builds them.
pub fn logged_text_into(out: &mut String, request: &HttpRequest) {
    crate::json::pretty_into(out, &LoggedView(request));
}

/// [`logged`] as `serde` writes it, field by field from the request.
struct LoggedView<'a>(&'a HttpRequest);

impl serde::Serialize for LoggedView<'_> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let request = self.0;
        // the fields of `ordered_with` in its order, the body bare and no `originalBody`
        let mut o = s.serialize_map(None)?;
        o.serialize_entry("method", &request.method)?;
        if !request.path.is_empty() {
            o.serialize_entry("path", &request.path)?;
        }
        if !request.path_parameters.is_empty() {
            o.serialize_entry("pathParameters", &path_parameters_value(&request.path_parameters))?;
        }
        if !request.query.is_empty() {
            o.serialize_entry("queryStringParameters", &LiteralMap(&request.query))?;
        }
        if !request.headers.is_empty() {
            o.serialize_entry("headers", &LiteralMap(&request.headers))?;
        }
        if !request.cookies.is_empty() {
            o.serialize_entry("cookies", &LiteralCookies(&request.cookies))?;
        }
        let untransported = request.protocol.is_empty();
        if request.transport() != crate::request::Protocol::Http3 && !(untransported && !request.keep_alive) {
            o.serialize_entry("keepAlive", &request.keep_alive)?;
        }
        if !(untransported && !request.secure) {
            o.serialize_entry("secure", &request.secure)?;
        }
        if !request.client_certificates.is_empty() {
            o.serialize_entry("clientCertificateChain", &Certificates(&request.client_certificates))?;
        }
        if let Some((host, port, secure)) = &request.socket_address {
            o.serialize_entry("socketAddress", &SocketAddress(host, *port, *secure))?;
        }
        if !request.protocol.is_empty() {
            o.serialize_entry("protocol", request.protocol)?;
        }
        if !request.local_address.is_empty() {
            o.serialize_entry("localAddress", &request.local_address)?;
        }
        if !request.remote_address.is_empty() {
            o.serialize_entry("remoteAddress", &request.remote_address)?;
        }
        if let Some(body) = request_body_json(request, BodyForm::Ordered) {
            o.serialize_entry("body", &bare(body))?;
        }
        o.end()
    }
}

/// A name [`literal`] does not write as itself: blank (written `""`), or starting with a marker (the object form).
fn literal_name_rewritten(name: &str) -> bool {
    name.starts_with(['!', '?']) || name.trim().is_empty()
}

/// [`literal_json`] as `serde` writes it.
struct LiteralValue<'a>(&'a str);

impl serde::Serialize for LiteralValue<'_> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let value = self.0;
        if value.trim().is_empty() {
            return s.serialize_str("");
        }
        if !value.starts_with(['!', '?']) {
            return s.serialize_str(value);
        }
        let mut o = s.serialize_map(Some(2))?;
        o.serialize_entry("not", &false)?;
        o.serialize_entry("value", value)?;
        o.end()
    }
}

/// [`literal_map_value`] as `serde` writes it.
struct LiteralMap<'a>(&'a MultiMap);

impl serde::Serialize for LiteralMap<'_> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let map = self.0;
        if map.iter().any(|(name, _)| literal_name_rewritten(name)) {
            return serde::Serialize::serialize(&literal_map_value(map), s);
        }
        // the names in descending order (`NottableString.compareTo`, UTF-16 units) by a stable sort, which keeps a
        // repeated name's entries together and in their order: written as one name with all their values
        let mut small = [0u32; 64];
        let mut large = Vec::new();
        let order: &mut [u32] = if map.len() <= small.len() {
            &mut small[..map.len()]
        } else {
            large.resize(map.len(), 0);
            &mut large
        };
        for (i, at) in order.iter_mut().enumerate() {
            *at = i as u32;
        }
        let name = |i: u32| map[i as usize].0.as_str();
        order.sort_by(|&a, &b| name(b).encode_utf16().cmp(name(a).encode_utf16()));
        let mut o = s.serialize_map(None)?;
        let mut from = 0;
        while from < order.len() {
            let first = name(order[from]);
            let to = from + 1 + order[from + 1..].iter().take_while(|&&i| name(i) == first).count();
            o.serialize_entry(first, &LiteralValues(map, &order[from..to]))?;
            from = to;
        }
        o.end()
    }
}

/// The values of the entries of a multimap at these indices, one list, each [`LiteralValue`].
struct LiteralValues<'a>(&'a MultiMap, &'a [u32]);

impl serde::Serialize for LiteralValues<'_> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut seq = s.serialize_seq(None)?;
        for &i in self.1 {
            for value in &self.0[i as usize].1 {
                seq.serialize_element(&LiteralValue(value))?;
            }
        }
        seq.end()
    }
}

/// [`literal_cookies_value`] as `serde` writes it.
struct LiteralCookies<'a>(&'a [(String, String)]);

impl serde::Serialize for LiteralCookies<'_> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let cookies = self.0;
        if cookies.iter().any(|(name, _)| literal_name_rewritten(name)) {
            return serde::Serialize::serialize(&literal_cookies_value(cookies), s);
        }
        let mut o = s.serialize_map(None)?;
        for (i, (name, _)) in cookies.iter().enumerate() {
            // a repeated name keeps its first position and its last value
            if cookies[..i].iter().any(|(earlier, _)| earlier == name) {
                continue;
            }
            let last = cookies[i..].iter().rev().find(|(later, _)| later == name).map_or("", |(_, value)| value.as_str());
            o.serialize_entry(name, &LiteralValue(last))?;
        }
        o.end()
    }
}

/// `clientCertificateChain` as [`ordered_with`] writes it.
struct Certificates<'a>(&'a [crate::tls::client_cert::ClientCertificate]);

impl serde::Serialize for Certificates<'_> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_seq(self.0.iter().map(|c| &c.model))
    }
}

/// `socketAddress` as [`ordered_with`] writes it.
struct SocketAddress<'a>(&'a str, u16, bool);

impl serde::Serialize for SocketAddress<'_> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut o = s.serialize_map(Some(3))?;
        o.serialize_entry("host", self.0)?;
        o.serialize_entry("port", &self.1)?;
        o.serialize_entry("scheme", if self.2 { "HTTPS" } else { "HTTP" })?;
        o.end()
    }
}

/// A request as its model's `toString` prints it (verification failures in the log): the ordered form with the
/// body as the body serializers write it — without `rawBytes`, default content types left out.
pub fn model_form(request: &HttpRequest) -> Value {
    model_json(ordered(request))
}

/// A recorded expectation as `RecordedExpectationFileSystemPersistence` writes it (`ExpectationDTO` through the
/// plain object writer): the request's and the response's bodies in their model form, without `rawBytes`.
pub fn persisted_expectation(recorded: &Value) -> Value {
    let mut out = recorded.clone();
    if let Some(o) = out.as_object_mut() {
        for key in ["httpRequest", "httpResponse"] {
            if let Some(v) = o.get(key).cloned() {
                let typed = matches!(v.pointer("/body/type").and_then(Value::as_str), Some("XML" | "BINARY"))
                    || (v.pointer("/body/type").and_then(Value::as_str) == Some("STRING") && v.pointer("/body/contentType").is_some());
                o.insert(key.into(), if typed { persisted_body(v) } else { model_json(v) });
            }
        }
    }
    out
}

/// The DTO serialisers' field order for the body kinds [`model_json`] leaves in typed form: `STRING` and `XML` carry
/// `rawBytes` before `contentType`, `BINARY` has `contentType` last and no `rawBytes`.
fn persisted_body(mut message: Value) -> Value {
    let Some(Value::Object(body)) = message.get("body").cloned() else { return message };
    let get = |k: &str| body.get(k).cloned();
    let mut o = Map::new();
    match body.get("type").and_then(Value::as_str) {
        Some(kind @ ("STRING" | "XML")) => {
            let payload = if kind == "XML" { "xml" } else { "string" };
            o.insert("type".into(), kind.into());
            o.insert(payload.into(), get(payload).unwrap_or(Value::Null));
            if let Some(raw) = get("rawBytes") {
                o.insert("rawBytes".into(), raw);
            }
            if let Some(ct) = get("contentType") {
                o.insert("contentType".into(), ct);
            }
        }
        Some("BINARY") => {
            o.insert("type".into(), "BINARY".into());
            o.insert("base64Bytes".into(), get("base64Bytes").unwrap_or(Value::Null));
            if let Some(ct) = get("contentType") {
                o.insert("contentType".into(), ct);
            }
        }
        _ => return message,
    }
    message["body"] = Value::Object(o);
    message
}

/// [`model_form`] of a request already in JSON form (a recorded expectation's).
pub fn model_json(mut out: Value) -> Value {
    let Some(Value::Object(body)) = out.get("body").cloned() else { return out };
    let get = |k: &str| body.get(k).cloned();
    let mut o = Map::new();
    match body.get("type").and_then(Value::as_str) {
        Some("JSON") if !body.contains_key("contentType") => {
            out["body"] = get("json").unwrap_or(Value::Null);
            return out;
        }
        Some("STRING") if !body.contains_key("contentType") => {
            out["body"] = get("string").unwrap_or(Value::Null);
            return out;
        }
        Some("STRING") => {
            o.insert("type".into(), "STRING".into());
            o.insert("string".into(), get("string").unwrap_or(Value::Null));
            o.insert("contentType".into(), get("contentType").unwrap_or(Value::Null));
        }
        Some(kind @ ("JSON" | "XML" | "BINARY")) => {
            let payload = match kind {
                "JSON" => "json",
                "XML" => "xml",
                _ => "base64Bytes",
            };
            if let Some(ct) = get("contentType") {
                o.insert("contentType".into(), ct);
            }
            o.insert("type".into(), kind.into());
            o.insert(payload.into(), get(payload).unwrap_or(Value::Null));
        }
        _ => return out,
    }
    out["body"] = Value::Object(o);
    out
}

/// `dashboard`: the argument stays the whole request, as `DashboardLogEntryDTO` reads `LogEntry.getArguments()`.
fn received_log_entry(
    request: &HttpRequest,
    timestamp: &DateTime<Local>,
    correlation_id: &str,
    whole: Option<&Value>,
    fields: Option<&[String]>,
    dashboard: bool,
) -> Value {
    let retained = logged(request);
    // A request `maxLoggedBodyBytes` cut: the line and `arguments` show it whole, `httpRequest` as retained.
    let logged = whole.cloned().unwrap_or_else(|| retained.clone());
    // `redactSecretsInLog`: the message and `arguments` too, not only `httpRequest` (upstream cc7d7d185)
    let logged = match fields {
        Some(fields) => redact_value(&logged, fields, true),
        None => logged,
    };
    // `LOG_ENTRIES` quotes the entry's own request in its compact form (`getSerializedArguments`).
    let compact = crate::log_entry::compact_request_json(&logged);
    let message = crate::matcher::format_log_message(0, "received request:{}", &[&compact]);
    let logged = if dashboard { logged } else { Value::String(compact) };
    // `message.replaceAll(" {2}", "   ").split(NEW_LINE)`, trailing empty lines dropped.
    let mut lines: Vec<Value> = message.replace("  ", "   ").split('\n').map(|l| Value::String(l.to_string())).collect();
    while lines.len() > 1 && lines.last().is_some_and(|l| l.as_str() == Some("")) {
        lines.pop();
    }
    let port: Option<u16> = request.local_address.rsplit_once(':').and_then(|(_, p)| p.parse().ok());
    let mut o = Map::new();
    o.insert("logLevel".into(), "INFO".into());
    o.insert("epochTime".into(), timestamp.timestamp_millis().into());
    o.insert("timestamp".into(), timestamp.format("%Y-%m-%d %H:%M:%S%.3f").to_string().into());
    o.insert("type".into(), "RECEIVED_REQUEST".into());
    o.insert("correlationId".into(), correlation_id.into());
    if let Some(port) = port {
        o.insert("port".into(), port.into());
    }
    o.insert("httpRequest".into(), retained);
    o.insert("messageFormat".into(), "received request:{}".into());
    o.insert("message".into(), Value::Array(lines));
    o.insert("arguments".into(), Value::Array(vec![logged]));
    if dashboard {
        // the argument is the entry's own request (`LogEntry.argumentOwnMessagePart`)
        o.insert("$ownParts".into(), json!(["request"]));
    }
    Value::Object(o)
}

/// A log argument as upstream's `toString` prints it: strings as they are, JSON pretty-printed.
pub fn log_value(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => crate::json::pretty(other),
    }
}

/// [`log_value`] appended to `out`.
pub fn log_value_into(out: &mut String, v: &Value) {
    match v {
        Value::String(s) => out.push_str(s),
        other => crate::json::pretty_into(out, other),
    }
}

/// `(table index, insertion index)` order of `java.util.HashMap<String, _>` iteration, for a map filled one
/// `put` at a time.
pub fn java_hashmap_order(keys: &[String]) -> Vec<usize> {
    let mut capacity = 16usize;
    while keys.len() as f64 > capacity as f64 * 0.75 {
        capacity *= 2;
    }
    hashmap_order(keys, capacity)
}

/// The same for a map filled by `merge` (or `compute`), which puts a new key at the head of its bin: within a bin,
/// the latest key comes first.
pub fn java_hashmap_merge_order(keys: &[String]) -> Vec<usize> {
    let mut capacity = 16usize;
    while keys.len() as f64 > capacity as f64 * 0.75 {
        capacity *= 2;
    }
    let mut order = hashmap_order(keys, capacity);
    let mut start = 0;
    while start < order.len() {
        let bin = java_bucket(&keys[order[start]], capacity);
        let end = (start..order.len()).find(|&i| java_bucket(&keys[order[i]], capacity) != bin).unwrap_or(order.len());
        order[start..end].reverse();
        start = end;
    }
    order
}

/// A `ConcurrentHashMap`'s iteration order for keys inserted in this order: bins of a table of 16 that doubles
/// once the count reaches three quarters of it, each bin in insertion order.
pub fn java_concurrent_hashmap_order(keys: &[String]) -> Vec<usize> {
    let mut capacity = 16usize;
    while keys.len() as f64 >= capacity as f64 * 0.75 {
        capacity *= 2;
    }
    hashmap_order(keys, capacity)
}

/// `new HashMap<>(map)` followed by one `put` of the last key: the copy sizes its table for the copied entries
/// (Java 21's `putMapEntries` takes `tableSizeFor(ceil(n / 0.75))`; 16 when there are none), the `put` doubles it
/// when it passes the threshold.
pub fn java_hashmap_copy_then_put_order(keys: &[String]) -> Vec<usize> {
    let copied = keys.len().saturating_sub(1);
    let mut capacity = if copied == 0 { 16 } else { ((copied as f64 / 0.75).ceil() as usize).max(1).next_power_of_two() };
    while keys.len() as f64 > capacity as f64 * 0.75 {
        capacity *= 2;
    }
    hashmap_order(keys, capacity)
}

/// `HashMap.hash(key) & (capacity - 1)` for a `String` key.
fn java_bucket(k: &str, capacity: usize) -> usize {
    let mut h: i32 = 0;
    for unit in k.encode_utf16() {
        h = h.wrapping_mul(31).wrapping_add(unit as i32);
    }
    let h = h ^ ((h as u32) >> 16) as i32;
    (h as u32 as usize) & (capacity - 1)
}

fn hashmap_order(keys: &[String], capacity: usize) -> Vec<usize> {
    let mut order: Vec<usize> = (0..keys.len()).collect();
    order.sort_by_key(|i| java_bucket(&keys[*i], capacity));
    order
}

pub fn map_value(map: &MultiMap, hash_order: bool) -> Value {
    let mut out = Map::new();
    if hash_order {
        let keys: Vec<String> = map.iter().map(|(k, _)| k.clone()).collect();
        for i in java_hashmap_order(&keys) {
            out.insert(map[i].0.clone(), json!(map[i].1));
        }
        Value::Object(out)
    } else {
        for (k, vs) in map {
            out.insert(k.clone(), json!(vs));
        }
        canonical::multi_map(&Value::Object(out))
    }
}

/// Cookies as the flat request JSON prints them: in `java.util.HashMap` iteration order, like its headers.
fn cookies_in_hashmap_order(cookies: &[(String, String)]) -> Value {
    let keys: Vec<String> = cookies.iter().map(|(k, _)| k.clone()).collect();
    let mut out = Map::new();
    // `NON_EMPTY` is the mapper's content inclusion too, so a cookie with an empty value is left out of the map
    for i in java_hashmap_order(&keys).into_iter().filter(|&i| !cookies[i].1.is_empty()) {
        out.insert(cookies[i].0.clone(), Value::String(cookies[i].1.clone()));
    }
    Value::Object(out)
}

/// A name or value of a real HTTP message as `NottableString`'s serialiser writes it: literal, so one whose own first
/// character is a marker (`!` negation, `?` optional) takes the object form (`{"not": false, "value": "!foo"}`)
/// rather than being read back as a matcher (upstream builds them with `string(value, false)`).
fn literal(s: &str) -> crate::model::NString {
    crate::model::NString { value: Some(s.to_string()), ..Default::default() }
}

/// [`literal`] as JSON: the plain string, or the object form for one a reader would take for a matcher.
pub fn literal_json(s: &str) -> Value {
    literal(s).to_json()
}

/// The headers or query parameters of a real HTTP message as `KeysToMultiValuesSerializer` writes them: map form in
/// descending name order, or the list form when a name starts with a marker; names and values literal.
pub fn literal_map_value(map: &MultiMap) -> Value {
    let mut entries = crate::model::Entries::new();
    for (k, vs) in map {
        let values = vs.iter().map(|v| Some(literal(v)));
        match entries.iter_mut().find(|(n, _)| n.value.as_deref() == Some(k.as_str())) {
            Some((_, existing)) => existing.extend(values),
            None => entries.push((literal(k), values.collect())),
        }
    }
    crate::model::multi_values_json(&entries, None)
}

/// The cookies of a real HTTP message as `CookiesSerializer` writes them, names and values literal.
pub fn literal_cookies_value(cookies: &[(String, String)]) -> Value {
    let mut entries = crate::model::Entries::new();
    for (k, v) in cookies {
        // `KeysAndValues`: a repeated name keeps its first position and its last value.
        match entries.iter_mut().find(|(n, _)| n.value.as_deref() == Some(k.as_str())) {
            Some((_, existing)) => *existing = vec![Some(literal(v))],
            None => entries.push((literal(k), vec![Some(literal(v))])),
        }
    }
    crate::model::key_values_json(&entries)
}

/// A multimap of a real HTTP message in list form (`[{"name", "values"}]`), names and values [`literal_json`].
pub fn literal_list_form(map: &MultiMap) -> Value {
    Value::Array(map.iter().map(|(k, vs)| json!({"name": literal_json(k), "values": vs.iter().map(|v| literal_json(v)).collect::<Vec<_>>()})).collect())
}

fn cookies_value(cookies: &[(String, String)]) -> Value {
    literal_cookies_value(cookies)
}

/// Which of MockServer's body renderings to produce.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum BodyForm {
    /// `retrieve?type=REQUESTS`, verification messages: typed bodies with `rawBytes` (JSON only when not compact).
    Flat,
    /// `REQUEST_RESPONSES`, logs: untyped text without `Content-Type`, JSON without `rawBytes`.
    Ordered,
    /// Recorded expectations: always typed, always `rawBytes`.
    Recorded,
}

/// `JsonBody.DEFAULT_JSON_CONTENT_TYPE` (`application/json; charset=utf-8`) in any spelling: upstream's serialiser
/// leaves it out of a JSON body.
fn is_default_json_content_type(ct: &str) -> bool {
    is_default_content_type(ct, "application/json")
}

/// `media` with `charset=utf-8` and nothing else, in any spelling.
fn is_default_content_type(ct: &str, media: &str) -> bool {
    let mut parts = ct.split(';').map(str::trim);
    let base = parts.next().unwrap_or_default();
    let params: Vec<&str> = parts.filter(|p| !p.is_empty()).collect();
    base.eq_ignore_ascii_case(media)
        && matches!(params.as_slice(), [p] if p.split_once('=').is_some_and(|(k, v)| {
            k.trim().eq_ignore_ascii_case("charset") && v.trim().trim_matches('"').eq_ignore_ascii_case("utf-8")
        }))
}

/// The body as MockServer's decoder classifies it by `Content-Type`.
pub fn body_json(body: &[u8], content_type: Option<&str>, form: BodyForm) -> Option<Value> {
    if body.is_empty() {
        return None;
    }
    let raw = || Value::String(B64.encode(body));
    // The body's media type is written as `MediaType.parse(header).toString()`.
    let content_type = content_type.map(crate::media_type::normalise);
    let content_type = content_type.as_deref();
    // A `Content-Type` of a binary media type makes a binary body, whatever the bytes are.
    let binary_type = content_type.is_some_and(|ct| !crate::media_type::MediaType::parse(Some(ct)).is_string());
    // Text in the charset the header names (UTF-16 bodies are text too) or defaults to (ISO-8859-1 for string types
    // other than JSON and XML), else it must be UTF-8.
    let media = crate::media_type::MediaType::parse(content_type);
    if content_type.is_some() && media.is_json() {
        return Some(json_body(body, content_type.unwrap_or_default(), &media, form));
    }
    let decoded = match media.charset() {
        Some(_) => Some(crate::media_type::text_with_named_charset(body, content_type)),
        None => media.charset_or_default().filter(|c| *c == "iso-8859-1").map(|c| crate::media_type::decode(body, Some(c))),
    };
    // `bytesToBody` decodes an XML body leniently in its charset (U+FFFD for bytes that are not UTF-8).
    let decoded = decoded.or_else(|| (content_type.is_some() && media.is_xml()).then(|| crate::media_type::decode(body, media.charset_or_default())));
    let text = match &decoded {
        Some(t) => Some(t.as_str()),
        None => std::str::from_utf8(body).ok(),
    }
    .filter(|_| !binary_type);
    match (content_type, text) {
        (Some(ct), Some(text)) if media.is_xml() => {
            let mut o = Map::new();
            o.insert("type".into(), "XML".into());
            o.insert("xml".into(), text.into());
            o.insert("rawBytes".into(), raw());
            // `XmlBody.DEFAULT_XML_CONTENT_TYPE` is left out.
            if !is_default_content_type(ct, "application/xml") {
                o.insert("contentType".into(), ct.into());
            }
            Some(Value::Object(o))
        }
        // `StringBody` keeps a blank value as "".
        (Some(ct), Some(text)) => Some(json!({"type": "STRING", "string": string_body(text), "rawBytes": raw(), "contentType": ct})),
        (None, Some(text)) if form == BodyForm::Recorded => Some(json!({"type": "STRING", "string": string_body(text), "rawBytes": raw()})),
        (None, Some(text)) => Some(Value::String(string_body(text).to_string())),
        (ct, None) => {
            let mut o = Map::new();
            o.insert("type".into(), "BINARY".into());
            o.insert("base64Bytes".into(), raw());
            if let Some(ct) = ct {
                o.insert("contentType".into(), ct.into());
            }
            Some(Value::Object(o))
        }
    }
}

/// `bytesToBody`'s `JsonBody` for a JSON media type: the bytes decoded leniently in the charset (U+FFFD for bytes
/// that are not UTF-8) and read the way `JsonBodyDTOSerializer` reads them (Jackson's `readTree`, which stops after the
/// first value). A value node is written raw, as the whole text. A text Jackson cannot read is kept as a string; the
/// retrieval paths refuse it first ([`unwritable_json_body`]) and the log's printers show it as its text.
fn json_body(body: &[u8], ct: &str, media: &crate::media_type::MediaType, form: BodyForm) -> Value {
    let text = crate::media_type::decode(body, media.charset_or_default());
    // A blank `JsonBody` is written with `"json" : null`.
    let blank = crate::media_type::is_blank(&text);
    let parsed = if blank { None } else { crate::json::parse_lenient(text.as_bytes()).ok() };
    // `rawBytes` is only kept, on the request-retrieval path, when the bytes are not simply the compact rendering of
    // the JSON (`OBJECT_MAPPER.writeValueAsBytes(jsonNode)`).
    let compact = parsed.as_ref().is_some_and(|v| crate::json::compact(v).as_bytes() == body);
    let json = match parsed {
        Some(v) => {
            let v = crate::model::big_decimal_tree(&v);
            if v.is_array() || v.is_object() || crate::json::compact(&v) == text { v } else { crate::model::number(&text) }
        }
        None if blank => Value::Null,
        None => Value::String(text),
    };
    // `JsonBodyDTOSerializer`: a body with only default values (the default content type, and no `rawBytes`) is
    // written as the bare JSON (forward_json_response_logged).
    if is_default_json_content_type(ct) && (form == BodyForm::Ordered || form == BodyForm::Flat && compact) {
        return json;
    }
    let mut o = Map::new();
    if !is_default_json_content_type(ct) {
        o.insert("contentType".into(), ct.into());
    }
    o.insert("type".into(), "JSON".into());
    o.insert("json".into(), json);
    if form == BodyForm::Flat && !compact {
        o.insert("rawBytes".into(), Value::String(B64.encode(body)));
    }
    Value::Object(o)
}

/// A body `JsonBodyDTOSerializer` cannot write: JSON-typed, not blank, and not JSON once decoded (Jackson's
/// `JsonParseException`), which fails every JSON rendering of the request or response that carries it.
pub fn unwritable_json_body(body: &[u8], content_type: Option<&str>) -> bool {
    let Some(ct) = content_type.filter(|_| !body.is_empty()) else { return false };
    let media = crate::media_type::MediaType::parse(Some(&crate::media_type::normalise(ct)));
    if !media.is_json() {
        return false;
    }
    let text = crate::media_type::decode(body, media.charset_or_default());
    !crate::media_type::is_blank(&text) && crate::json::parse_lenient(text.as_bytes()).is_err()
}

/// [`unwritable_json_body`] of a recorded request (a body cut at `maxLoggedBodyBytes` is binary, so writable).
pub fn unwritable_request(request: &HttpRequest) -> bool {
    !(request.body_kind == BodyKind::Binary && !request.body.is_empty()) && unwritable_json_body(&request.body, request.body_content_type())
}

/// `SerializationFailure.describe`: how many values were written and the index of the one that failed.
pub fn serialization_failure_description(count: usize, index: usize) -> String {
    format!("{count} value{}, failed at index {index}", if count == 1 { "" } else { "s" })
}

/// [`serialization_failure_description`] with `LogEntrySerializer.identify`: the failing entry's `type` and
/// `correlationId` (`describe(values, e, LogEntrySerializer::identify)`), neither rendered.
pub fn log_entry_failure_description(count: usize, index: usize, entry: &Value) -> String {
    let field = |name: &str| entry.get(name).and_then(Value::as_str).map_or("null".to_string(), str::to_string);
    format!("{} (type {}, correlationId {})", serialization_failure_description(count, index), field("type"), field("correlationId"))
}

/// Whether Jackson cannot write a log entry's JSON (`LogEntrySerializer`): its `throwable` has a JSSE PKIX path
/// building failure in its cause chain (an untrusted server certificate: `ValidatorException`'s
/// `SunCertPathBuilderException`). The bean getters of those `sun.security` classes (`getAdjacencyList`, `getCert`) are
/// in packages `java.base` does not export, so serialising the throwable throws; a TLS failure of
/// another kind (a peer that is no TLS server, a closed handshake) writes fine.
pub fn unwritable_log_entry(entry: &Value) -> bool {
    let mut at = entry.get("throwable");
    while let Some(throwable) = at {
        // The MQTT client's chain carries rustls' text for the same untrusted certificate (`UnknownIssuer`, or a CA
        // presented as the leaf): the JDK finds no path for both.
        let no_path = |m: &str| m.contains("PKIX path building failed") || m.contains("invalid peer certificate: UnknownIssuer") || m.contains("CaUsedAsEndEntity");
        // From a webhook's TLS failure under CUSTOM trust: path validation (`PKIX path validation failed`,
        // a CertPathValidatorException with `getCertPath`: an expired or non-CA intermediate, a bad signature) and an
        // extended key usage refusal (`ValidatorException`, `getCert`) fail Jackson too. A host name mismatch
        // (`HostnameChecker`, a plain CertificateException) writes.
        let invalid = |m: &str| m.contains("PKIX path validation failed") || m.contains("Extended key usage does not permit use for TLS");
        if throwable.get("message").and_then(Value::as_str).is_some_and(|m| no_path(m) || invalid(m)) {
            return true;
        }
        at = throwable.get("cause");
    }
    false
}

/// `StringBody`'s value: a blank text is kept as "" (`isNotBlank(value) ? value : ""`).
fn string_body(text: &str) -> &str {
    if crate::media_type::is_blank(text) { "" } else { text }
}

fn body_value(request: &HttpRequest, with_json_raw_bytes: bool) -> Option<Value> {
    let form = if with_json_raw_bytes { BodyForm::Flat } else { BodyForm::Ordered };
    request_body_json(request, form)
}

/// [`body_json`] of a request's body: one `maxLoggedBodyBytes` cut is a `BinaryBody` whatever its bytes say.
fn request_body_json(request: &HttpRequest, form: BodyForm) -> Option<Value> {
    if request.body_kind == BodyKind::Binary && !request.body.is_empty() {
        return Some(json!({"type": "BINARY", "base64Bytes": B64.encode(&request.body)}));
    }
    body_json(&request.body, request.body_content_type(), form)
}

/// A recorded request's body as an expectation holds it (`withBody(request.getBody())`), before the echo writes it:
/// typed, with its `rawBytes`.
pub(crate) fn expectation_body(request: &HttpRequest) -> Option<Value> {
    request_body_json(request, BodyForm::Recorded)
}

/// The flat form (`retrieve?type=REQUESTS`, verification messages): `HttpRequestPrettyPrintedDTO`, which has no
/// `clientCertificateChain`.
pub fn flat(request: &HttpRequest) -> Value {
    let mut o = Map::new();
    if let Some(body) = body_value(request, true) {
        o.insert("body".into(), body);
    }
    if request.cookies.iter().any(|(_, v)| !v.is_empty()) {
        o.insert("cookies".into(), cookies_in_hashmap_order(&request.cookies));
    }
    if !request.headers.is_empty() {
        o.insert("headers".into(), map_value(&request.headers, true));
    }
    // A request no transport built (a gRPC bidi stream's `synthesiseBidiRequest`) has no protocol, keep-alive or TLS
    // flag to print: all three are null upstream.
    let transported = !request.protocol.is_empty();
    if transported && request.transport() != crate::request::Protocol::Http3 {
        o.insert("keepAlive".into(), Value::Bool(request.keep_alive));
    }
    o.insert("method".into(), request.method.clone().into());
    if let Some(original) = &request.original_body {
        o.insert("originalBody".into(), Value::String(B64.encode(original)));
    }
    // an empty path (a request target `http://host`) is left out, as Jackson leaves out an empty string
    if !request.path.is_empty() {
        o.insert("path".into(), request.path.clone().into());
    }
    if transported {
        o.insert("protocol".into(), request.protocol.into());
    }
    if !request.query.is_empty() {
        o.insert("queryStringParameters".into(), map_value(&request.query, true));
    }
    if transported {
        o.insert("secure".into(), Value::Bool(request.secure));
    }
    Value::Object(o)
}

/// The ordered form (`retrieve?type=REQUEST_RESPONSES`, logs).
pub fn ordered(request: &HttpRequest) -> Value {
    ordered_with(request, BodyForm::Ordered)
}

pub fn ordered_with(request: &HttpRequest, form: BodyForm) -> Value {
    let mut o = Map::new();
    o.insert("method".into(), request.method.clone().into());
    // left out when empty, as in the flat form
    if !request.path.is_empty() {
        o.insert("path".into(), request.path.clone().into());
    }
    if !request.path_parameters.is_empty() {
        o.insert("pathParameters".into(), path_parameters_value(&request.path_parameters));
    }
    if !request.query.is_empty() {
        o.insert("queryStringParameters".into(), literal_map_value(&request.query));
    }
    if !request.headers.is_empty() {
        o.insert("headers".into(), literal_map_value(&request.headers));
    }
    if !request.cookies.is_empty() {
        o.insert("cookies".into(), cookies_value(&request.cookies));
    }
    // An HTTP/3 request has no keep-alive flag (`Http3RequestBridge.toHttpRequest` sets none); a request no transport
    // built (a gRPC bidi stream's `synthesiseBidiRequest`) has neither flag unless one was set.
    let untransported = request.protocol.is_empty();
    if request.transport() != crate::request::Protocol::Http3 && !(untransported && !request.keep_alive) {
        o.insert("keepAlive".into(), Value::Bool(request.keep_alive));
    }
    if !(untransported && !request.secure) {
        o.insert("secure".into(), Value::Bool(request.secure));
    }
    if !request.client_certificates.is_empty() {
        o.insert("clientCertificateChain".into(), Value::Array(request.client_certificates.iter().map(|c| c.model.clone()).collect()));
    }
    if let Some((host, port, secure)) = &request.socket_address {
        o.insert("socketAddress".into(), serde_json::json!({"host": host, "port": port, "scheme": if *secure { "HTTPS" } else { "HTTP" }}));
    }
    // A request without a protocol (built from a callback's answer) has none to print.
    if !request.protocol.is_empty() {
        o.insert("protocol".into(), request.protocol.into());
    }
    if !request.local_address.is_empty() {
        o.insert("localAddress".into(), request.local_address.clone().into());
    }
    if !request.remote_address.is_empty() {
        o.insert("remoteAddress".into(), request.remote_address.clone().into());
    }
    if let Some(body) = request_body_json(request, form) {
        o.insert("body".into(), body);
    }
    if let Some(original) = &request.original_body {
        o.insert("originalBody".into(), Value::String(B64.encode(original)));
    }
    Value::Object(o)
}

/// The ordered form with the path parameters the matched expectation extracted (`withPathParameters`), as an
/// object callback receives it.
pub fn ordered_with_path_parameters(request: &HttpRequest, parameters: &MultiMap) -> Value {
    if parameters.is_empty() || request.path_parameters == *parameters {
        return ordered(request);
    }
    let mut request = request.clone();
    request.path_parameters = parameters.clone();
    ordered(&request)
}

/// A request's `pathParameters` as its serialiser writes them: in descending name order.
fn path_parameters_value(parameters: &MultiMap) -> Value {
    let mut sorted = parameters.clone();
    sorted.sort_by(|(a, _), (b, _)| b.cmp(a));
    Value::Object(sorted.iter().map(|(k, vs)| (k.clone(), json!(vs))).collect())
}

pub fn exchange_json(x: &Exchange) -> Value {
    let mut o = Map::new();
    o.insert("httpRequest".into(), x.shown_request.clone().unwrap_or_else(|| ordered(&x.request)));
    if !x.response.is_null() {
        o.insert("httpResponse".into(), Value::clone(&x.response));
    }
    o.insert("timestamp".into(), x.timestamp.format("%Y-%m-%d %H:%M:%S%.3f").to_string().into());
    Value::Object(o)
}

/// A multimap in list form (`[{"name", "values"}]`), which keeps its order through the model.
pub fn list_form(map: &MultiMap) -> Value {
    Value::Array(map.iter().map(|(k, vs)| json!({"name": k, "values": vs})).collect())
}

/// A logged body in input form: the text as received, typed by `Content-Type` like [`body_json`].
pub fn input_body(body: &[u8], content_type: Option<&str>) -> Option<Value> {
    let typed = body_json(body, content_type, BodyForm::Recorded)?;
    let text = std::str::from_utf8(body).ok();
    Some(match (typed.get("type").and_then(Value::as_str), text) {
        (Some("JSON"), Some(text)) => json!({"type": "JSON", "json": text}),
        _ => typed,
    })
}

/// A recorded request in input form (headers, query and cookies in the order they arrived).
pub fn input_request(request: &HttpRequest) -> Value {
    let mut o = Map::new();
    o.insert("method".into(), request.method.clone().into());
    o.insert("path".into(), request.path.clone().into());
    if !request.query.is_empty() {
        o.insert("queryStringParameters".into(), literal_list_form(&request.query));
    }
    if !request.headers.is_empty() {
        o.insert("headers".into(), literal_list_form(&request.headers));
    }
    if !request.cookies.is_empty() {
        o.insert("cookies".into(), Value::Array(request.cookies.iter().map(|(k, v)| json!({"name": literal_json(k), "value": literal_json(v)})).collect()));
    }
    // An HTTP/3 request has no keep-alive flag (`Http3RequestBridge.toHttpRequest` sets none).
    if request.transport() != crate::request::Protocol::Http3 {
        o.insert("keepAlive".into(), Value::Bool(request.keep_alive));
    }
    o.insert("secure".into(), Value::Bool(request.secure));
    o.insert("protocol".into(), request.protocol.into());
    if let Some(body) = input_body(&request.body, request.first_header("content-type")) {
        o.insert("body".into(), body);
    }
    Value::Object(o)
}

thread_local! {
    /// The values [`interned`] lately on this thread, each with its weight as a response once weighed (0 before:
    /// [`response_weight`]).
    static RECENT: std::cell::RefCell<VecDeque<(Arc<Value>, std::cell::Cell<u64>)>> = const { std::cell::RefCell::new(VecDeque::new()) };
}

/// How many values [`RECENT`] holds.
const RECENT_VALUES: usize = 8;

/// `value`, or an equal one logged lately on this thread: a static response's logged form and its action are the same
/// from request to request, and each copy was ~1 KB of the event log per request.
pub fn interned(value: Value) -> Arc<Value> {
    let mut value = Some(value);
    let shared = RECENT.try_with(|recent| {
        let mut recent = recent.borrow_mut();
        let given = value.as_ref().expect("not yet taken");
        if let Some((found, _)) = recent.iter().find(|(v, _)| **v == *given) {
            return found.clone();
        }
        if recent.len() == RECENT_VALUES {
            recent.pop_front();
        }
        let shared = Arc::new(value.take().expect("not yet taken"));
        recent.push_back((shared.clone(), Default::default()));
        shared
    });
    // a thread on its way out shares nothing
    shared.unwrap_or_else(|_| Arc::new(value.take().unwrap_or_default()))
}

/// [`interned`] of a value already shared (an expectation's own response): itself when it is among the recent ones.
pub fn interned_shared(value: Arc<Value>) -> Arc<Value> {
    RECENT
        .try_with(|recent| {
            let mut recent = recent.borrow_mut();
            if let Some((found, _)) = recent.iter().find(|(v, _)| Arc::ptr_eq(v, &value) || **v == *value) {
                return found.clone();
            }
            if recent.len() == RECENT_VALUES {
                recent.pop_front();
            }
            recent.push_back((value.clone(), Default::default()));
            value.clone()
        })
        .unwrap_or(value)
}

/// The weight of `response` as an entry's response, kept beside it while it is among this thread's [`RECENT`] values:
/// an interned response is the same from request to request, and was weighed again for each.
fn response_weight(response: &Arc<Value>) -> u64 {
    RECENT
        .try_with(|recent| {
            let recent = recent.borrow();
            let (_, kept) = recent.iter().find(|(v, _)| Arc::ptr_eq(v, response))?;
            // a response weighs at least its overhead, so 0 is never a weight
            if kept.get() == 0 {
                kept.set(weight::response_json(response));
            }
            Some(kept.get())
        })
        .ok()
        .flatten()
        .unwrap_or_else(|| weight::response_json(response))
}

#[cfg(test)]
#[path = "recorded_tests.rs"]
mod concurrency_tests;
