//! The dashboard's push channel (`org.mockserver.dashboard`): `GET /_mockserver_ui_websocket` upgrades to a
//! WebSocket that pushes one JSON frame (`logMessages`, `activeExpectations`, `recordedRequests`,
//! `proxiedRequests`) whenever the event log or the expectations change, and answers a client's request matcher
//! (a text frame) with the same frame filtered by it, or `{"error": …}`.
//!
//! The model half (this file's first part) mirrors upstream's classes so the Java tests port one to one:
//! [`DashEntry`] is `DashboardLogEntryDTO`, [`entry_value`] / [`group_value`] are its two serializers,
//! [`DescriptionProcessor`] is `DescriptionProcessor` with its three `Description` kinds, and [`build_frame`] is
//! `DashboardWebSocketHandler.sendUpdate`. The live half reads the event log and the store (`frame_for`) and runs the
//! connection (`serve`).

use std::cell::Cell;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde_json::{Map, Value, json};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::Role;

use crate::request::HttpRequest;
use crate::state::State;

pub const PATH: &str = "/_mockserver_ui_websocket";

/// `UI_UPDATE_ITEM_LIMIT`: how many items each panel of a frame carries.
const ITEM_LIMIT: usize = 100;

/// `Description.MAX_LENGTH`
const MAX_DESCRIPTION_LENGTH: usize = 115;

// ---------------------------------------------------------------------------------------------------------------
// Java text helpers
// ---------------------------------------------------------------------------------------------------------------

/// `String.split(regex)` for a literal separator: trailing empty parts are dropped, and a string with no match
/// stays whole.
fn java_split(text: &str, separator: &str) -> Vec<String> {
    let mut parts: Vec<String> = text.split(separator).map(str::to_string).collect();
    if parts.len() == 1 {
        return parts;
    }
    while parts.last().is_some_and(String::is_empty) {
        parts.pop();
    }
    parts
}

/// `StringUtils.abbreviate(text, width)`.
fn abbreviate(text: &str, width: usize) -> String {
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= width {
        return text.to_string();
    }
    let keep = width.saturating_sub(3);
    format!("{}...", chars[..keep].iter().collect::<String>())
}

/// `StringUtils.repeat(" ", count)`: nothing for a count of zero or less.
fn spaces(count: isize) -> String {
    " ".repeat(count.max(0) as usize)
}

fn length(text: &str) -> usize {
    text.chars().count()
}

// ---------------------------------------------------------------------------------------------------------------
// Descriptions
// ---------------------------------------------------------------------------------------------------------------

/// `DescriptionProcessor`: remembers the longest description of each kind so every one is padded to line up with
/// the rest, whenever it is rendered (which is after all of them were created).
#[derive(Default)]
pub struct DescriptionProcessor {
    max_http_request: Cell<usize>,
    max_open_api: Cell<usize>,
    max_open_api_object: Cell<usize>,
    max_log_event: Cell<usize>,
}

/// What a description describes.
pub enum Described<'a> {
    /// A request definition as JSON (an `HttpRequest` or an `OpenAPIDefinition`).
    Definition(&'a Value),
    Log(&'a DashEntry),
}

/// `Description`: rendered by [`Description::to_value`] once the processor has seen every description.
pub enum Description {
    /// `RequestDefinitionDescription`: `first`, padding, `second`.
    Request { first: String, second: String, length: usize, open_api: bool, processor: Rc<DescriptionProcessor> },
    /// `RequestDefinitionObjectDescription`: an inline OpenAPI document and its operation.
    Object { first: String, object: Value, second: String, processor: Rc<DescriptionProcessor> },
    /// `LogMessageDescription`: the entry's time and type.
    Log { first: String, second: String, length: usize, processor: Rc<DescriptionProcessor> },
    /// `ReceivedRequestDescription`: a received request with no method or path (a DNS query or a binary message),
    /// its kind and a summary, which the dashboard lays out as an HTTP request's method and path (upstream #102).
    Received { kind: &'static str, summary: String },
}

impl Description {
    fn request(first: String, second: String, processor: &Rc<DescriptionProcessor>, open_api: bool) -> Description {
        let total = length(&first) + length(&second);
        let (shown_first, shown_second) = if total > MAX_DESCRIPTION_LENGTH {
            if length(&second) > length(&first) {
                let width = MAX_DESCRIPTION_LENGTH - length(&first);
                (first.clone(), abbreviate(&second, width))
            } else {
                let width = MAX_DESCRIPTION_LENGTH - length(&second);
                (abbreviate(&first, width), second.clone())
            }
        } else {
            (first.clone(), second.clone())
        };
        Description::Request { first: shown_first, second: shown_second, length: total, open_api, processor: processor.clone() }
    }

    /// `Description.length()`.
    pub fn length(&self) -> usize {
        match self {
            Description::Request { length, .. } | Description::Log { length, .. } => length + 1,
            Description::Object { first, second, .. } => self::length(first) + 8 + self::length(second) + 1,
            Description::Received { kind, summary } => self::length(kind) + self::length(summary) + 1,
        }
    }

    /// `Description.toObject()`: a string, or an object for an inline OpenAPI document.
    pub fn to_value(&self) -> Value {
        match self {
            Description::Request { first, second, length, open_api, processor } => {
                let max = if *open_api { processor.max_open_api.get() } else { processor.max_http_request.get() };
                Value::String(format!("{first}{}{second}", spaces(max as isize - *length as isize + 1)))
            }
            Description::Object { first, object, second, processor } => {
                let pad = spaces(processor.max_open_api_object.get() as isize - self.length() as isize + 1);
                json!({"json": true, "object": object, "first": first, "second": format!("{pad}{second}")})
            }
            Description::Log { first, second, length, processor } => {
                let pad = spaces(processor.max_log_event.get() as isize - *length as isize + 1);
                Value::String(format!("{first} {second}{pad} "))
            }
            Description::Received { kind, summary } => json!({"json": false, "first": kind, "second": summary}),
        }
    }
}

/// `NottableString.getValue()` of a JSON string or `{"not": …, "value": …}` field.
fn nottable_value(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => s.strip_prefix('!').unwrap_or(s).to_string(),
        Some(Value::Object(o)) => o.get("value").and_then(Value::as_str).unwrap_or_default().to_string(),
        _ => String::new(),
    }
}

impl DescriptionProcessor {
    pub fn new() -> Rc<DescriptionProcessor> {
        Rc::new(DescriptionProcessor::default())
    }

    pub fn max_http_request_length(&self) -> usize {
        self.max_http_request.get()
    }

    pub fn max_open_api_length(&self) -> usize {
        self.max_open_api.get()
    }

    pub fn max_open_api_object_length(&self) -> usize {
        self.max_open_api_object.get()
    }

    pub fn max_log_event_length(&self) -> usize {
        self.max_log_event.get()
    }

    /// `description(object)`.
    pub fn description(self: &Rc<Self>, object: Described<'_>) -> Option<Description> {
        self.description_with_id(object, None)
    }

    /// `description(object, id)`: `None` for anything that is neither a request, an OpenAPI definition nor a log
    /// entry.
    pub fn description_with_id(self: &Rc<Self>, object: Described<'_>, id: Option<&str>) -> Option<Description> {
        let id_message = id.filter(|i| !i.trim().is_empty()).map(|i| format!("{i}: ")).unwrap_or_default();
        match object {
            Described::Definition(definition) if definition.get("specUrlOrPayload").is_some() => {
                let operation_id = definition.get("operationId").and_then(Value::as_str).filter(|o| !o.trim().is_empty()).unwrap_or_default();
                let spec = crate::openapi::spec_text(&definition["specUrlOrPayload"]).unwrap_or_default();
                let spec = spec.trim();
                if crate::openapi::is_spec_url(spec) {
                    let name = spec.rsplit_once('/').map(|(_, n)| n).unwrap_or("");
                    let description = Description::request(format!("{id_message}{name}"), operation_id.to_string(), self, true);
                    self.max_open_api.set(self.max_open_api.get().max(description.length()));
                    Some(description)
                } else {
                    let object = sort_model(crate::openapi::load(spec).ok()?, None);
                    let description =
                        Description::Object { first: format!("{id_message}spec "), object, second: operation_id.to_string(), processor: self.clone() };
                    self.max_open_api_object.set(self.max_open_api_object.get().max(description.length()));
                    Some(description)
                }
            }
            Described::Definition(definition) if is_plain_request(definition) => {
                let method = nottable_value(definition.get("method"));
                let path = nottable_value(definition.get("path"));
                let description = Description::request(format!("{id_message}{method}"), path, self, false);
                self.max_http_request.set(self.max_http_request.get().max(description.length()));
                Some(description)
            }
            Described::Definition(_) => None,
            Described::Log(entry) => {
                let timestamp = entry.timestamp.as_deref().unwrap_or_default();
                // `StringUtils.substringAfter(timestamp, "-")`: nothing when there is no dash.
                let after = timestamp.split_once('-').map(|(_, rest)| rest).unwrap_or("");
                let first = format!("{id_message}{after}");
                let second = entry.kind.clone().unwrap_or_default();
                let total = length(&first) + length(&second);
                let description = Description::Log { first, second, length: total, processor: self.clone() };
                self.max_log_event.set(self.max_log_event.get().max(description.length()));
                Some(description)
            }
        }
    }
}

/// `DescriptionProcessor.BINARY_PREVIEW_BYTES`
const BINARY_PREVIEW_BYTES: usize = 16;

impl DescriptionProcessor {
    /// `receivedRequestDescription(request, binaryLength)`: as [`DescriptionProcessor::description`], also describing
    /// a DNS query by its name and record type, and a binary message by its length and first bytes in hex, or `bytes
    /// redacted` under `redactSecretsInLog` (the message itself is masked then). Neither widens the HTTP padding.
    pub fn received_request_description(self: &Rc<Self>, request: &Value, binary_length: Option<usize>, redact_secrets_in_log: bool) -> Option<Description> {
        if crate::canonical::is_dns_request(request) {
            let name = request.get("dnsName").and_then(Value::as_str).unwrap_or_default();
            let summary = match request.get("dnsType").and_then(Value::as_str) {
                Some(kind) => format!("{name} {kind}"),
                None => name.to_string(),
            };
            return Some(Description::received("DNS", &summary));
        }
        if crate::canonical::is_binary_request(request) {
            let summary = if redact_secrets_in_log {
                "bytes redacted".to_string()
            } else {
                use base64::Engine;
                let text = request.get("binaryData").and_then(Value::as_str).unwrap_or_default();
                let bytes = base64::engine::general_purpose::STANDARD.decode(text).unwrap_or_default();
                // the length received (`binaryLength`), not the length the cut shows
                let length = binary_length.unwrap_or(bytes.len());
                let shown = length.min(BINARY_PREVIEW_BYTES);
                if shown == 0 {
                    format!("{length} bytes")
                } else {
                    let hex: String = bytes[..shown].iter().map(|b| format!("{b:02x}")).collect();
                    format!("{length} bytes {hex}{}", if length > shown { "..." } else { "" })
                }
            };
            return Some(Description::received("BINARY", &summary));
        }
        self.description(Described::Definition(request))
    }
}

impl Description {
    fn received(kind: &'static str, summary: &str) -> Description {
        Description::Received { kind, summary: abbreviate(summary, MAX_DESCRIPTION_LENGTH) }
    }
}

/// The OpenAPI model as MockServer's own mapper writes it (`SORT_PROPERTIES_ALPHABETICALLY`): every bean's properties
/// in alphabetical order, while the entries of a map (paths, responses, media types, schema properties, …) keep the
/// order they were read in.
fn sort_model(value: Value, parent: Option<&str>) -> Value {
    // Properties of the swagger model whose value is a map, not a bean.
    const MAPS: &[&str] = &[
        "paths", "callbacks", "responses", "content", "schemas", "properties", "headers", "examples", "links", "requestBodies",
        "securitySchemes", "pathItems", "variables", "encoding", "mapping", "scopes", "parameters_map",
    ];
    match value {
        Value::Object(map) => {
            let is_map = parent.is_some_and(|p| MAPS.contains(&p));
            let media_type = parent == Some("<media type>");
            let mut entries: Vec<(String, Value)> = map.into_iter().collect();
            if media_type && !entries.iter().any(|(k, _)| k == "exampleSetFlag") {
                // `MediaType.getExampleSetFlag` is a public getter, so MockServer's mapper writes it.
                entries.push(("exampleSetFlag".into(), Value::Bool(false)));
            }
            if !is_map {
                entries.sort_by(|a, b| a.0.cmp(&b.0));
            }
            // The children of a map are beans again; a bean's children are looked up by their own property name.
            let entries = entries.into_iter().map(|(k, v)| {
                // Enums are written by name (`SIMPLE`), not by their `@JsonValue`.
                if k == "style" && let Value::String(style) = &v {
                    return (k, Value::String(style.to_ascii_uppercase()));
                }
                let child = if is_map { (parent == Some("content")).then_some("<media type>") } else { Some(k.as_str()) };
                let v = sort_model(v, child);
                (k, v)
            });
            Value::Object(entries.collect())
        }
        Value::Array(items) => Value::Array(items.into_iter().map(|v| sort_model(v, parent)).collect()),
        other => other,
    }
}

/// An `HttpRequest` (as opposed to a DNS, conditional or other definition).
fn is_plain_request(definition: &Value) -> bool {
    definition.is_object()
        && !crate::canonical::is_dns_request(definition)
        && !crate::canonical::is_binary_request(definition)
        && !crate::canonical::is_conditional_request(definition)
}

// ---------------------------------------------------------------------------------------------------------------
// DashboardBodyCap
// ---------------------------------------------------------------------------------------------------------------

/// `DashboardBodyCap.MAX_BODY_CHARACTERS`: how many characters (UTF-16 units, as Java counts them) of a body an update
/// carries; the dashboard loads the rest through `GET /mockserver/logEntryBody`.
pub const MAX_BODY_CHARACTERS: usize = 64 * 1024;
/// `DashboardBodyCap.MESSAGE_OVERHEAD_CHARACTERS`: a message's headers, path and the like, which are not capped.
pub const MESSAGE_OVERHEAD_CHARACTERS: u64 = 1024;
/// `DashboardBodyCap.MAX_BINARY_BYTES`: a binary message is shown as base64, and this many bytes fill the cap.
pub const MAX_BINARY_BYTES: usize = MAX_BODY_CHARACTERS / 4 * 3;
/// `DashboardWebSocketHandler.MAX_UPDATE_CHARACTERS`: roughly how many characters of log rows one update may carry.
pub const MAX_UPDATE_CHARACTERS: u64 = 16 * 1024 * 1024;

/// A string's length in UTF-16 units (`String.length()`).
fn utf16_len(text: &str) -> usize {
    text.chars().map(char::len_utf16).sum()
}

/// `DashboardBodyCap.prefix`: the first `limit` UTF-16 units of `text`, never ending on the first half of a
/// surrogate pair (a character that would straddle the limit is left out whole).
fn utf16_prefix(text: &str, limit: usize) -> &str {
    let mut units = 0;
    for (index, c) in text.char_indices() {
        units += c.len_utf16();
        if units > limit {
            return &text[..index];
        }
    }
    text
}

/// `DashboardBodyCap.BodyText`: a body's text as the dashboard shows it, cut to the cap, and its full length.
struct BodyText {
    text: String,
    length: u64,
}

impl BodyText {
    fn of(text: &str) -> BodyText {
        BodyText { text: utf16_prefix(text, MAX_BODY_CHARACTERS).to_string(), length: utf16_len(text) as u64 }
    }

    fn truncated(&self) -> bool {
        self.length > utf16_len(&self.text) as u64
    }
}

/// `DashboardBodyCap.bodyText`: a rendered body (a string, or a JSON body's tree, measured as Jackson writes it
/// compactly) or, for a body object as an expectation writes it (`{"type": …}`), its `toString`.
fn body_text(body: &Value) -> BodyText {
    match body {
        Value::String(text) => BodyText::of(text),
        Value::Object(o) if o.get("type").is_some_and(Value::is_string) => {
            let field = ["json", "string", "xml", "regex", "base64Bytes", "jsonSchema", "jsonPath", "xpath", "graphQL", "schema"]
                .iter()
                .find_map(|key| o.get(*key));
            match field {
                Some(Value::String(text)) => BodyText::of(text),
                Some(other) => BodyText::of(&crate::json::compact(other)),
                None => BodyText::of(&crate::json::compact(body)),
            }
        }
        other => BodyText::of(&crate::json::compact(other)),
    }
}

/// `DashboardBodyCap.capText`: a text longer than the cap, cut and followed by how much was left out.
pub fn cap_text(text: &str) -> String {
    let length = utf16_len(text);
    if length <= MAX_BODY_CHARACTERS {
        return text.to_string();
    }
    let shown = utf16_prefix(text, MAX_BODY_CHARACTERS);
    format!("{shown}... ({} more characters not shown)", length - utf16_len(shown))
}

/// What capping one message found: `None` when it has no body to measure, else the characters it shows and, when
/// it was cut, its full length.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Capped {
    pub shown: Option<u64>,
    pub original: Option<u64>,
}

/// `base64Length`
fn base64_length(bytes: u64) -> u64 {
    bytes.div_ceil(3) * 4
}

/// `DashboardBodyCap.cap(RequestDefinition|HttpResponse)` on a message's JSON, in place: its body (a binary
/// message's `binaryData`) cut to the cap.
fn cap_message(message: &mut Value) -> Capped {
    use base64::Engine;
    let Some(o) = message.as_object_mut() else {
        return Capped::default();
    };
    if crate::canonical::is_binary_request(&Value::Object(o.clone())) {
        let Some(Value::String(data)) = o.get("binaryData") else {
            return Capped::default();
        };
        let bytes = base64::engine::general_purpose::STANDARD.decode(data).unwrap_or_default();
        let length = base64_length(bytes.len() as u64);
        if length <= MAX_BODY_CHARACTERS as u64 {
            return Capped { shown: Some(length), original: None };
        }
        let shown = base64::engine::general_purpose::STANDARD.encode(&bytes[..MAX_BINARY_BYTES]);
        o.insert("binaryData".into(), Value::String(shown));
        return Capped { shown: Some(base64_length(MAX_BINARY_BYTES as u64)), original: Some(length) };
    }
    let Some(body) = o.get("body").filter(|b| !b.is_null()) else {
        return Capped::default();
    };
    let text = body_text(body);
    if !text.truncated() {
        return Capped { shown: Some(text.length), original: None };
    }
    let shown = utf16_len(&text.text) as u64;
    o.insert("body".into(), Value::String(text.text));
    Capped { shown: Some(shown), original: Some(text.length) }
}

/// Which of upstream's message classes an argument's JSON is: an `Expectation` (it has an `httpRequest`), an
/// `HttpResponse` (a status code or reason phrase and no request line), or a `RequestDefinition` (a request line, a
/// body or a binary message); `None` for any other object. `own` is the entry's own part the argument is, if any.
fn message_kind(value: &Value, own: Option<&str>) -> Option<&'static str> {
    let o = value.as_object()?;
    match own {
        Some("request") => return Some("request"),
        Some("response") => return Some("response"),
        _ => {}
    }
    if o.contains_key("httpRequest") {
        return Some("expectation");
    }
    let request_line = ["method", "path", "binaryData", "dnsName", "keepAlive", "secure"].iter().any(|k| o.contains_key(*k));
    if !request_line && (o.contains_key("statusCode") || o.contains_key("reasonPhrase")) {
        return Some("response");
    }
    if request_line || o.contains_key("body") || o.contains_key("headers") {
        return Some("request");
    }
    None
}

/// `DashboardBodyCap.capArgument`, in place: the characters the argument adds to an update, and, when a body in it was
/// cut, the full length and the marker's part.
fn cap_argument(argument: &mut DashArg, own: Option<&str>) -> (u64, Option<(u64, &'static str)>) {
    match argument {
        DashArg::Text(text) => {
            let characters = utf16_len(text).min(MAX_BODY_CHARACTERS) as u64;
            *text = cap_text(text);
            (characters, None)
        }
        DashArg::Json(value) => match message_kind(value, own) {
            Some("expectation") => {
                let mut characters = MESSAGE_OVERHEAD_CHARACTERS;
                let mut longest = None;
                for key in ["httpRequest", "httpResponse"] {
                    if let Some(message) = value.get_mut(key) {
                        let capped = cap_message(message);
                        characters += capped.shown.unwrap_or(0);
                        longest = longest.max(capped.original);
                    }
                }
                (characters, longest.map(|l| (l, "expectation")))
            }
            Some(kind) => {
                let capped = cap_message(value);
                (MESSAGE_OVERHEAD_CHARACTERS + capped.shown.unwrap_or(0), capped.original.map(|l| (l, kind)))
            }
            None => (256, None),
        },
    }
}

/// `DashboardBodyCap.truncationMarker`
pub fn truncation_marker(log_entry_id: &str, part: &str, original_length: u64, loadable: bool) -> Value {
    json!({
        "logEntryId": log_entry_id,
        "part": part,
        "originalLength": original_length,
        "shownLength": MAX_BODY_CHARACTERS,
        "loadable": loadable && part != "expectation",
    })
}

/// `DashboardBodyCap.capExpectationTree`: cuts, in place, every `body` of an expectation's JSON longer than the cap
/// (a JSON or binary body measured and cut as its compact text) and every other string longer than the cap but a
/// binary message's `binaryData`; the longest original length cut, or 0.
pub fn cap_expectation_tree(node: &mut Value) -> u64 {
    let mut longest = 0;
    match node {
        Value::Object(object) => {
            for (name, child) in object.iter_mut() {
                // a binary message's bytes are a binary node in upstream's tree, not text, and never cut
                if name == "binaryData" {
                    continue;
                }
                if name == "body" && (child.is_object() || child.is_array()) {
                    let text = crate::json::compact(child);
                    let length = utf16_len(&text) as u64;
                    if length > MAX_BODY_CHARACTERS as u64 {
                        *child = Value::String(utf16_prefix(&text, MAX_BODY_CHARACTERS).to_string());
                        longest = longest.max(length);
                        continue;
                    }
                }
                longest = longest.max(cap_child(child));
            }
        }
        Value::Array(items) => {
            for item in items.iter_mut() {
                longest = longest.max(cap_child(item));
            }
        }
        _ => {}
    }
    longest
}

fn cap_child(child: &mut Value) -> u64 {
    if let Value::String(text) = child {
        let length = utf16_len(text);
        if length > MAX_BODY_CHARACTERS {
            *text = utf16_prefix(text, MAX_BODY_CHARACTERS).to_string();
            return length as u64;
        }
        return 0;
    }
    cap_expectation_tree(child)
}

/// `DashboardBodyCap.expectationTruncationMarker`
pub fn expectation_truncation_marker(expectation_id: &str, original_length: u64) -> Value {
    json!({"expectationId": expectation_id, "part": "expectation", "originalLength": original_length, "shownLength": MAX_BODY_CHARACTERS})
}

/// `DashboardWebSocketHandler.FrameBudget`: roughly how many characters an update may hold. Rows arrive newest
/// first, so once a log message or a request row would take the update past this, it and every older one of its kind
/// are left out and the update says so. Log messages may use only part of the update, so request rows keep a share.
#[derive(Debug)]
pub struct FrameBudget {
    max_characters: u64,
    max_log_message_characters: u64,
    used_characters: u64,
    log_message_characters: u64,
    row_characters: u64,
    log_messages_limit_reached: bool,
    rows_limit_reached: bool,
}

impl FrameBudget {
    pub fn new(max_characters: u64) -> FrameBudget {
        FrameBudget::with_log_share(max_characters, max_characters / 4 * 3)
    }

    pub fn with_log_share(max_characters: u64, max_log_message_characters: u64) -> FrameBudget {
        FrameBudget {
            max_characters,
            max_log_message_characters,
            used_characters: 0,
            log_message_characters: 0,
            row_characters: 0,
            log_messages_limit_reached: false,
            rows_limit_reached: false,
        }
    }

    pub fn admit_log_message(&mut self, characters: u64) -> bool {
        if self.log_messages_limit_reached {
            return false;
        }
        if self.log_message_characters > 0
            && (self.log_message_characters + characters > self.max_log_message_characters || self.used_characters + characters > self.max_characters)
        {
            self.log_messages_limit_reached = true;
            return false;
        }
        self.log_message_characters += characters;
        self.used_characters += characters;
        true
    }

    pub fn admit_row(&mut self, characters: u64) -> bool {
        if self.rows_limit_reached {
            return false;
        }
        if self.row_characters > 0 && self.used_characters + characters > self.max_characters {
            self.rows_limit_reached = true;
            return false;
        }
        self.row_characters += characters;
        self.used_characters += characters;
        true
    }

    pub fn log_messages_limit_reached(&self) -> bool {
        self.log_messages_limit_reached
    }

    pub fn rows_limit_reached(&self) -> bool {
        self.rows_limit_reached
    }
}

// ---------------------------------------------------------------------------------------------------------------
// DashboardLogEntryDTO and its serializers
// ---------------------------------------------------------------------------------------------------------------

/// One message argument: a `String` or `NottableString` (shown quoted, or line by line), or any other object (shown
/// as JSON).
#[derive(Clone, Debug, PartialEq)]
pub enum DashArg {
    Text(String),
    Json(Value),
}

impl DashArg {
    /// A logged argument's JSON: a string stays text (upstream's other string-like arguments, a socket address, are
    /// not told apart in the log's JSON).
    pub fn from_json(value: &Value) -> DashArg {
        match value {
            Value::String(text) => DashArg::Text(text.clone()),
            other => DashArg::Json(other.clone()),
        }
    }
}

/// `DashboardLogEntryDTO`.
#[derive(Default)]
pub struct DashEntry {
    pub id: String,
    pub correlation_id: Option<String>,
    /// `yyyy-MM-dd HH:mm:ss.SSS`
    pub timestamp: Option<String>,
    /// The `LogMessageType` name.
    pub kind: Option<String>,
    pub requests: Vec<Value>,
    pub response: Option<Value>,
    pub message_format: Option<String>,
    pub arguments: Option<Vec<DashArg>>,
    /// The stack trace's lines.
    pub throwable: Option<Vec<String>>,
    pub because: Option<String>,
    pub description: Option<Description>,
    /// `LogEntry.isDeleted()`: a cleared entry that has not been dropped yet; frames leave it out.
    pub deleted: bool,
    /// `argumentOwnMessageParts`: per argument, `request` or `response` when it is the entry's own (`None` when no
    /// argument is); only those load whole from the entry.
    pub own_parts: Option<Vec<Option<String>>>,
    /// What [`DashEntry::cap_bodies`] found, once it ran.
    pub caps: Option<EntryCaps>,
}

/// `DashboardLogEntryDTO`'s `messageSizes`, `argumentSizes` and `binaryLengths`: what capping one entry's bodies found.
#[derive(Clone, Debug, Default)]
pub struct EntryCaps {
    /// Per request of the entry.
    pub requests: Vec<Capped>,
    /// Per request: a binary message's length in bytes before the cut.
    pub binary_lengths: Vec<Option<usize>>,
    pub response: Capped,
    /// Per argument: the full body length of a request, response or expectation argument that was cut, and its part.
    pub arguments: Vec<Option<(u64, &'static str)>>,
    /// `argumentSizes.displayedCharacters()`
    pub argument_characters: u64,
}

impl DashEntry {
    pub fn new(id: impl Into<String>, correlation_id: Option<&str>, timestamp: Option<&str>, kind: Option<&str>) -> DashEntry {
        DashEntry {
            id: id.into(),
            correlation_id: correlation_id.map(str::to_string),
            timestamp: timestamp.map(str::to_string),
            kind: kind.map(str::to_string),
            ..Default::default()
        }
    }

    /// `getHttpRequest()`: the first request.
    pub fn request(&self) -> Option<&Value> {
        self.requests.first()
    }

    /// The constructor's half of `DashboardLogEntryDTO` that `DashboardBodyCap` does: every body of the entry's
    /// requests, response and request, response or expectation arguments cut to [`MAX_BODY_CHARACTERS`] (a binary
    /// message's to [`MAX_BINARY_BYTES`]), each text argument and `because` too, with what was cut recorded in
    /// [`DashEntry::caps`]. Runs once.
    pub fn cap_bodies(&mut self) {
        if self.caps.is_some() {
            return;
        }
        use base64::Engine;
        let mut caps = EntryCaps::default();
        for request in &mut self.requests {
            let binary = crate::canonical::is_binary_request(request).then(|| {
                let data = request.get("binaryData").and_then(Value::as_str).unwrap_or_default();
                base64::engine::general_purpose::STANDARD.decode(data).map(|b| b.len()).unwrap_or_default()
            });
            caps.binary_lengths.push(binary);
            caps.requests.push(cap_message(request));
        }
        if let Some(response) = &mut self.response {
            caps.response = cap_message(response);
        }
        if let Some(arguments) = &mut self.arguments {
            for (i, argument) in arguments.iter_mut().enumerate() {
                let own = self.own_parts.as_ref().and_then(|o| o.get(i).cloned().flatten());
                let (characters, cut) = cap_argument(argument, own.as_deref());
                caps.argument_characters += characters;
                caps.arguments.push(cut);
            }
        }
        if let Some(because) = &self.because {
            self.because = Some(cap_text(because));
        }
        self.caps = Some(caps);
    }

    /// `argumentLoadableFromEntry`
    fn argument_loadable(&self, index: usize) -> bool {
        self.own_parts.as_ref().and_then(|o| o.get(index)).is_some_and(Option::is_some)
    }

    /// `estimatedLogMessageCharacters`: roughly how many characters the entry adds to an update as a log message.
    pub fn estimated_log_message_characters(&self) -> u64 {
        MESSAGE_OVERHEAD_CHARACTERS
            + self.message_format.as_deref().map_or(0, |f| utf16_len(f) as u64)
            + self.caps.as_ref().map_or(0, |c| c.argument_characters)
            + self.throwable.as_ref().map_or(0, |t| t.len() as u64 * 100)
    }

    /// An entry from one element of `retrieve?format=LOG_ENTRIES` (`LogEntrySerializer`), which already carries the
    /// redaction `redactSecretsInLog` asks for on its request(s) and response.
    pub fn from_log_json(entry: &Value, id: String) -> DashEntry {
        let text = |key: &str| entry.get(key).and_then(Value::as_str).map(str::to_string);
        let requests = match (entry.get("httpRequest"), entry.get("httpRequests")) {
            (Some(one), _) => vec![one.clone()],
            (None, Some(Value::Array(many))) => many.clone(),
            _ => Vec::new(),
        };
        DashEntry {
            id,
            correlation_id: text("correlationId"),
            timestamp: text("timestamp"),
            kind: text("type"),
            requests,
            response: entry.get("httpResponse").cloned(),
            message_format: text("messageFormat"),
            arguments: entry.get("arguments").and_then(Value::as_array).map(|a| {
                let objects = entry.get("$objectArguments").and_then(Value::as_object);
                a.iter().enumerate().map(|(i, v)| match objects.and_then(|o| o.get(&i.to_string())) {
                    Some(shown) => DashArg::Json(shown.clone()),
                    None => DashArg::from_json(v),
                }).collect()
            }),
            throwable: entry.get("$throwable").and_then(Value::as_array).map(|lines| lines.iter().filter_map(|l| l.as_str().map(str::to_string)).collect()),
            because: text("because"),
            description: None,
            deleted: false,
            own_parts: entry
                .get("$ownParts")
                .and_then(Value::as_array)
                .map(|parts| parts.iter().map(|p| p.as_str().map(str::to_string)).collect()),
            caps: None,
        }
    }
}

/// `DashboardLogEntryDTOSerializer.logStyle`.
pub fn log_style(kind: &str) -> Value {
    // `style.whiteSpace` is put first as an empty placeholder: a kind that wants it gets `pre-wrap` in that slot,
    // the others drop it.
    let (color, pre_wrap): (Option<&str>, bool) = match kind {
        "RUNNABLE" => (None, false),
        "TRACE" => (Some("rgb(215, 216, 154)"), true),
        "DEBUG" => (Some("rgb(178,132,190)"), true),
        "INFO" => (Some("rgb(59,122,87)"), true),
        "WARN" => (Some("rgb(245, 95, 105)"), true),
        "ERROR" => (Some("rgb(179, 97, 122)"), true),
        "EXCEPTION" => (Some("rgb(211,33,45)"), true),
        "CLEARED" => (Some("rgb(139, 146, 52)"), false),
        "RETRIEVED" => (Some("rgb(222, 147, 95)"), false),
        "UPDATED_EXPECTATION" => (Some("rgb(176,191,26)"), false),
        "CREATED_EXPECTATION" => (Some("rgb(216,199,166)"), false),
        "REMOVED_EXPECTATION" => (Some("rgb(124,185,232)"), false),
        "RECEIVED_REQUEST" => (Some("rgb(114,160,193)"), false),
        "EXPECTATION_RESPONSE" => (Some("rgb(161,208,231)"), false),
        "NO_MATCH_RESPONSE" => (Some("rgb(196,98,16)"), false),
        "EXPECTATION_MATCHED" => (Some("rgb(117,185,186)"), false),
        "EXPECTATION_NOT_MATCHED" => (Some("rgb(204,165,163)"), false),
        "VERIFICATION" => (Some("rgb(178, 148, 187)"), false),
        "VERIFICATION_FAILED" => (Some("rgb(234, 67, 106)"), false),
        "FORWARDED_REQUEST" => (Some("rgb(152, 208, 255)"), false),
        "TEMPLATE_GENERATED" => (Some("rgb(241, 186, 27)"), false),
        "TEMPLATE_GENERATION_FAILED" => (Some("rgb(211,33,45)"), true),
        "SERVER_CONFIGURATION" => (Some("rgb(138, 175, 136)"), false),
        _ => (Some("rgb(201, 125, 240)"), false),
    };
    let mut style = Map::new();
    if pre_wrap {
        style.insert("style.whiteSpace".into(), "pre-wrap".into());
    }
    style.insert("paddingBottom".into(), "4px".into());
    style.insert("whiteSpace".into(), "nowrap".into());
    style.insert("overflow".into(), "auto".into());
    if let Some(color) = color {
        style.insert("color".into(), color.into());
    }
    style.insert("paddingTop".into(), "4px".into());
    Value::Object(style)
}

/// `DashboardLogEntryDTOSerializer.serialize`.
pub fn entry_value(entry: &DashEntry) -> Value {
    let mut value = Map::new();
    if let Some(timestamp) = &entry.timestamp {
        value.insert("timestamp".into(), timestamp.clone().into());
    }
    if let Some(description) = &entry.description {
        value.insert("description".into(), description.to_value());
    }
    if let Some(kind) = &entry.kind {
        value.insert("style".into(), log_style(kind));
    }
    if let Some(format) = &entry.message_format {
        let id = &entry.id;
        let format_parts = if format.trim().is_empty() { vec![String::new()] } else { java_split(format, "{}") };
        let mut parts: Vec<Value> = Vec::new();
        for (i, part) in format_parts.iter().enumerate() {
            parts.push(json!({"key": format!("{id}_{i}msg"), "value": part}));
            if let Some(argument) = entry.arguments.as_ref().and_then(|a| a.get(i)) {
                parts.push(argument_part(entry, i, argument));
            }
        }
        if let Some(throwable) = &entry.throwable {
            parts.push(json!({"key": format!("{id}_throwable_msg"), "value": "exception:"}));
            parts.push(json!({"key": format!("{id}_throwable_value"), "multiline": true, "argument": true, "value": throwable}));
        }
        value.insert("messageParts".into(), Value::Array(parts));
    }
    json!({"key": format!("{}_log", entry.id), "value": value})
}

fn argument_part(entry: &DashEntry, i: usize, argument: &DashArg) -> Value {
    let key = format!("{}_{i}arg", entry.id);
    match argument {
        DashArg::Text(text) => {
            let lines = {
                let split = java_split(text, "\n");
                if split.is_empty() { vec![String::new()] } else { split }
            };
            if entry.because.as_deref() == Some(text.as_str()) {
                json!({"key": key, "because": true, "argument": true, "value": lines})
            } else if lines.len() > 1 {
                json!({"key": key, "multiline": true, "argument": true, "value": lines})
            } else {
                json!({"key": key, "multiline": false, "argument": true, "value": format!("\"{}\"", lines[0])})
            }
        }
        DashArg::Json(Value::Null) => json!({"key": key, "json": true, "argument": true, "value": "\"\""}),
        DashArg::Json(other) => {
            let mut part = json!({"key": key, "json": true, "argument": true, "value": other});
            if let Some((original, kind)) = entry.caps.as_ref().and_then(|c| c.arguments.get(i).copied().flatten()) {
                part["truncatedBody"] = truncation_marker(&entry.id, kind, original, entry.argument_loadable(i));
            }
            part
        }
    }
}

/// `DashboardLogEntryDTOGroupSerializer.serialize`: a group of several entries rolls up under the first's header, a
/// group of one is that entry. `processor` is the group's own (`getDescriptionProcessor`).
pub fn group_value(entries: &[DashEntry], processor: &Rc<DescriptionProcessor>) -> Value {
    match entries {
        [] => Value::Null,
        [only] => entry_value(only),
        [first, ..] => {
            let mut header = DashEntry::new(first.id.clone(), first.correlation_id.as_deref(), first.timestamp.as_deref(), first.kind.as_deref());
            header.description = processor.description(Described::Log(first));
            let mut group = serde_json::Map::new();
            group.insert("key".into(), format!("{}_log_group", first.id).into());
            // every entry in a group shares this id; the dashboard needs it for `PUT /mockserver/explain` (9.1.0)
            if let Some(id) = first.correlation_id.as_deref() {
                group.insert("correlationId".into(), id.into());
            }
            group.insert("group".into(), entry_value(&header));
            group.insert("value".into(), Value::Array(entries.iter().map(entry_value).collect()));
            Value::Object(group)
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------
// sendUpdate
// ---------------------------------------------------------------------------------------------------------------

/// An active expectation as the frame needs it: its id, its `httpRequest` and its JSON.
pub struct ActiveExpectation {
    pub id: String,
    pub http_request: Value,
    pub value: Value,
}

enum LogItem {
    Entry(Box<DashEntry>),
    Group(Vec<DashEntry>),
}

struct Item {
    description: Option<Description>,
    value: Value,
    key: String,
    /// The recorded and proxied panels write `description` before `value` and `key`; the expectations panel writes
    /// `key`, `description`, `value`.
    key_first: bool,
    /// The recorded and proxied rows end with their entry's `timestamp` and (when not blank) `correlationId`.
    timestamp: Option<String>,
    correlation_id: Option<String>,
    /// Written last: a row's `truncatedBodies`, an expectation's `truncatedExpectation`.
    marker: Option<(&'static str, Value)>,
}

impl Item {
    fn to_value(&self, fallback_description: Option<&str>) -> Value {
        let mut o = Map::new();
        if self.key_first {
            o.insert("key".into(), self.key.clone().into());
        }
        match (&self.description, fallback_description) {
            (Some(d), _) => {
                o.insert("description".into(), d.to_value());
            }
            (None, Some(f)) => {
                o.insert("description".into(), f.into());
            }
            _ => {}
        }
        o.insert("value".into(), self.value.clone());
        if !self.key_first {
            o.insert("key".into(), self.key.clone().into());
        }
        if let Some(timestamp) = &self.timestamp {
            o.insert("timestamp".into(), timestamp.clone().into());
        }
        if let Some(correlation_id) = self.correlation_id.as_deref().filter(|c| !c.trim().is_empty()) {
            o.insert("correlationId".into(), correlation_id.into());
        }
        if let Some((name, marker)) = &self.marker {
            o.insert((*name).into(), marker.clone());
        }
        Value::Object(o)
    }
}

fn is_blank(text: Option<&str>) -> bool {
    text.is_none_or(|t| t.trim().is_empty())
}

/// `RowMessage`: the request or response a recorded or proxied row shows (cut), what capping it found, and the id of
/// the log entry that holds it whole.
#[derive(Clone)]
struct RowMessage {
    message: Value,
    capped: Capped,
    source: String,
    part: &'static str,
}

impl RowMessage {
    /// `RowMessage.characters`
    fn characters(&self) -> u64 {
        MESSAGE_OVERHEAD_CHARACTERS
            + self.capped.shown.unwrap_or_else(|| match self.message.get("body") {
                None | Some(Value::Null) => 0,
                Some(Value::String(text)) => utf16_len(text) as u64,
                Some(_) => MAX_BODY_CHARACTERS as u64,
            })
    }
}

/// `markTruncated`: marks a row's message whose body was cut, with the log entry to load it from.
fn mark_truncated(markers: &mut Map<String, Value>, field: &str, message: Option<&RowMessage>, loadable: bool) {
    if let Some(message) = message && let Some(original) = message.capped.original {
        markers.insert(field.into(), truncation_marker(&message.source, message.part, original, loadable));
    }
}

/// `DashboardWebSocketHandler.sendUpdate`'s frame: `entries` newest first (deleted ones already gone) and the
/// active expectations in match order. A panel with nothing in it is left out, as Jackson's inclusion drops an empty
/// list.
pub fn build_frame(entries: Vec<DashEntry>, expectations: Vec<ActiveExpectation>) -> Value {
    build_frame_with(entries, expectations, false)
}

/// [`build_frame`] under `redactSecretsInLog` as `redact_secrets_in_log` says, which a binary Received Requests row
/// describes as `bytes redacted`.
pub fn build_frame_with(entries: Vec<DashEntry>, expectations: Vec<ActiveExpectation>, redact_secrets_in_log: bool) -> Value {
    build_frame_within(entries, expectations, redact_secrets_in_log, &mut FrameBudget::new(MAX_UPDATE_CHARACTERS))
}

/// [`build_frame_with`] whose log messages and rows `budget` bounds (`populateLogSections`); the frame says when it
/// left some out (`frameLimitReached`, `logMessagesLimitReached`).
pub fn build_frame_within(entries: Vec<DashEntry>, expectations: Vec<ActiveExpectation>, redact_secrets_in_log: bool, budget: &mut FrameBudget) -> Value {
    // Over every expectation the filter retrieved, not the capped page.
    let active_total = expectations.len();
    let active_include_llm = expectations.iter().any(|e| e.value.get("httpLlmResponse").is_some_and(|v| !v.is_null()));
    let active_processor = DescriptionProcessor::new();
    let log_processor = DescriptionProcessor::new();
    let recorded_processor = DescriptionProcessor::new();
    let proxied_processor = DescriptionProcessor::new();

    let active: Vec<Item> = expectations
        .into_iter()
        .take(ITEM_LIMIT)
        .map(|mut e| {
            // `activeExpectationValue`: long bodies cut; the dashboard loads the whole expectation by id before editing it
            let longest = cap_expectation_tree(&mut e.value);
            Item {
                description: active_processor.description_with_id(Described::Definition(&e.http_request), Some(&e.id)),
                marker: (longest > 0).then(|| ("truncatedExpectation", expectation_truncation_marker(&e.id, longest))),
                value: e.value,
                key: e.id,
                key_first: true,
                timestamp: None,
                correlation_id: None,
            }
        })
        .collect();
    let active_ids: Vec<String> = active.iter().map(|i| i.key.clone()).collect();

    let mut log_items: Vec<LogItem> = Vec::new();
    let mut group_index: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut recorded: Vec<Item> = Vec::new();
    let mut proxied: Vec<Item> = Vec::new();
    // A response is stashed by correlation id when it is met, newest first, so the request that follows it can
    // be shown with its response.
    let mut responses: std::collections::HashMap<String, RowMessage> = std::collections::HashMap::new();
    for mut entry in entries.into_iter().filter(|e| !e.deleted) {
        // the walk stops once no section can take another item (the frame is the same as a full walk's)
        if !((!budget.log_messages_limit_reached() && log_items.len() < ITEM_LIMIT)
            || (!budget.rows_limit_reached() && (recorded.len() < ITEM_LIMIT || proxied.len() < ITEM_LIMIT)))
        {
            break;
        }
        entry.cap_bodies();
        let caps = entry.caps.clone().unwrap_or_default();
        let kind = entry.kind.clone();
        let correlation = entry.correlation_id.clone();
        let response = entry.response.clone();
        let requests = entry.requests.clone();
        let id = entry.id.clone();
        let timestamp = entry.timestamp.clone();
        if log_items.len() < ITEM_LIMIT && budget.admit_log_message(entry.estimated_log_message_characters()) {
            entry.description = log_processor.description(Described::Log(&entry));
            if !is_blank(correlation.as_deref()) && kind.as_deref() != Some("TRACE") {
                let correlation = correlation.clone().unwrap();
                match group_index.get(&correlation) {
                    Some(index) => {
                        if let LogItem::Group(group) = &mut log_items[*index] {
                            group.push(entry);
                        }
                    }
                    None => {
                        group_index.insert(correlation, log_items.len());
                        log_items.push(LogItem::Group(vec![entry]));
                    }
                }
            } else {
                log_items.push(LogItem::Entry(Box::new(entry)));
            }
        }
        let response_message =
            response.as_ref().map(|r| RowMessage { message: r.clone(), capped: caps.response, source: id.clone(), part: "response" });
        if matches!(kind.as_deref(), Some("EXPECTATION_RESPONSE" | "NO_MATCH_RESPONSE")) && !is_blank(correlation.as_deref()) && let Some(message) = &response_message {
            responses.entry(correlation.clone().unwrap()).or_insert_with(|| message.clone());
        }
        if kind.as_deref() == Some("RECEIVED_REQUEST") && recorded.len() < ITEM_LIMIT {
            for (index, request) in requests.iter().enumerate().filter(|(_, r)| !r.is_null()) {
                let request_message = RowMessage {
                    message: request.clone(),
                    capped: caps.requests.get(index).copied().unwrap_or_default(),
                    source: id.clone(),
                    part: "request",
                };
                let response_message = correlation.as_deref().filter(|c| !c.trim().is_empty()).and_then(|c| responses.get(c));
                if !budget.admit_row(request_message.characters() + response_message.map_or(0, RowMessage::characters)) {
                    break;
                }
                let mut value = Map::new();
                value.insert("httpRequest".into(), request.clone());
                if let Some(response) = response_message {
                    value.insert("httpResponse".into(), response.message.clone());
                }
                let mut markers = Map::new();
                // the endpoint returns an entry's first request
                mark_truncated(&mut markers, "httpRequest", Some(&request_message), index == 0);
                mark_truncated(&mut markers, "httpResponse", response_message, true);
                let binary_length = caps.binary_lengths.get(index).copied().flatten();
                recorded.push(Item {
                    description: recorded_processor.received_request_description(request, binary_length, redact_secrets_in_log),
                    value: Value::Object(value),
                    key: format!("{id}_request"),
                    key_first: false,
                    timestamp: timestamp.clone(),
                    correlation_id: correlation.clone(),
                    marker: (!markers.is_empty()).then(|| ("truncatedBodies", Value::Object(markers))),
                });
            }
        }
        if kind.as_deref() == Some("FORWARDED_REQUEST") && proxied.len() < ITEM_LIMIT {
            let request_message = requests.first().map(|r| RowMessage {
                message: r.clone(),
                capped: caps.requests.first().copied().unwrap_or_default(),
                source: id.clone(),
                part: "request",
            });
            let mut value = Map::new();
            if let Some(request) = &request_message {
                value.insert("httpRequest".into(), request.message.clone());
            }
            if let Some(response) = &response_message {
                value.insert("httpResponse".into(), response.message.clone());
            }
            let description = requests.first().and_then(|r| proxied_processor.description(Described::Definition(r)));
            let characters = request_message.as_ref().map_or(0, RowMessage::characters) + response_message.as_ref().map_or(0, RowMessage::characters);
            if !value.is_empty() && budget.admit_row(characters) {
                let mut markers = Map::new();
                mark_truncated(&mut markers, "httpRequest", request_message.as_ref(), true);
                mark_truncated(&mut markers, "httpResponse", response_message.as_ref(), true);
                proxied.push(Item {
                    description,
                    value: Value::Object(value),
                    key: format!("{id}_proxied"),
                    key_first: false,
                    timestamp: timestamp.clone(),
                    correlation_id: correlation.clone(),
                    marker: (!markers.is_empty()).then(|| ("truncatedBodies", Value::Object(markers))),
                });
            }
        }
    }

    let mut frame = Map::new();
    let log_messages: Vec<Value> = log_items
        .iter()
        .map(|item| match item {
            LogItem::Entry(entry) => entry_value(entry),
            LogItem::Group(group) => group_value(group, &log_processor),
        })
        .collect();
    if !log_messages.is_empty() {
        frame.insert("logMessages".into(), Value::Array(log_messages));
    }
    let active_values: Vec<Value> = active.iter().zip(&active_ids).map(|(item, id)| item.to_value(Some(id))).collect();
    if !active_values.is_empty() {
        frame.insert("activeExpectations".into(), Value::Array(active_values));
    }
    frame.insert("activeExpectationsTotal".into(), active_total.into());
    frame.insert("activeExpectationsIncludeLlm".into(), active_include_llm.into());
    let recorded_values: Vec<Value> = recorded.iter().map(|i| i.to_value(None)).collect();
    if !recorded_values.is_empty() {
        frame.insert("recordedRequests".into(), Value::Array(recorded_values));
    }
    let proxied_values: Vec<Value> = proxied.iter().map(|i| i.to_value(None)).collect();
    if !proxied_values.is_empty() {
        frame.insert("proxiedRequests".into(), Value::Array(proxied_values));
    }
    // only when it applies, so an update under the ceiling is unchanged
    if budget.rows_limit_reached() {
        frame.insert("frameLimitReached".into(), true.into());
    }
    if budget.log_messages_limit_reached() {
        frame.insert("logMessagesLimitReached".into(), true.into());
    }
    Value::Object(frame)
}

/// The frame as the text of a WebSocket message: compact, or pretty-printed as Jackson does.
pub fn frame_text(frame: &Value, pretty: bool) -> String {
    if pretty { crate::json::pretty(frame) } else { frame.to_string() }
}

// ---------------------------------------------------------------------------------------------------------------
// The live half
// ---------------------------------------------------------------------------------------------------------------

/// An id for a log entry that stays the same from one frame to the next (the event log's own ids are not kept): a
/// UUID derived from what identifies the entry, and how many identical ones precede it.
fn stable_id(entry: &Value, occurrence: usize) -> String {
    let basis = format!(
        "{}|{}|{}|{}|{}|{occurrence}",
        entry.get("epochTime").map(Value::to_string).unwrap_or_default(),
        entry.get("type").and_then(Value::as_str).unwrap_or_default(),
        entry.get("correlationId").and_then(Value::as_str).unwrap_or_default(),
        entry.get("messageFormat").and_then(Value::as_str).unwrap_or_default(),
        entry.get("message").map(Value::to_string).unwrap_or_default(),
    );
    uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_OID, basis.as_bytes()).to_string()
}

/// `LogEntry.LogMessageTypeCategory.resolveEffectiveLevel` as `sendUpdate` applies it to the dashboard log: the
/// `logLevelOverrides` the server started with (a later `PUT /mockserver/configuration` does not reach the dashboard,
/// confirmed against the oracle), keyed by a type name or a category name, upper-cased; an unknown level is ignored.
struct LevelOverrides {
    overrides: std::collections::HashMap<String, i32>,
    global: i32,
}

impl LevelOverrides {
    fn of(state: &State) -> LevelOverrides {
        let mut overrides = std::collections::HashMap::new();
        if let Some(Ok(Value::Object(map))) = state.config.property_outside_file("logLevelOverrides").map(|text| serde_json::from_str::<Value>(&text)) {
            for (key, level) in map {
                if let Some(level) = level.as_str().and_then(Self::level) {
                    overrides.insert(key.to_ascii_uppercase(), level);
                }
            }
        }
        // A global `OFF` is no level (`Configuration.logLevel()` is null), so `isEnabled` shows nothing it governs.
        let global = if state.log_level.eq_ignore_ascii_case("OFF") { 50 } else { Self::level(&state.log_level).unwrap_or(20) };
        LevelOverrides { overrides, global }
    }

    /// `org.slf4j.event.Level.toInt`, through `VALID_LEVELS` (the SLF4J levels, so `OFF` and `WARNING` are none).
    fn level(name: &str) -> Option<i32> {
        match name.to_ascii_uppercase().as_str() {
            "TRACE" => Some(0),
            "DEBUG" => Some(10),
            "INFO" => Some(20),
            "WARN" => Some(30),
            "ERROR" => Some(40),
            _ => None,
        }
    }

    /// `LogMessageTypeCategory.categoryFor`.
    fn category(kind: &str) -> Option<&'static str> {
        Some(match kind {
            "EXPECTATION_MATCHED" | "EXPECTATION_NOT_MATCHED" | "NO_MATCH_RESPONSE" => "MATCHING",
            "RECEIVED_REQUEST" | "FORWARDED_REQUEST" | "EXPECTATION_RESPONSE" | "TEMPLATE_GENERATED" | "TEMPLATE_GENERATION_FAILED" => "REQUEST_LIFECYCLE",
            "CREATED_EXPECTATION" | "UPDATED_EXPECTATION" | "REMOVED_EXPECTATION" | "CLEARED" => "EXPECTATION_MANAGEMENT",
            "VERIFICATION" | "VERIFICATION_FAILED" | "VERIFICATION_PASSED" | "RETRIEVED" => "VERIFICATION",
            "SERVER_CONFIGURATION" | "AUTHENTICATION_FAILED" | "OPENAPI_REQUEST_VALIDATION_FAILED" | "OPENAPI_RESPONSE_VALIDATION_FAILED" => "SERVER",
            "TRACE" | "DEBUG" | "INFO" | "WARN" | "ERROR" | "EXCEPTION" => "GENERAL",
            _ => return None,
        })
    }

    /// The predicate of `sendUpdate`: `overrides.isEmpty() || isEnabled(entry level, effective level)`. Upstream also lets a
    /// `LogEntry.alwaysLog` entry through, but the only such entries (`ConfigurationProperties` loading the properties file)
    /// are logged before any event log exists, so no entry in it carries the flag and none is modelled here.
    fn shows(&self, entry: &Value) -> bool {
        if self.overrides.is_empty() {
            return true;
        }
        let kind = entry.get("type").and_then(Value::as_str).unwrap_or_default();
        let effective = self
            .overrides
            .get(kind)
            .or_else(|| Self::category(kind).and_then(|category| self.overrides.get(category)))
            .copied()
            .unwrap_or(self.global);
        let level = entry.get("logLevel").and_then(Value::as_str).and_then(Self::level).unwrap_or(20);
        level >= effective
    }
}

/// The entries `sendUpdate` shows of `raw` (the event log as `retrieve?format=LOG_ENTRIES` writes it, oldest first)
/// under the `logLevelOverrides`, each with its id ([`stable_id`]), which is what a row's key carries.
fn identified<'a>(state: &State, raw: &'a [Value]) -> Vec<(String, &'a Value)> {
    let overrides = LevelOverrides::of(state);
    let mut seen: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    raw.iter()
        .filter(|entry| overrides.shows(entry))
        .map(|entry| {
            let signature = format!("{}{}{}{}", entry["epochTime"], entry["type"], entry["correlationId"], entry["message"]);
            let count = seen.entry(signature).or_insert(0);
            let id = stable_id(entry, *count);
            *count += 1;
            (id, entry)
        })
        .collect()
}

/// `GET /mockserver/logEntryBody?id=<log entry id>&part=request|response` (`HttpState.handleLogEntryBodyGet`): the
/// entry's first request or its response, whole and as the dashboard shows it (redacted under `redactSecretsInLog`),
/// as `{"httpRequest": …}` or `{"httpResponse": …}`; a DNS query or binary message is its definition (upstream #102).
/// The id is a dashboard row's (an entry's [`stable_id`] in an unfiltered frame).
pub fn log_entry_body(state: &State, request: &HttpRequest) -> crate::reply::Reply {
    use crate::reply::Reply;
    let id = crate::request::first(&request.query, "id").filter(|i| !i.trim().is_empty());
    let part = crate::request::first(&request.query, "part");
    let (Some(id), Some(part @ ("request" | "response"))) = (id, part) else {
        return Reply::api_body(400, "application/json", r#"{"error":"id and part (request or response) are required"}"#);
    };
    let raw = state.log.log_entries_as(
        crate::recorded::EntryScope::Messages,
        |_| true,
        crate::control::unfiltered_admits_definition,
        Some(state.first_port()),
        &state.config,
        true,
    );
    let entry = identified(state, &raw).into_iter().find(|(entry_id, _)| entry_id == id).map(|(_, entry)| entry);
    let message = entry.and_then(|entry| match part {
        "request" => entry.get("httpRequest").or_else(|| entry.get("httpRequests").and_then(|r| r.get(0))),
        _ => entry.get("httpResponse"),
    });
    match message.filter(|m| !m.is_null()) {
        Some(message) => {
            let key = if part == "request" { "httpRequest" } else { "httpResponse" };
            Reply::api_body(200, "application/json", crate::json::compact(&json!({key: message})))
        }
        None => {
            let error = format!("no {part} for this log entry; it may have been cleared or evicted");
            Reply::api_body(404, "application/json", crate::json::compact(&json!({"error": error})))
        }
    }
}

/// `sendUpdate` for `filter` (a request matcher, `None` for every request): the current frame.
pub fn frame_for(state: &State, filter: Option<&Value>) -> Value {
    // `DescriptionProcessor.buildOpenAPI(…, configuration)`: the specs it describes are parsed under the forward target checks.
    crate::openapi::checking_spec_fetches(&state.config, || frame_for_unchecked(state, filter))
}

fn frame_for_unchecked(state: &State, filter: Option<&Value>) -> Value {
    let matcher = crate::matcher::string::with_remote_refs_policy(state.json_schema_allow_remote_refs(), || filter.map(crate::matcher::RequestMatcher::compile));
    let any = crate::matcher::RequestMatcher::any();
    let effective = matcher.as_ref().unwrap_or(&any);
    // `RequestMatchers.isUnfiltered`: the dashboard's `{}` is "show all", not a reverse match.
    let unfiltered = filter.is_none_or(crate::control::is_empty_filter);
    let raw = state.log.log_entries_as(
        crate::recorded::EntryScope::Messages,
        |r| effective.matches(r, crate::matcher::Mode::ControlPlane),
        |d| if unfiltered { crate::control::unfiltered_admits_definition(d) } else { crate::control::definition_matches_filter(d, effective) },
        Some(state.first_port()),
        &state.config,
        true,
    );
    let mut entries: Vec<DashEntry> = identified(state, &raw).into_iter().map(|(id, entry)| DashEntry::from_log_json(entry, id)).collect();
    entries.reverse();
    let expectations = crate::control::retrievable_logged(state)
        .into_iter()
        .filter(|e| unfiltered || crate::control::expectation_matches_filter(e, effective))
        .map(|e| {
            let mut value = e.current();
            let http_request = e.canonical["httpRequest"].clone();
            if http_request.get("specUrlOrPayload").is_some() && let Some(definition) = http_request.as_object() && let Ok(matchers) = crate::openapi::request_matchers(definition) {
                // `HttpRequest`'s own property order, whatever order the operation's parameters came in.
                const ORDER: &[&str] = &[
                    "not", "method", "path", "pathParameters", "queryStringParameters", "headers", "cookies", "keepAlive", "secure",
                    "body",
                ];
                let matchers = matchers
                    .into_iter()
                    .map(|matcher| match matcher {
                        Value::Object(map) => {
                            let mut entries: Vec<(String, Value)> = map.into_iter().collect();
                            entries.sort_by_key(|(k, _)| ORDER.iter().position(|o| o == k).unwrap_or(ORDER.len()));
                            Value::Object(entries.into_iter().collect())
                        }
                        other => other,
                    })
                    .collect();
                if let Some(Value::Object(request)) = value.get_mut("httpRequest") {
                    request.insert("requestMatchers".into(), Value::Array(matchers));
                }
            }
            ActiveExpectation { id: e.id.clone(), http_request, value }
        })
        .collect();
    build_frame_with(entries, expectations, state.config.redact_secrets_in_log())
}

/// Is this the request `DashboardWebSocketHandler` takes over: exactly the push channel's URI (a query string makes it
/// another URI, which the proxy path then treats as any WebSocket upgrade).
pub fn is_channel(request: &HttpRequest) -> bool {
    request.path == PATH && request.raw_query.is_none() && request.query.is_empty()
}

/// How the upgrade request fares with Netty's handshaker factory.
enum Handshake {
    /// Version 7, 8 or 13.
    Accepted,
    /// `sendUnsupportedVersionResponse`.
    UnsupportedVersion,
    /// An exception: logged, then the channel closes without an answer.
    Rejected(String),
}

fn handshake(request: &HttpRequest) -> Handshake {
    let header = |name: &str| request.first_header(name).map(str::to_string);
    match header("sec-websocket-version").as_deref() {
        Some("13" | "8" | "7") => {}
        Some(_) => return Handshake::UnsupportedVersion,
        None => return Handshake::Rejected("WebSocketServerHandshakeException: not a WebSocket request: missing key".into()),
    }
    if !request.method.eq_ignore_ascii_case("GET") {
        return Handshake::Rejected(format!("WebSocketServerHandshakeException: Invalid WebSocket handshake method: {}", request.method));
    }
    let upgrade = header("upgrade").is_some_and(|u| u.eq_ignore_ascii_case("websocket"));
    let connection = request
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("connection"))
        .flat_map(|(_, values)| values)
        .any(|c| c.to_ascii_lowercase().contains("upgrade"));
    if !upgrade || !connection {
        return Handshake::Rejected("WebSocketServerHandshakeException: not a WebSocket handshake request: missing upgrade".into());
    }
    if header("sec-websocket-key").is_none() {
        return Handshake::Rejected("WebSocketServerHandshakeException: not a WebSocket request: missing key".into());
    }
    Handshake::Accepted
}

/// The first lines of a Jackson exception's stack trace: its (shaded) class and message.
fn jackson_trace(error: &jackson::JacksonError) -> String {
    format!("shaded_package.{}: {}", error.class, error.message)
}

/// `HttpRequestSerializer.deserialize` of a client's text frame: the request matcher it names, or the message of the
/// `IllegalArgumentException` upstream sends back as `{"error": …}`. `Ok(None)` is a frame upstream answers with
/// nothing at all (not JSON).
pub(crate) fn parse_filter(state: &State, text: &str) -> Result<Option<Value>, String> {
    const SPECIFICATION: &str = "OpenAPI Specification: https://app.swaggerhub.com/apis/jamesdbloom/mock-server-openapi/9.2.x\nDocumentation: https://mock-server.com/mock_server/creating_expectations.html";
    if text.trim().is_empty() {
        return Err(format!("1 error:\n - a request is required but value was \"{text}\"\n\n{SPECIFICATION}"));
    }
    let mut body = text.to_string();
    if body.contains("\"httpRequest\"") {
        match crate::jnode::read_tree(&body) {
            Ok(tree) => {
                if let Some(inner) = tree.get("httpRequest") {
                    body = inner.to_string();
                }
            }
            Err(e) => {
                // `HttpRequestSerializer.deserialize` logs the Jackson exception (as an ERROR entry with it as the throwable).
                let entry = crate::recorded::LogEntry::at(crate::recorded::Level::Error, format!("exception while parsing{{}}for HttpRequest {}", e.message))
                    .args([body.as_str()])
                    .throwable(jackson_trace(&e));
                crate::log::error_event(state, entry);
                return Err(format!("exception while parsing [{body}] for HttpRequest"));
            }
        }
    }
    // `JsonSchemaValidator.isValid` reports a body that is not JSON as `<exception class> - <message>`.
    if let Err(e) = crate::jnode::read_tree(&body) {
        // `JsonSchemaValidator.isValid` logs what it throws.
        crate::log::error_event(state, crate::recorded::LogEntry::at(crate::recorded::Level::Error, "exception validating JSON").throwable(jackson_trace(&e)));
        let class = e.class.rsplit('.').next().unwrap_or_default();
        return Err(crate::schema::incorrect_request(&body, &format!("{class} - {}", e.message)));
    }
    let Ok(value) = crate::json::parse_lenient(body.as_bytes()) else {
        return Ok(None);
    };
    match crate::schema::validate_http_message(&value, false) {
        Ok(()) => Ok(Some(value)),
        Err(report) => Err(crate::schema::incorrect_request(&body, &report)),
    }
}

/// How long the pushes of one connection are held apart (upstream's semaphore hands out one permit a second), and how
/// often a connection looks again without having been told of a change, which only matters for the one change nobody
/// announces: an expectation reaching its time to live.
///
/// Deliberate differences from upstream, all of them its own timing races (observed against the oracle):
/// its first frame comes 0.1 to 1.4 s after the upgrade or never (the semaphore and a one-slot `DiscardOldest`
/// scheduler queue drop it), a reply to a client's message is dropped when it lands within a second of the previous
/// frame and its retries (200 ms, three times) miss the next permit. A client cannot depend on either, so this
/// server always sends the first frame (100 ms after the upgrade, `registerListeners`) and answers every message.
const THROTTLE: Duration = Duration::from_secs(1);
const FALLBACK: Duration = Duration::from_secs(1);

/// Takes over `stream` for a dashboard upgrade request (`DashboardWebSocketHandler.channelRead`). Returns when the
/// connection ends.
pub async fn serve<S>(state: Arc<State>, request: &HttpRequest, mut stream: S)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // `ControlPlaneWebSocketUpgradeGate.originAllowed`, before authentication
    if !crate::cors_origin::upgrade_origin_allowed(&state, request, "dashboard UI", &mut stream).await {
        return;
    }
    if let Some((status, _)) = crate::auth::control_plane_rejection(&state, request) {
        if state.info_enabled() {
            let entry = crate::recorded::LogEntry::new(
                crate::recorded::Kind::AuthenticationFailed,
                "dashboard UI web socket upgrade rejected with status {} - control plane authentication required",
            )
            .args([status.to_string()]);
            state.log.message(entry);
        }
        let reason = if status == 403 { "Forbidden" } else { "Unauthorized" };
        let _ = stream.write_all(format!("HTTP/1.1 {status} {reason}\r\ncontent-length: 0\r\n\r\n").as_bytes()).await;
        let _ = stream.shutdown().await;
        return;
    }
    match handshake(request) {
        Handshake::UnsupportedVersion => {
            let _ = stream.write_all(b"HTTP/1.1 426 Upgrade Required\r\nsec-websocket-version: 13\r\ncontent-length: 0\r\n\r\n").await;
            // The connection stays open, as Netty leaves it.
            let mut sink = [0u8; 1024];
            while matches!(tokio::io::AsyncReadExt::read(&mut stream, &mut sink).await, Ok(n) if n > 0) {}
            return;
        }
        Handshake::Rejected(message) => {
            caught(&state, &message);
            let _ = stream.shutdown().await;
            return;
        }
        Handshake::Accepted => {}
    }
    let accept = derive_accept_key(request.first_header("sec-websocket-key").unwrap_or_default().as_bytes());
    let head = format!("HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\nconnection: upgrade\r\nsec-websocket-accept: {accept}\r\n\r\n");
    if stream.write_all(head.as_bytes()).await.is_err() {
        return;
    }
    let ws = WebSocketStream::from_raw_socket(stream, Role::Server, None).await;
    let (mut sink, mut source) = ws.split();
    let mut filter: Option<Value> = None;
    let mut last_sent: Option<u64> = None;
    let mut last_push = tokio::time::Instant::now() - THROTTLE;
    // When the next frame is due, if a change is waiting to be pushed. The first one follows the upgrade by 100 ms
    // (`registerListeners`), unless the client has asked for one by then.
    let mut due: Option<tokio::time::Instant> = Some(tokio::time::Instant::now() + Duration::from_millis(100));
    let mut fallback = tokio::time::interval_at(tokio::time::Instant::now() + FALLBACK, FALLBACK);
    fallback.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut log_changes = state.log.changes.subscribe();
    let mut store_changes = state.store.changes.subscribe();
    let mut closing = state.closing.subscribe();
    // frames are read and written on the connection's event loop, which a runtime LLM call may block
    let worker = crate::server::current_worker();
    let connections = &state.connections;
    let loop_free = || async move {
        if let Some(event_loop) = worker {
            connections.loop_free(event_loop).await;
        }
    };
    loop {
        // A change is pushed at once, or as soon as the connection's one frame a second allows.
        macro_rules! schedule {
            () => {
                if due.is_none() {
                    due = Some((tokio::time::Instant::now()).max(last_push + THROTTLE));
                }
            };
        }
        tokio::select! {
            _ = tokio::time::sleep_until(due.unwrap_or_else(tokio::time::Instant::now)), if due.is_some() => {
                due = None;
                loop_free().await;
                let text = frame_text(&frame_for(&state, filter.as_ref()), false);
                let digest = digest(&text);
                if last_sent != Some(digest) {
                    if sink.send(Message::text(text)).await.is_err() {
                        break;
                    }
                    last_sent = Some(digest);
                    last_push = tokio::time::Instant::now();
                }
            }
            _ = log_changes.changed() => schedule!(),
            _ = store_changes.changed() => schedule!(),
            _ = fallback.tick() => schedule!(),
            changed = closing.changed() => {
                if changed.is_err() || *closing.borrow() {
                    break;
                }
            }
            incoming = source.next() => {
                loop_free().await;
                match incoming {
                    Some(Ok(Message::Text(text))) => match parse_filter(&state, &text) {
                        Ok(Some(request)) => {
                            filter = if request.as_object().is_some_and(|o| o.is_empty()) { None } else { Some(request) };
                            let text = frame_text(&frame_for(&state, filter.as_ref()), false);
                            last_sent = Some(digest(&text));
                            last_push = tokio::time::Instant::now();
                            if sink.send(Message::text(text)).await.is_err() {
                                break;
                            }
                        }
                        Ok(None) => {}
                        Err(message) => {
                            // Upstream answers a bad matcher with the error alone; a frame follows only when the log changed
                            // (the entry `parse_filter` logs for an unreadable matcher).
                            if sink.send(Message::text(json!({"error": message}).to_string())).await.is_err() {
                                break;
                            }
                        }
                    },
                    Some(Ok(Message::Ping(payload))) => {
                        let _ = sink.send(Message::Pong(payload)).await;
                    }
                    Some(Ok(Message::Close(frame))) => {
                        let _ = sink.send(Message::Close(frame)).await;
                        break;
                    }
                    // A binary or pong frame is `UnsupportedOperationException`: logged, and the channel closes.
                    Some(Ok(Message::Binary(_) | Message::Pong(_) | Message::Frame(_))) => {
                        caught(&state, "UnsupportedOperationException: frame types not supported");
                        break;
                    }
                    Some(Err(_)) | None => break,
                }
            }
        }
    }
}

fn digest(text: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    text.hash(&mut hasher);
    hasher.finish()
}

/// `exceptionCaught`: an ERROR entry naming the exception (upstream's carries its Java stack trace too).
fn caught(state: &State, exception: &str) {
    let entry = crate::recorded::LogEntry::new(crate::recorded::Kind::Error, "web socket server caught exception").text("web socket server caught exception");
    let _ = exception;
    state.log.message(entry);
}
