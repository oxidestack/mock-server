//! Typed event-log entries (`org.mockserver.log.model.LogEntry`): what `retrieve?format=LOG_ENTRIES` serialises.
//!
//! Every entry keeps its type, level, attached request(s), response and expectation, message format and arguments,
//! alongside the text `retrieve?type=LOGS` prints (`getMessage`, the format filled with the arguments' `toString`).

use chrono::{DateTime, Local};
use serde_json::{Map, Value};

use crate::request::HttpRequest;

/// A JSON value an entry holds, shared rather than copied: an entry's request is mostly its first argument
/// too, its expectation its second, and a request's matched and response entries carry the same logged request. A
/// `serde_json::Value` of a small request is ~10 times its text, so each copy was ~4 KB of the event log.
///
/// A request's logged form may also be built on first read ([`Json::logged_request`]): it keeps the request, so an
/// entry nobody reads (the event log's usual fate at WARN or on the matched path) never pays for the rendering, and a
/// console line quoting it writes its text straight from the request ([`Json::write_text`]).
pub struct Json(std::sync::Arc<JsonCell>);

struct JsonCell {
    value: std::sync::OnceLock<Value>,
    /// The request whose logged form ([`crate::recorded::logged`]) the value is, rendered from it when first read.
    request: Option<std::sync::Arc<HttpRequest>>,
    /// Known, without rendering it, to be a request `CredentialRedaction.forLog` leaves as it is (not a control-plane
    /// request), so attaching it to an entry need not read it.
    credential_free: bool,
}

impl Json {
    pub fn new(value: Value) -> Json {
        let cell = std::sync::OnceLock::new();
        let _ = cell.set(value);
        Json(std::sync::Arc::new(JsonCell { value: cell, request: None, credential_free: false }))
    }

    /// [`crate::recorded::logged`] of `request`, rendered the first time it is read; `credential_free` when the request
    /// is known to carry nothing `CredentialRedaction.forLog` masks.
    pub fn logged_request(request: std::sync::Arc<HttpRequest>, credential_free: bool) -> Json {
        Json(std::sync::Arc::new(JsonCell { value: std::sync::OnceLock::new(), request: Some(request), credential_free }))
    }

    /// [`crate::recorded::log_value`] of the value, appended to `out`: a request's logged form nothing has rendered is
    /// written straight from the request, and stays unrendered.
    pub fn write_text(&self, out: &mut String) {
        match (self.0.value.get(), &self.0.request) {
            (None, Some(request)) => crate::recorded::logged_text_into(out, request),
            _ => crate::recorded::log_value_into(out, self),
        }
    }

    /// See [`Json::logged_request`].
    pub fn is_credential_free(&self) -> bool {
        self.0.credential_free
    }

    /// The value, copied only while another entry still shares it.
    pub fn unwrap_or_clone(json: Json) -> Value {
        (*json).clone()
    }

    /// Whether the value exists already: a lazy one nobody has read does not, and comparing it would render it.
    pub fn is_rendered(&self) -> bool {
        self.0.value.get().is_some()
    }

    pub fn ptr_eq(a: &Json, b: &Json) -> bool {
        std::sync::Arc::ptr_eq(&a.0, &b.0)
    }
}

impl Clone for Json {
    fn clone(&self) -> Json {
        Json(self.0.clone())
    }
}

impl std::ops::Deref for Json {
    type Target = Value;
    fn deref(&self) -> &Value {
        self.0.value.get_or_init(|| self.0.request.as_deref().map_or(Value::Null, crate::recorded::logged))
    }
}

impl std::fmt::Debug for Json {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        (**self).fmt(f)
    }
}

impl PartialEq for Json {
    fn eq(&self, other: &Json) -> bool {
        **self == **other
    }
}

impl From<Value> for Json {
    fn from(value: Value) -> Json {
        Json::new(value)
    }
}

/// `org.slf4j.event.Level`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Level {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl Level {
    pub fn name(self) -> &'static str {
        match self {
            Level::Trace => "TRACE",
            Level::Debug => "DEBUG",
            Level::Info => "INFO",
            Level::Warn => "WARN",
            Level::Error => "ERROR",
        }
    }

    /// `LogMessageType.valueOf(logLevel.name())`: the type an entry gets when none was set.
    fn kind(self) -> Kind {
        match self {
            Level::Trace => Kind::Trace,
            Level::Debug => Kind::Debug,
            Level::Info => Kind::Info,
            Level::Warn => Kind::Warn,
            Level::Error => Kind::Error,
        }
    }
}

/// `LogEntry.LogMessageType`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
    Exception,
    Cleared,
    Retrieved,
    UpdatedExpectation,
    CreatedExpectation,
    RemovedExpectation,
    ReceivedRequest,
    ExpectationResponse,
    ExpectationMatched,
    ExpectationNotMatched,
    NoMatchResponse,
    Verification,
    VerificationFailed,
    VerificationPassed,
    ForwardedRequest,
    OpenapiRequestValidationFailed,
    OpenapiResponseValidationFailed,
    TemplateGenerated,
    ServerConfiguration,
    AuthenticationFailed,
    TemplateGenerationFailed,
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Kind::Trace => "TRACE",
            Kind::Debug => "DEBUG",
            Kind::Info => "INFO",
            Kind::Warn => "WARN",
            Kind::Error => "ERROR",
            Kind::Exception => "EXCEPTION",
            Kind::Cleared => "CLEARED",
            Kind::Retrieved => "RETRIEVED",
            Kind::UpdatedExpectation => "UPDATED_EXPECTATION",
            Kind::CreatedExpectation => "CREATED_EXPECTATION",
            Kind::RemovedExpectation => "REMOVED_EXPECTATION",
            Kind::ReceivedRequest => "RECEIVED_REQUEST",
            Kind::ExpectationResponse => "EXPECTATION_RESPONSE",
            Kind::ExpectationMatched => "EXPECTATION_MATCHED",
            Kind::ExpectationNotMatched => "EXPECTATION_NOT_MATCHED",
            Kind::NoMatchResponse => "NO_MATCH_RESPONSE",
            Kind::Verification => "VERIFICATION",
            Kind::VerificationFailed => "VERIFICATION_FAILED",
            Kind::VerificationPassed => "VERIFICATION_PASSED",
            Kind::ForwardedRequest => "FORWARDED_REQUEST",
            Kind::OpenapiRequestValidationFailed => "OPENAPI_REQUEST_VALIDATION_FAILED",
            Kind::OpenapiResponseValidationFailed => "OPENAPI_RESPONSE_VALIDATION_FAILED",
            Kind::TemplateGenerated => "TEMPLATE_GENERATED",
            Kind::ServerConfiguration => "SERVER_CONFIGURATION",
            Kind::AuthenticationFailed => "AUTHENTICATION_FAILED",
            Kind::TemplateGenerationFailed => "TEMPLATE_GENERATION_FAILED",
        }
    }
}

/// One message argument: its JSON (as `LogEntrySerializer` writes `arguments`); its text in the message follows from the
/// JSON and [`Arg::shape`] when the message is read, not when the argument is made.
pub struct Arg {
    pub json: Json,
    /// Not a `String` or `NottableString` upstream (a socket address): the dashboard shows it as JSON (`json: true`),
    /// with this value, though the log's JSON writes it as text.
    pub object: Option<String>,
    /// How the argument's text follows from [`Arg::json`] (see [`ArgText::plain`]), which a redacted render also uses.
    pub shape: ArgText,
}

/// How an argument's text in the message follows from its JSON.
#[derive(Clone, Debug)]
pub enum ArgText {
    /// [`crate::recorded::log_value`] of the JSON.
    Json,
    /// A text of its own (scrubbed, not re-rendered, under `redactSecretsInLog`).
    Custom(String),
    /// A `java.util.List`: `[a, b]` of each element's text, the JSON an array.
    List(Vec<ArgText>),
    /// `SensitiveLogValue` (upstream c76143e4a): a payload logged with no request to redact it against, such
    /// as a binary request's hex dump. Under `redactSecretsInLog` the argument is the placeholder and this text is
    /// scrubbed from the rest of the entry.
    Sensitive(String),
}

impl ArgText {
    /// The argument's text from its (possibly redacted) JSON.
    fn render(&self, json: &Value, redaction: &crate::log_redaction::Redaction) -> String {
        match self {
            ArgText::Json => crate::recorded::log_value(json),
            ArgText::Custom(text) => redaction.scrub(text),
            ArgText::List(items) => {
                let empty = Vec::new();
                let elements = json.as_array().unwrap_or(&empty);
                let texts: Vec<String> = items.iter().enumerate().map(|(i, item)| item.render(elements.get(i).unwrap_or(&Value::Null), redaction)).collect();
                format!("[{}]", texts.join(", "))
            }
            ArgText::Sensitive(_) => crate::recorded::LOG_REDACTED.to_string(),
        }
    }

    /// The argument's text from its JSON, unredacted.
    fn plain(&self, json: &Value) -> String {
        match self {
            ArgText::Json => crate::recorded::log_value(json),
            ArgText::Custom(text) | ArgText::Sensitive(text) => text.clone(),
            ArgText::List(items) => {
                let empty = Vec::new();
                let elements = json.as_array().unwrap_or(&empty);
                let texts: Vec<String> = items.iter().enumerate().map(|(i, item)| item.plain(elements.get(i).unwrap_or(&Value::Null))).collect();
                format!("[{}]", texts.join(", "))
            }
        }
    }

    /// [`ArgText::plain`] appended to `out`.
    fn plain_into(&self, json: &Json, out: &mut String) {
        match self {
            ArgText::Json => json.write_text(out),
            other => other.plain_value_into(json, out),
        }
    }

    /// [`ArgText::plain_into`] of a value.
    fn plain_value_into(&self, json: &Value, out: &mut String) {
        match self {
            ArgText::Json => crate::recorded::log_value_into(out, json),
            ArgText::Custom(text) | ArgText::Sensitive(text) => out.push_str(text),
            ArgText::List(items) => {
                let elements = json.as_array().map_or(&[][..], Vec::as_slice);
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push_str(", ");
                    }
                    item.plain_value_into(elements.get(i).unwrap_or(&Value::Null), out);
                }
                out.push(']');
            }
        }
    }
}

impl Arg {
    /// An argument whose `toString` is not its JSON.
    pub fn with_text(json: Value, text: impl Into<String>) -> Arg {
        Arg { json: Json::new(json), shape: ArgText::Custom(text.into()), object: None }
    }

    /// A `java.util.List` argument: its text is `AbstractCollection.toString` (`[a, b]` of each element's text), its
    /// JSON the array.
    pub fn list(items: Vec<Arg>) -> Arg {
        let shape = ArgText::List(items.iter().map(|a| a.shape.clone()).collect());
        Arg { json: Json::new(Value::Array(items.into_iter().map(|a| Json::unwrap_or_clone(a.json)).collect())), object: None, shape }
    }

    /// `SensitiveLogValue.of(text)`: shown as it is, or as the placeholder under `redactSecretsInLog`.
    pub fn sensitive(text: impl Into<String>) -> Arg {
        let text = text.into();
        Arg { json: Json::new(Value::String(text.clone())), shape: ArgText::Sensitive(text), object: None }
    }

    /// A socket address (`InetSocketAddress`) that the log writes as `host:port`, which is also how Jackson writes it.
    pub fn socket_address(address: impl std::fmt::Display) -> Arg {
        let text = address.to_string();
        Arg { json: Json::new(Value::String(text.clone())), object: Some(text), shape: ArgText::Json }
    }

    /// An `InetSocketAddress` the log keeps as the object: its `toString` (`/ip:port`) in the text, and Jackson's
    /// `ip:port` both in the entry's JSON arguments and on the dashboard (`ClientTlsHandshakeFailureLog`'s client,
    /// read off the oracle).
    pub fn inet_socket_address(text: impl Into<String>, json: impl Into<String>) -> Arg {
        let (text, json) = (text.into(), json.into());
        Arg { json: Json::new(Value::String(json.clone())), shape: ArgText::Custom(text), object: Some(json) }
    }

    /// An enum constant (a `DnsRecordType`, say) that the log writes by name: not a `String` upstream, so the dashboard
    /// shows it as JSON (`json: true`), whose value is that name too.
    pub fn enum_name(name: impl Into<String>) -> Arg {
        let text = name.into();
        Arg { json: Json::new(Value::String(text.clone())), object: Some(text), shape: ArgText::Json }
    }

    /// A socket address whose log text is `text` (`InetSocketAddress.toString`, `host/ip:port`) and whose Jackson
    /// form, which the dashboard shows, is `dashboard` (`host:port`).
    pub fn socket_address_as(text: impl Into<String>, dashboard: impl Into<String>) -> Arg {
        let text = text.into();
        Arg { json: Json::new(Value::String(text.clone())), shape: ArgText::Custom(text), object: Some(dashboard.into()) }
    }
}

impl From<Value> for Arg {
    fn from(json: Value) -> Arg {
        Arg::from(Json::new(json))
    }
}

impl From<Json> for Arg {
    fn from(json: Json) -> Arg {
        Arg { json, object: None, shape: ArgText::Json }
    }
}

impl From<&Value> for Arg {
    fn from(json: &Value) -> Arg {
        Arg::from(json.clone())
    }
}

impl From<&str> for Arg {
    fn from(text: &str) -> Arg {
        Arg { json: Json::new(Value::String(text.to_string())), object: None, shape: ArgText::Json }
    }
}

impl From<String> for Arg {
    fn from(text: String) -> Arg {
        Arg { json: Json::new(Value::String(text)), object: None, shape: ArgText::Json }
    }
}

impl From<&&str> for Arg {
    fn from(text: &&str) -> Arg {
        Arg::from(*text)
    }
}

impl From<&String> for Arg {
    fn from(text: &String) -> Arg {
        Arg::from(text.as_str())
    }
}

/// A value the entry holds by reference, serialised as it is when the log is read (upstream logs the live
/// `Expectation`, whose remaining times go on changing after the message was formatted).
#[derive(Clone)]
pub struct Live(pub std::sync::Arc<dyn Fn() -> Value + Send + Sync>);

impl std::fmt::Debug for Live {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Live")
    }
}

/// Arguments that are live objects upstream (a `Configuration` set), rendered when the log is first read and kept as
/// rendered then (`LogEntry.getMessage` memoises a message that quotes no request or response); or, when they quote a
/// request or response (`quotesHttpMessage`), rendered again on every read.
#[derive(Clone)]
pub struct LiveArguments {
    render: std::sync::Arc<dyn Fn() -> Vec<(usize, Arg)> + Send + Sync>,
    rendered: std::sync::Arc<std::sync::OnceLock<Vec<(usize, Json, ArgText)>>>,
    memoised: bool,
}

impl std::fmt::Debug for LiveArguments {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LiveArguments")
    }
}

/// What an entry's message and compact form are built from, kept until something reads them: the format
/// and the arguments' JSON and shapes as [`LogEntry::args`] saw them. Most entries are never read as text (a request's
/// `returning response` entry below the console's level is only ever retrieved as JSON), and pretty-printing a request,
/// a response and an expectation per request was most of the data plane's allocation. Clones of an entry share it, and
/// so the text one of them renders.
#[derive(Debug)]
pub struct Pending {
    format: String,
    arguments: Vec<Json>,
    shapes: Vec<ArgText>,
    texts: std::sync::OnceLock<Vec<String>>,
    text: std::sync::OnceLock<String>,
    compact: std::sync::OnceLock<Vec<String>>,
}

impl Pending {
    /// Each argument's text, [`ArgText::plain`] of its JSON.
    fn texts(&self) -> &[String] {
        self.texts.get_or_init(|| self.arguments.iter().enumerate().map(|(i, a)| self.shapes.get(i).unwrap_or(&ArgText::Json).plain(a)).collect())
    }

    fn text(&self) -> &str {
        self.text.get_or_init(|| {
            let refs: Vec<&str> = self.texts().iter().map(String::as_str).collect();
            crate::matcher::format_log_message(0, &self.format, &refs)
        })
    }

    /// [`Pending::text`] appended to `out`, each argument rendered into `scratch` and copied from there: the text is
    /// not kept, so printing an entry leaves it as small as an entry nothing read.
    fn write_text(&self, out: &mut String, scratch: &mut String) {
        if let Some(text) = self.text.get() {
            return out.push_str(text);
        }
        let texts = self.texts.get();
        crate::matcher::format_log_message_into(out, 0, &self.format, self.arguments.len(), |i, write| match texts {
            Some(texts) => write(&texts[i]),
            None => {
                scratch.clear();
                self.shapes.get(i).unwrap_or(&ArgText::Json).plain_into(&self.arguments[i], scratch);
                write(scratch);
            }
        });
    }

    fn compact(&self) -> &[String] {
        self.compact.get_or_init(|| {
            let parts = java_split_placeholders(&self.format);
            self.arguments.iter().zip(self.texts()).enumerate().map(|(i, (a, text))| compact_argument(parts.get(i).copied().unwrap_or(""), a, text)).collect()
        })
    }
}

/// [`LogEntry::message_text`]'s source: a text of its own, or the one the arguments make.
#[derive(Clone, Debug)]
enum MessageText {
    Own(String),
    Pending(std::sync::Arc<Pending>),
}

/// [`LogEntry::compact_arguments`]'s source.
#[derive(Clone, Debug)]
enum CompactArguments {
    Own(Vec<String>),
    Pending(std::sync::Arc<Pending>),
}

impl CompactArguments {
    fn get(&self) -> &[String] {
        match self {
            CompactArguments::Own(own) => own,
            CompactArguments::Pending(pending) => pending.compact(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct LogEntry {
    pub level: Level,
    pub kind: Kind,
    pub correlation_id: Option<String>,
    /// `httpRequests`: `None` when no request was set (no field), one (`httpRequest`) or several (`httpRequests`).
    pub requests: Option<Vec<Json>>,
    pub response: Option<Json>,
    pub error: Option<Value>,
    pub expectation: Option<Json>,
    pub expectation_id: Option<String>,
    pub format: String,
    pub arguments: Option<Vec<Json>>,
    /// The arguments that are objects upstream although their JSON is text ([`Arg::object`]): index and dashboard value.
    pub object_arguments: Vec<(usize, String)>,
    /// `StringFormatter.toCompactString` of each argument, for the console under `compactLogFormat`.
    compact_arguments: Option<CompactArguments>,
    /// `getThrowable()`, as the lines of its stack trace (`ExceptionUtils.getStackTrace`). Only the dashboard shows it:
    /// the log's JSON would write the whole bean, JVM frames included, which cannot be reproduced.
    pub throwable: Option<Vec<String>>,
    /// The throwable's JSON bean when its message spans lines or its cause has properties of its own, which the
    /// lines of [`LogEntry::throwable`] cannot say.
    pub throwable_bean: Option<Value>,
    pub because: Option<String>,
    /// `getMessage()`: the format filled with the arguments' texts ([`LogEntry::message_text`]).
    text: MessageText,
    /// How each argument's text follows from its JSON ([`LogEntry::args`]), for a redacted render.
    pub arg_shapes: Option<Vec<ArgText>>,
    /// [`LogEntry::text`] was set by itself, not formatted from the arguments.
    pub text_custom: bool,
    /// A redacted render's redaction, for the argument [`LogEntry::live`] replaces when serialised.
    pub redaction: Option<std::sync::Arc<crate::log_redaction::Redaction>>,
    /// Logged from the event log's own thread (verification results), which stamps no port on it.
    pub portless: bool,
    /// The expectation held live: it replaces `expectation` and the argument at the index when serialised.
    pub live: Option<(Live, Option<usize>)>,
    /// `expectationIsSynthetic`: the expectation is the one a forwarded exchange derives from its own request and
    /// response (`setExpectation(request, response)`), which `LOG_ENTRIES` writes without their bodies.
    pub synthetic_expectation: bool,
    /// [`LogEntry::own_compact`] taken before a redacted render redacted the arguments (and scrubbed), which then no
    /// longer equal the entry's own request and response.
    pub own_compact_fixed: Option<Option<Vec<Option<String>>>>,
    /// Arguments that are the entry's own request although no `httpRequest` shows it (a binary request definition,
    /// which the log's JSON writes `null`): quoted as `String.valueOf` of it, compacted.
    pub own_arguments: Vec<usize>,
    /// Arguments equal to the entry's own request or response that upstream logs as another object of the same value
    /// (`setHttpResponse(notFoundResponse())` with `setArguments(request, notFoundResponse())`): quoted in full.
    pub other_arguments: Vec<usize>,
    /// See [`LiveArguments`]; [`LogEntry::settled`] puts them in place.
    pub live_arguments: Option<LiveArguments>,
    /// `HttpRequest.maskedCredentialValues` of the control-plane requests the entry holds without their credentials
    /// ([`crate::credential_redaction`]): scrubbed from its other text under `redactSecretsInLog`.
    pub masked_values: Vec<String>,
}

impl LogEntry {
    /// An INFO entry of `kind` (an entry of a level's own kind takes that level).
    pub fn new(kind: Kind, format: impl Into<String>) -> LogEntry {
        let format = format.into();
        let level = match kind {
            Kind::Trace => Level::Trace,
            Kind::Debug => Level::Debug,
            Kind::Warn => Level::Warn,
            Kind::Error | Kind::Exception => Level::Error,
            _ => Level::Info,
        };
        LogEntry {
            level,
            kind,
            correlation_id: None,
            requests: None,
            response: None,
            error: None,
            expectation: None,
            expectation_id: None,
            text: MessageText::Own(format.clone()),
            arg_shapes: None,
            text_custom: false,
            redaction: None,
            format,
            arguments: None,
            object_arguments: Vec::new(),
            compact_arguments: None,
            throwable: None,
            throwable_bean: None,
            because: None,
            portless: false,
            live: None,
            synthetic_expectation: false,
            own_compact_fixed: None,
            own_arguments: Vec::new(),
            other_arguments: Vec::new(),
            live_arguments: None,
            masked_values: Vec::new(),
        }
    }

    /// An entry with no type of its own (`setLogLevel` only): its type is the level's.
    pub fn at(level: Level, format: impl Into<String>) -> LogEntry {
        LogEntry::new(level.kind(), format).level(level)
    }

    pub fn level(mut self, level: Level) -> LogEntry {
        self.level = level;
        self
    }

    pub fn kind(mut self, kind: Kind) -> LogEntry {
        self.kind = kind;
        self
    }

    /// `setHttpRequest(request)`: the request as log lines show it, and its correlation id.
    pub fn request(self, request: &HttpRequest) -> LogEntry {
        let id = (!request.log_correlation_id.is_empty()).then(|| request.log_correlation_id.clone());
        let mut entry = self.request_json(crate::recorded::logged(request));
        if id.is_some() {
            entry.correlation_id = id;
        }
        entry
    }

    /// [`LogEntry::request`] with the request's logged form already built.
    pub fn request_logged(self, request: &HttpRequest, logged: &crate::recorded::LoggedRequest) -> LogEntry {
        let id = (!request.log_correlation_id.is_empty()).then(|| request.log_correlation_id.clone());
        let mut entry = self.request_shared(logged.json.clone());
        if id.is_some() {
            entry.correlation_id = id;
        }
        entry
    }

    /// `setHttpRequest(definition)` for a request definition (a matcher, a filter).
    pub fn request_json(self, request: Value) -> LogEntry {
        self.request_shared(Json::new(request))
    }

    /// [`LogEntry::request_json`] with a request JSON other entries (or this entry's arguments) hold too.
    pub fn request_shared(mut self, request: Json) -> LogEntry {
        let request = self.for_log(request);
        self.requests = Some(vec![request]);
        self
    }

    /// `setHttpRequests(definitions)`.
    pub fn requests(mut self, requests: Vec<Value>) -> LogEntry {
        self.requests = Some(requests.into_iter().map(|r| self.for_log(Json::new(r))).collect());
        self
    }

    /// `CredentialRedaction.forLog`: a control-plane request the entry holds without its credentials, the values it
    /// masked remembered for `redactSecretsInLog`.
    fn for_log(&mut self, request: Json) -> Json {
        if request.is_credential_free() {
            return request;
        }
        match crate::credential_redaction::json_for_log(&request) {
            Some((masked, values)) => {
                self.masked_values.extend(values);
                Json::new(masked)
            }
            None => request,
        }
    }

    /// `setHttpRequest(null)`: the default `request()`, written `{ }`.
    pub fn default_request(self) -> LogEntry {
        self.request_json(Value::Object(Map::new()))
    }

    pub fn correlation(mut self, id: impl Into<String>) -> LogEntry {
        self.correlation_id = Some(id.into());
        self
    }

    pub fn response(mut self, response: Value) -> LogEntry {
        self.response = Some(Json::new(response));
        self
    }

    pub fn expectation(self, expectation: Value) -> LogEntry {
        self.expectation_shared(Json::new(expectation))
    }

    /// `setExpectation(request, response)`: the expectation derived from the entry's own request and response.
    pub fn synthetic_expectation(mut self, expectation: Value) -> LogEntry {
        self.synthetic_expectation = true;
        self.expectation(expectation)
    }

    /// [`LogEntry::expectation`] with an expectation JSON the entry's arguments hold too.
    pub fn expectation_shared(mut self, expectation: Json) -> LogEntry {
        self.expectation = Some(expectation);
        self
    }

    pub fn expectation_id(mut self, id: impl Into<String>) -> LogEntry {
        self.expectation_id = Some(id.into());
        self
    }

    pub fn because(mut self, because: impl Into<String>) -> LogEntry {
        self.because = Some(because.into());
        self
    }

    /// `setArguments(...)`: the message becomes the format filled with their texts (built when it is first read).
    pub fn args<A: Into<Arg>>(mut self, arguments: impl IntoIterator<Item = A>) -> LogEntry {
        let arguments: Vec<Arg> = arguments.into_iter().map(Into::into).map(|a| self.argument_for_log(a)).collect();
        self.object_arguments = arguments.iter().enumerate().filter_map(|(i, a)| a.object.clone().map(|value| (i, value))).collect();
        let shapes: Vec<ArgText> = arguments.iter().map(|a| a.shape.clone()).collect();
        let jsons: Vec<Json> = arguments.into_iter().map(|a| a.json).collect();
        let pending = std::sync::Arc::new(Pending {
            format: self.format.clone(),
            arguments: jsons.clone(),
            shapes: shapes.clone(),
            texts: Default::default(),
            text: Default::default(),
            compact: Default::default(),
        });
        self.text = MessageText::Pending(pending.clone());
        self.compact_arguments = Some(CompactArguments::Pending(pending));
        self.arg_shapes = Some(shapes);
        self.text_custom = false;
        self.arguments = Some(jsons);
        self
    }

    /// The message format, replaced before the arguments are set.
    pub fn with_format(mut self, format: String) -> LogEntry {
        self.format = format;
        self
    }

    /// `getMessage()`: the format filled with the arguments' texts.
    pub fn message_text(&self) -> &str {
        match &self.text {
            MessageText::Own(text) => text,
            MessageText::Pending(pending) => pending.text(),
        }
    }

    /// [`LogEntry::message_text`] appended to `out` without keeping it (`scratch` holds an argument's text on the way):
    /// what the console prints.
    pub fn write_message(&self, out: &mut String, scratch: &mut String) {
        match &self.text {
            MessageText::Own(text) => out.push_str(text),
            MessageText::Pending(pending) => pending.write_text(out, scratch),
        }
    }

    /// `StringFormatter.toCompactString` of each argument, when the entry has arguments.
    pub fn compact_arguments(&self) -> Option<&[String]> {
        self.compact_arguments.as_ref().map(CompactArguments::get)
    }

    /// `CredentialRedaction.argumentForLog`: a control-plane request argument without its credentials.
    fn argument_for_log(&mut self, argument: Arg) -> Arg {
        if !matches!(argument.shape, ArgText::Json) || argument.json.is_credential_free() {
            return argument;
        }
        match crate::credential_redaction::json_for_log(&argument.json) {
            Some((masked, values)) => {
                self.masked_values.extend(values);
                Arg::from(masked)
            }
            None => argument,
        }
    }

    /// This entry as it renders under `redactSecretsInLog` with these body fields (upstream cc7d7d185, c76143e4a,
    /// adopted after 8.0.0; `LogEntry.redactedView`): the arguments redacted (requests, responses, expectations and
    /// pairs field by field, free text scrubbed of the entry's credential values), the message re-formatted from the
    /// scrubbed format and those arguments (or, when it was set by itself, scrubbed), and the compact message,
    /// `because` and throwable scrubbed. The top-level `httpRequest(s)`/`httpResponse` are left to the serialiser's
    /// own redaction, and a real expectation stays as it is.
    pub fn redacted(&self, fields: &[String]) -> LogEntry {
        let requests: Vec<&Value> = self.requests.iter().flatten().map(|r| &**r).collect();
        let responses: Vec<&Value> = self.response.iter().map(|r| &**r).collect();
        let shapes = self.arg_shapes.clone().unwrap_or_else(|| vec![ArgText::Json; self.arguments.as_ref().map_or(0, Vec::len)]);
        let sensitive = |i: usize| matches!(shapes.get(i), Some(ArgText::Sensitive(_)));
        // a sensitive argument is no request or response to collect credentials from: its text is one
        let arguments: Vec<&Value> = self.arguments.iter().flatten().enumerate().filter(|(i, _)| !sensitive(*i)).map(|(_, a)| &**a).collect();
        let mut texts: Vec<&str> = self.masked_values.iter().map(String::as_str).collect();
        texts.extend(shapes.iter().filter_map(|s| if let ArgText::Sensitive(text) = s { Some(text.as_str()) } else { None }));
        let redaction = crate::log_redaction::Redaction::with_texts(fields, &requests, &responses, &arguments, &texts);
        let mut out = self.clone();
        // the compact form of the entry's own request or response, from the raw one, then scrubbed
        // (a binary definition's bytes masked first, `EventLogRedactor`)
        let masked = {
            let mask = |v: &Json| crate::recorded::masked_binary_definition(v).map(Json::new);
            let mut masked = self.clone();
            masked.requests = self.requests.as_ref().map(|rs| rs.iter().map(|r| mask(r).unwrap_or_else(|| r.clone())).collect());
            masked.arguments = self.arguments.as_ref().map(|args| args.iter().map(|a| mask(a).unwrap_or_else(|| a.clone())).collect());
            masked
        };
        out.own_compact_fixed = Some(masked.own_compact().map(|own| own.into_iter().map(|c| c.map(|c| redaction.scrub(&c))).collect()));
        out.format = redaction.scrub(&self.format);
        if let Some(args) = &self.arguments {
            let redacted: Vec<Value> = args
                .iter()
                .enumerate()
                .map(|(i, a)| if sensitive(i) { Value::String(crate::recorded::LOG_REDACTED.to_string()) } else { redaction.argument(a) })
                .collect();
            let texts: Vec<String> = redacted.iter().enumerate().map(|(i, v)| shapes.get(i).unwrap_or(&ArgText::Json).render(v, &redaction)).collect();
            if self.text_custom {
                out.text = MessageText::Own(redaction.scrub(self.message_text()));
            } else {
                let refs: Vec<&str> = texts.iter().map(String::as_str).collect();
                out.text = MessageText::Own(crate::matcher::format_log_message(0, &out.format, &refs));
            }
            if self.compact_arguments.is_some() {
                // each argument redacted before the compact form shortens it: a credential cut to a prefix would no
                // longer be recognised by the scrub
                let parts = java_split_placeholders(&out.format);
                out.compact_arguments = Some(CompactArguments::Own(redacted.iter().enumerate().map(|(i, v)| compact_argument(parts.get(i).copied().unwrap_or(""), v, &texts[i])).collect()));
            }
            out.object_arguments = self.object_arguments.iter().map(|(i, v)| (*i, redaction.scrub(v))).collect();
            out.arguments = Some(redacted.into_iter().map(Json::new).collect());
        } else {
            out.text = MessageText::Own(redaction.scrub(self.message_text()));
        }
        if self.kind == Kind::ForwardedRequest {
            // `getRedactedExpectation`: the synthetic expectation a forwarded exchange derives from its own request and
            // response is redacted too; a real one is a user-authored matcher and stays as it is
            out.expectation = self.expectation.as_ref().map(|e| Json::new(redaction.argument(e)));
        }
        out.because = self.because.as_ref().map(|b| redaction.scrub(b));
        out.throwable = self.throwable.as_ref().map(|lines| lines.iter().map(|l| redaction.scrub(l)).collect());
        out.throwable_bean = self.throwable_bean.as_ref().map(|b| scrub_strings(b, &redaction));
        out.redaction = Some(std::sync::Arc::new(redaction));
        out
    }

    /// `setThrowable(throwable)`: `trace` is Java's `printStackTrace` text, the exception first (`class: message`), then
    /// its frames. Nothing here has frames, so it is that first line.
    pub fn throwable(mut self, trace: impl AsRef<str>) -> LogEntry {
        self.throwable = Some(trace.as_ref().split('\n').map(str::to_string).collect());
        self
    }

    /// The JSON bean of the throwable, for the log's JSON in place of the one read from its lines.
    pub fn throwable_bean(mut self, bean: Value) -> LogEntry {
        self.throwable_bean = Some(bean);
        self
    }

    /// The expectation (and the argument at `argument`) serialised from `live` when the log is read.
    pub fn live_expectation(mut self, live: impl Fn() -> Value + Send + Sync + 'static, argument: Option<usize>) -> LogEntry {
        self.live = Some((Live(std::sync::Arc::new(live)), argument));
        self
    }

    /// `LogEntry.getCompactMessage`: the format with each argument's compact form, or (no arguments) the message.
    pub fn compact_text(&self) -> String {
        match &self.compact_arguments {
            Some(arguments) => compact_message(&self.format, arguments.get()),
            None => self.message_text().to_string(),
        }
    }

    /// `LogEntry.argumentOwnMessagePart`: per argument, `request` when it is the entry's own (first) request, `response`
    /// when it is its own response, else `None` (only those load whole through `GET /mockserver/logEntryBody`); `None`
    /// when no argument is. Upstream tells its own by identity, as [`LogEntry::own_compact`] does.
    pub fn own_message_parts(&self) -> Option<Vec<Option<&'static str>>> {
        let args = self.arguments.as_ref()?;
        let parts = java_split_placeholders(&self.format);
        let same = |a: &Json, b: &Json| !a.is_null() && (Json::ptr_eq(a, b) || **a == **b);
        let own: Vec<Option<&'static str>> = args
            .iter()
            .enumerate()
            .map(|(i, argument)| {
                let other = self.other_arguments.contains(&i) || java_trim(parts.get(i).copied().unwrap_or("")).ends_with("action:");
                if other {
                    None
                } else if self.response.as_ref().is_some_and(|r| same(r, argument)) {
                    Some("response")
                } else if self.own_arguments.contains(&i) || self.requests.as_ref().and_then(|r| r.first()).is_some_and(|r| same(r, argument)) {
                    Some("request")
                } else {
                    None
                }
            })
            .collect();
        own.iter().any(Option::is_some).then_some(own)
    }

    /// `LogEntry.serializedArgumentsFor`: per argument, its compact form when it is the entry's own request or response
    /// (`StringFormatter.toCompactString`: `POST /path`, `201`) or the curl command of its own request, which follows
    /// that request's `in json:{}` (`DeferredLogArgument.getRequest`); `None` when no argument is. Upstream tells its
    /// own by identity; an argument here is its own when it is the same JSON (shared or equal).
    pub fn own_compact(&self) -> Option<Vec<Option<String>>> {
        let args = self.arguments.as_ref()?;
        let parts = java_split_placeholders(&self.format);
        let same = |a: &Json, b: &Json| !a.is_null() && (Json::ptr_eq(a, b) || **a == **b);
        let mut own: Vec<Option<String>> = Vec::with_capacity(args.len());
        for (i, argument) in args.iter().enumerate() {
            // an action (`for action:{}`) is never the response it produced, whatever its value
            let other = self.other_arguments.contains(&i) || java_trim(parts.get(i).copied().unwrap_or("")).ends_with("action:");
            let compact = if other {
                None
            } else if self.response.as_ref().is_some_and(|r| same(r, argument)) {
                Some(argument.get("statusCode").and_then(Value::as_i64).map_or_else(|| "response".to_string(), |s| s.to_string()))
            } else if self.own_arguments.contains(&i) {
                let shape = self.arg_shapes.as_ref().and_then(|s| s.get(i)).unwrap_or(&ArgText::Json);
                Some(collapse_lines(&shape.plain(argument)))
            } else if self.requests.iter().flatten().any(|r| same(r, argument)) {
                Some(compact_request_json(argument))
            } else if i > 0 && java_trim(parts.get(i).copied().unwrap_or("")).ends_with("in curl:") {
                own[i - 1].clone().filter(|_| self.requests.iter().flatten().any(|r| same(r, &args[i - 1])))
            } else {
                None
            };
            own.push(compact);
        }
        own.iter().any(Option::is_some).then_some(own)
    }

    /// `LogEntry.boundQuotedBodies` (with `replaceQuoted`) under `maxLoggedBodyBytes` = `max`: `swaps` pairs each own
    /// request or response the log cut with its cut copy, which replaces the arguments equal to it (they stay the
    /// entry's own). Every other body the entry quotes is cut too (its own requests and response, a real expectation,
    /// expectation, request and response arguments), and the `because` and each text argument longer than `max` are
    /// cut ([`crate::recorded::cut_text`]); the message follows the cut arguments. A forward's derived expectation is
    /// derived again from the cut request and response.
    pub fn bound_quoted_bodies(&mut self, max: usize, swaps: &[(Value, Value)]) {
        use crate::recorded::{cut_expectation, cut_message, cut_text};
        let swapped = |v: &Value| swaps.iter().find(|(whole, _)| whole == v).map(|(_, cut)| cut.clone());
        // a copy already cut holds its bytes as base64 text, longer than they are, and is not cut again
        let already_cut = |v: &Value| swaps.iter().any(|(_, cut)| cut == v);
        let cut_message = |v: &Value, max: usize, typed: bool| if already_cut(v) { None } else { cut_message(v, max, typed) };
        for request in self.requests.iter_mut().flatten() {
            if let Some(cut) = swapped(request).or_else(|| cut_message(request, max, false)) {
                *request = Json::new(cut);
            }
        }
        if let Some(cut) = self.response.as_deref().and_then(|r| swapped(r).or_else(|| cut_message(r, max, false))) {
            self.response = Some(Json::new(cut));
        }
        if self.synthetic_expectation {
            if let (Some(expectation), Some([request])) = (&self.expectation, self.requests.as_deref()) {
                let mut derived = Value::clone(expectation);
                if let Some(o) = derived.as_object_mut() {
                    o.insert("httpRequest".into(), Value::clone(request));
                    if let Some(response) = &self.response {
                        o.insert("httpResponse".into(), Value::clone(response));
                    }
                }
                self.expectation = Some(Json::new(derived));
            }
        } else if let Some(cut) = self.expectation.as_deref().and_then(|e| cut_expectation(e, max)) {
            self.expectation = Some(Json::new(cut));
        }
        if let Some((Live(render), argument)) = self.live.take() {
            let render = move || {
                let expectation = render();
                cut_expectation(&expectation, max).unwrap_or(expectation)
            };
            self.live = Some((Live(std::sync::Arc::new(render)), argument));
        }
        if let Some(cut) = self.because.as_deref().and_then(|b| cut_text(b, max)) {
            self.because = Some(cut);
        }
        let Some(args) = self.arguments.as_mut() else { return };
        let parts: Vec<String> = java_split_placeholders(&self.format).into_iter().map(str::to_string).collect();
        let mut changed = false;
        for (i, argument) in args.iter_mut().enumerate() {
            let shape = self.arg_shapes.as_ref().and_then(|s| s.get(i));
            let cut = if let Some(cut) = swapped(argument) {
                Some(cut)
            } else {
                match &**argument {
                    Value::Object(o) if o.contains_key("httpRequest") && (o.contains_key("id") || o.contains_key("priority") || o.contains_key("times")) => {
                        cut_expectation(argument, max)
                    }
                    Value::Object(o) if !o.contains_key("httpRequest") => cut_message(argument, max, false),
                    // a text, not an object logged as one, a sensitive value or a request's curl command
                    Value::String(text)
                        if matches!(shape, None | Some(ArgText::Json))
                            && !self.object_arguments.iter().any(|(at, _)| *at == i)
                            && !self.own_arguments.contains(&i)
                            && !java_trim(parts.get(i).map(String::as_str).unwrap_or("")).ends_with("in curl:") =>
                    {
                        cut_text(text, max).map(Value::String)
                    }
                    _ => None,
                }
            };
            if let Some(cut) = cut {
                *argument = Json::new(cut);
                if let Some(slot) = self.arg_shapes.as_mut().and_then(|s| s.get_mut(i)) {
                    *slot = ArgText::Json;
                }
                changed = true;
            }
        }
        if changed && !self.text_custom {
            let shapes = self.arg_shapes.clone().unwrap_or_default();
            let texts: Vec<String> = args.iter().enumerate().map(|(i, a)| shapes.get(i).unwrap_or(&ArgText::Json).plain(a)).collect();
            let refs: Vec<&str> = texts.iter().map(String::as_str).collect();
            self.text = MessageText::Own(crate::matcher::format_log_message(0, &self.format, &refs));
            if self.compact_arguments.is_some() {
                self.compact_arguments = Some(CompactArguments::Own(args.iter().enumerate().map(|(i, a)| compact_argument(parts.get(i).map(String::as_str).unwrap_or(""), a, &texts[i])).collect()));
            }
        }
    }

    /// Marks the argument at `index` as the entry's own request (see [`LogEntry::own_arguments`]).
    pub fn own_argument(mut self, index: usize) -> LogEntry {
        self.own_arguments.push(index);
        self
    }

    /// Marks the argument at `index` as another object than the entry's own request or response, whatever its value
    /// (see [`LogEntry::other_arguments`]).
    pub fn other_argument(mut self, index: usize) -> LogEntry {
        self.other_arguments.push(index);
        self
    }

    /// Arguments rendered by `render` when the log is first read (see [`LiveArguments`]), in place of those
    /// [`LogEntry::args`] gave at the same indexes.
    pub fn live_arguments(mut self, render: impl Fn() -> Vec<(usize, Arg)> + Send + Sync + 'static) -> LogEntry {
        self.live_arguments = Some(LiveArguments { render: std::sync::Arc::new(render), rendered: Default::default(), memoised: true });
        self
    }

    /// [`LogEntry::live_arguments`] rendered again on every read, as upstream renders a message that quotes a request
    /// or response (an `HttpResponse` the handler goes on changing after logging it). An argument that is the entry's
    /// own response replaces the entry's response too: upstream logs the one object as both.
    pub fn live_arguments_unmemoised(mut self, render: impl Fn() -> Vec<(usize, Arg)> + Send + Sync + 'static) -> LogEntry {
        self.live_arguments = Some(LiveArguments { render: std::sync::Arc::new(render), rendered: Default::default(), memoised: false });
        self
    }

    /// The entry as the log reads it: its [`LiveArguments`] rendered (once, when memoised) and the message formatted
    /// again with them.
    pub fn settled(&self) -> std::borrow::Cow<'_, LogEntry> {
        let (Some(live), Some(args)) = (&self.live_arguments, &self.arguments) else { return std::borrow::Cow::Borrowed(self) };
        let render = || (live.render)().into_iter().map(|(i, a)| (i, a.json, a.shape)).collect::<Vec<_>>();
        let fresh;
        let rendered = match live.memoised {
            true => live.rendered.get_or_init(render),
            false => {
                fresh = render();
                if fresh.is_empty() {
                    return std::borrow::Cow::Borrowed(self);
                }
                &fresh
            }
        };
        let mut out = self.clone();
        out.live_arguments = None;
        let mut args = args.clone();
        let mut shapes = self.arg_shapes.clone().unwrap_or_else(|| vec![ArgText::Json; args.len()]);
        for (i, json, shape) in rendered {
            if let (Some(arg), Some(slot)) = (args.get_mut(*i), shapes.get_mut(*i)) {
                if !live.memoised && self.response.as_ref().is_some_and(|r| Json::ptr_eq(r, arg) || **r == **arg) {
                    out.response = Some(json.clone());
                }
                *arg = json.clone();
                *slot = shape.clone();
            }
        }
        let texts: Vec<String> = args.iter().zip(&shapes).map(|(a, s)| s.plain(a)).collect();
        if !self.text_custom {
            let refs: Vec<&str> = texts.iter().map(String::as_str).collect();
            out.text = MessageText::Own(crate::matcher::format_log_message(0, &self.format, &refs));
        }
        let parts = java_split_placeholders(&self.format);
        out.compact_arguments = Some(CompactArguments::Own(args.iter().enumerate().map(|(i, a)| compact_argument(parts.get(i).copied().unwrap_or(""), a, &texts[i])).collect()));
        out.arguments = Some(args);
        out.arg_shapes = Some(shapes);
        std::borrow::Cow::Owned(out)
    }

    pub fn without_port(mut self) -> LogEntry {
        self.portless = true;
        self
    }

    /// A message text that the arguments' texts do not produce by themselves (an indented sub-message).
    pub fn text(mut self, text: impl Into<String>) -> LogEntry {
        self.text = MessageText::Own(text.into());
        self.text_custom = true;
        self
    }

    /// [`LogEntry::to_json`] with what only the dashboard reads, under keys no log JSON has: `$objectArguments` (index to
    /// dashboard value of the [`Arg::object`] arguments), `$throwable` (the stack trace's lines) and `$ownParts`
    /// ([`LogEntry::own_message_parts`]). The arguments
    /// stay whole: `DashboardLogEntryDTO` reads `LogEntry.getArguments()`, not the serializer's compact forms of the
    /// entry's own request and response.
    pub fn to_dashboard_json(&self, timestamp: &DateTime<Local>, port: Option<u16>) -> Value {
        let mut value = self.serialize(timestamp, port, false);
        if let Value::Object(o) = &mut value {
            if !self.object_arguments.is_empty() {
                o.insert("$objectArguments".into(), self.object_arguments.iter().map(|(i, value)| (i.to_string(), Value::String(value.clone()))).collect());
            }
            if let Some(lines) = &self.throwable {
                o.insert("$throwable".into(), lines.iter().cloned().map(Value::String).collect());
            }
            if let Some(own) = self.own_message_parts() {
                o.insert("$ownParts".into(), own.into_iter().map(|p| p.map_or(Value::Null, Value::from)).collect());
            }
        }
        value
    }

    /// `LogEntrySerializer.serialize`, stamped with the entry's time and the server's port.
    pub fn to_json(&self, timestamp: &DateTime<Local>, port: Option<u16>) -> Value {
        self.serialize(timestamp, port, true)
    }

    /// `compact_own`: write the entry's own request, response or curl command arguments in their compact form
    /// (`getSerializedArguments`).
    fn serialize(&self, timestamp: &DateTime<Local>, port: Option<u16>, compact_own: bool) -> Value {
        let mut o = Map::new();
        o.insert("logLevel".into(), self.level.name().into());
        o.insert("epochTime".into(), timestamp.timestamp_millis().into());
        o.insert("timestamp".into(), timestamp.format("%Y-%m-%d %H:%M:%S%.3f").to_string().into());
        o.insert("type".into(), self.kind.name().into());
        if let Some(id) = &self.correlation_id {
            o.insert("correlationId".into(), id.clone().into());
        }
        if let Some(port) = port.filter(|_| !self.portless) {
            o.insert("port".into(), port.into());
        }
        // `getHttpUpdatedRequests`: each request's body as `LogEntry.updateBody` leaves it.
        match self.requests.as_deref() {
            Some([one]) => {
                o.insert("httpRequest".into(), crate::recorded::log_entry_request(one));
            }
            Some(many) if many.len() > 1 => {
                o.insert("httpRequests".into(), Value::Array(many.iter().map(|r| crate::recorded::log_entry_request(r)).collect()));
            }
            _ => {}
        }
        if let Some(v) = &self.response {
            o.insert("httpResponse".into(), Value::clone(v));
        }
        if let Some(v) = &self.error {
            o.insert("httpError".into(), v.clone());
        }
        let live = self.live.as_ref().map(|(live, argument)| ((live.0)(), *argument));
        if let Some((v, _)) = &live {
            o.insert("expectation".into(), v.clone());
        } else if let Some(v) = &self.expectation {
            // `getSerializedExpectation`: a forwarded exchange's synthetic expectation without the bodies its
            // `httpRequest`/`httpResponse` already write
            o.insert("expectation".into(), if self.synthetic_expectation { without_bodies(v) } else { Value::clone(v) });
        }
        if let Some(v) = &self.expectation_id {
            o.insert("expectationId".into(), v.clone().into());
        }
        o.insert("messageFormat".into(), self.format.clone().into());
        // `getSerializedMessage`/`getSerializedArguments`: the entry's own request, response or curl command quoted in
        // its compact form, since the entry writes them in full once
        let own = match &self.own_compact_fixed {
            Some(own) => own.clone(),
            None => self.own_compact(),
        };
        let text = match (&own, &self.arguments) {
            (Some(own), Some(args)) if !self.text_custom => {
                let shapes = self.arg_shapes.as_deref().unwrap_or_default();
                let texts: Vec<String> = args
                    .iter()
                    .enumerate()
                    .map(|(i, a)| match own.get(i).cloned().flatten() {
                        Some(compact) => compact,
                        None => {
                            let shape = shapes.get(i).unwrap_or(&ArgText::Json);
                            match &self.redaction {
                                Some(redaction) => shape.render(a, redaction),
                                None => shape.plain(a),
                            }
                        }
                    })
                    .collect();
                let refs: Vec<&str> = texts.iter().map(String::as_str).collect();
                std::borrow::Cow::Owned(crate::matcher::format_log_message(0, &self.format, &refs))
            }
            _ => std::borrow::Cow::Borrowed(self.message_text()),
        };
        // `getMessage().replaceAll(" {2}", "   ").split(NEW_LINE)`: `String.split` drops trailing empty parts.
        let mut lines: Vec<Value> = text.replace("  ", "   ").split('\n').map(|l| Value::String(l.to_string())).collect();
        while lines.len() > 1 && lines.last().is_some_and(|l| l.as_str() == Some("")) {
            lines.pop();
        }
        o.insert("message".into(), Value::Array(lines));
        if let Some(args) = &self.arguments {
            let mut args: Vec<Value> = args.iter().map(|a| Value::clone(a)).collect();
            if let Some((v, Some(i))) = live && let Some(slot) = args.get_mut(i) {
                *slot = match &self.redaction {
                    Some(redaction) => redaction.argument(&v),
                    None => v,
                };
            }
            for (slot, compact) in args.iter_mut().zip(own.iter().flatten().filter(|_| compact_own)) {
                if let Some(compact) = compact {
                    *slot = Value::String(compact.clone());
                }
            }
            o.insert("arguments".into(), Value::Array(args));
        }
        if let Some(v) = &self.because {
            o.insert("because".into(), v.clone().into());
        }
        if let Some(bean) = &self.throwable_bean {
            o.insert("throwable".into(), bean.clone());
        } else if let Some(lines) = &self.throwable {
            o.insert("throwable".into(), throwable_bean(lines));
        }
        Value::Object(o)
    }
}

/// Jackson's bean form of a `Throwable` (`cause`, `localizedMessage`, `message`, `stackTrace`; nulls and empty
/// `suppressed` dropped) from the lines of its `printStackTrace`: `class: message`, then the cause blocks. The JVM
/// frames cannot be reproduced, so `stackTrace` is empty (docs/divergences.md, dashboard throwable lines).
/// `message.split("\\{}")`: Java drops the trailing empty parts (an empty format stays one empty part).
fn java_split_placeholders(format: &str) -> Vec<&str> {
    let mut parts: Vec<&str> = format.split("{}").collect();
    while parts.len() > 1 && parts.last() == Some(&"") {
        parts.pop();
    }
    if parts == [""] && !format.is_empty() {
        parts.clear();
    }
    parts
}

/// `StringFormatter.formatCompactLogMessage`: the format's parts, trimmed, each followed by its argument's compact
/// form (already [`compact_argument`]), single spaces between.
pub fn compact_message(format: &str, arguments: &[String]) -> String {
    let mut out = String::new();
    for (i, part) in java_split_placeholders(format).into_iter().enumerate() {
        let part = java_trim(part);
        if i > 0 && !out.is_empty() && !part.is_empty() {
            out.push(' ');
        }
        out.push_str(part);
        if let Some(compact) = arguments.get(i).filter(|c| !c.is_empty()) {
            if !out.is_empty() {
                out.push(' ');
            }
            out.push_str(compact);
        }
    }
    out
}

/// `String.trim`: every character up to U+0020 at either end.
fn java_trim(text: &str) -> &str {
    text.trim_matches(|c: char| c <= ' ')
}

/// Fields of `HttpRequest` and `HttpResponse` as their JSON writes them: an object of these alone, with neither a method,
/// a path nor a status code, is still one of the two (a request matcher `{ }`, an action `{"body": "x"}`).
pub(crate) const MESSAGE_FIELDS: &[&str] = &[
    "body", "headers", "cookies", "queryStringParameters", "pathParameters", "keepAlive", "secure", "protocol", "socketAddress",
    "clientCertificateChain", "localAddress", "remoteAddress", "streamId", "reasonPhrase", "connectionOptions", "delay", "trailers",
];

/// `StringFormatter.toCompactString` of one argument, told apart by its JSON (`preceding` is the format's text before
/// its placeholder, which decides between a request and a response that have neither a method, a path nor a status):
/// an `HttpResponse` is its status code (`response` without one), an `HttpRequest` `METHOD path`, either alone or
/// `request`, an `Expectation` its id, an `Action` its type in lower case; anything else `String.valueOf` with every
/// whitespace run around a line break made one space, trimmed, and cut to 117 characters and `...` past 120.
pub fn compact_argument(preceding: &str, json: &Value, text: &str) -> String {
    if let Value::Object(o) = json {
        let string = |key: &str| match o.get(key) {
            Some(Value::String(s)) => s.clone(),
            Some(Value::Object(n)) => n.get("value").and_then(Value::as_str).unwrap_or_default().to_string(),
            _ => String::new(),
        };
        let request_like = o.contains_key("method") || o.contains_key("path");
        let is_expectation = o.get("id").is_some_and(Value::is_string) && ["httpRequest", "priority", "times", "timeToLive"].iter().any(|k| o.contains_key(*k));
        if is_expectation && !request_like {
            return string("id");
        }
        if let Some(status) = o.get("statusCode") {
            return status.as_i64().map_or_else(|| "response".to_string(), |s| s.to_string());
        }
        if request_like {
            return compact_request(&string("method"), &string("path"));
        }
        if o.keys().all(|k| MESSAGE_FIELDS.contains(&k.as_str())) {
            if o.contains_key("reasonPhrase") || o.contains_key("connectionOptions") {
                return "response".into();
            }
            let preceding = java_trim(preceding).to_ascii_lowercase();
            return if preceding.ends_with("response:") || preceding.ends_with("action:") { "response".into() } else { "request".into() };
        }
        if o.contains_key("host") && o.keys().all(|k| ["host", "port", "scheme", "delay"].contains(&k.as_str())) {
            return "forward".into();
        }
        if ["requestOverride", "requestModifier", "responseOverride", "responseModifier"].iter().any(|k| o.contains_key(*k)) {
            return "forward_replace".into();
        }
        if o.contains_key("dropConnection") || o.contains_key("responseBytes") {
            return "error".into();
        }
    }
    collapse_lines(text)
}

/// `toCompactString(HttpRequest)` of a request's JSON: `METHOD path`, either alone, or `request`.
pub fn compact_request_json(json: &Value) -> String {
    // `StringFormatter.toCompactString` of a DNS or binary definition, which is no `HttpRequest`: its `toString`
    // (pretty JSON) on one line
    if crate::canonical::is_dns_request(json) || crate::canonical::is_binary_request(json) {
        return collapse_lines(&crate::json::pretty(json));
    }
    let string = |key: &str| match json.get(key) {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Object(n)) => n.get("value").and_then(Value::as_str).unwrap_or_default().to_string(),
        _ => String::new(),
    };
    compact_request(&string("method"), &string("path"))
}

/// An expectation's JSON with neither its request's nor its response's body.
fn without_bodies(expectation: &Value) -> Value {
    let mut out = expectation.clone();
    for field in ["httpRequest", "httpResponse"] {
        if let Some(Value::Object(o)) = out.get_mut(field) {
            o.shift_remove("body");
        }
    }
    out
}

fn compact_request(method: &str, path: &str) -> String {
    match (method.trim().is_empty(), path.trim().is_empty()) {
        (false, false) => format!("{method} {path}"),
        (true, false) => path.to_string(),
        (false, true) => method.to_string(),
        (true, true) => "request".into(),
    }
}

/// `str.replaceAll("\\s*\\n\\s*", " ").trim()`, cut to 117 characters and `...` when longer than 120.
fn collapse_lines(text: &str) -> String {
    let is_space = |c: char| matches!(c, ' ' | '\t' | '\n' | '\u{0B}' | '\u{0C}' | '\r');
    let mut out = String::with_capacity(text.len().min(256));
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if is_space(c) {
            let mut run = String::from(c);
            while let Some(next) = chars.next_if(|n| is_space(*n)) {
                run.push(next);
            }
            // one greedy match takes a whole run that holds a line break (its later breaks included)
            if run.contains('\n') {
                out.push(' ');
            } else {
                out.push_str(&run);
            }
        } else {
            out.push(c);
        }
    }
    let trimmed = java_trim(&out);
    if trimmed.encode_utf16().count() <= 120 {
        return trimmed.to_string();
    }
    let mut cut = String::new();
    let mut units = 0;
    for c in trimmed.chars() {
        units += c.len_utf16();
        if units > 117 {
            break;
        }
        cut.push(c);
    }
    cut + "..."
}

/// Every string in `v` scrubbed (a throwable's bean: `RedactedThrowable`'s messages).
fn scrub_strings(v: &Value, redaction: &crate::log_redaction::Redaction) -> Value {
    match v {
        Value::String(s) => Value::String(redaction.scrub(s)),
        Value::Array(items) => Value::Array(items.iter().map(|i| scrub_strings(i, redaction)).collect()),
        Value::Object(o) => Value::Object(o.iter().map(|(k, v)| (k.clone(), scrub_strings(v, redaction))).collect()),
        other => other.clone(),
    }
}

fn throwable_bean(lines: &[String]) -> Value {
    const CAUSE: &str = "Caused by: ";
    let mut bean = Map::new();
    if let Some(at) = lines.iter().skip(1).position(|l| l.starts_with(CAUSE)) {
        let mut rest = lines[at + 1..].to_vec();
        rest[0] = rest[0][CAUSE.len()..].to_string();
        bean.insert("cause".into(), throwable_bean(&rest));
    }
    let head = lines.first().map(String::as_str).unwrap_or_default();
    if let Some((_, message)) = head.split_once(": ") {
        bean.insert("localizedMessage".into(), message.into());
        bean.insert("message".into(), message.into());
    }
    bean.insert("stackTrace".into(), Value::Array(Vec::new()));
    Value::Object(bean)
}
