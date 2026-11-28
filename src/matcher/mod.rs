//! Request matchers: does an [`HttpRequest`] satisfy an expectation's `httpRequest` (or a verify/clear/retrieve
//! filter)? Compiled once from the canonical JSON form (§3.1–§3.4).

mod backtrack;
mod body;
pub(crate) use body::{jayway_compile_check, jayway_truthy};
mod client_cert;
mod client_ip;
#[cfg(test)]
mod concurrency_tests;
mod definition;
pub mod graphql;
pub(crate) mod java_pattern;
mod jayway_syntax;
mod jwt;
mod multimap;
mod response;
pub(crate) mod string;

use serde_json::Value;

use body::BodyMatcher;
pub use body::with_xpath_timeout;
pub use body::{multipart_parts, MultipartPart};
use multimap::MultiMapMatcher;
pub(crate) use multimap::with_definition_values;

/// The request fields matched as maps (`MultiValueMapMatcher`, `HashMapMatcher`), in upstream's matching order.
const MAP_FIELDS: &[&str] = &["headers", "cookies", "pathParameters", "queryParameters"];
pub use response::{ResponseMatcher, diff_line};
pub use string::{MatchNote, StringMatcher, WouldMatch};
pub(crate) use string::{RegexTimeout, regex_timeouts, regex_timeouts_each, take_regex_timeouts, with_control_plane};
pub(crate) use definition::body_to_string;
pub(crate) use definition::{body_deserialization_failure, expectation_body_failure};

/// `JsonSchemaValidator.isValid(json)`: the report for `json_text` against `schema`, empty when it passes.
pub fn json_schema_report(schema: &Value, json_text: &str) -> String {
    // A schema the `jsonschema` crate cannot build is still evaluated (networknt accepts more).
    let validator = string::validator(schema).ok();
    match crate::json::parse_lenient(json_text.as_bytes()) {
        Ok(instance) => crate::schema::value_report(validator.as_ref(), schema, &instance),
        Err(e) => format!("JsonParseException - {e}"),
    }
}


use crate::canonical;
use crate::request::{HttpRequest, MultiMap};

thread_local! {
    static EXACT_CASE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Runs `f` — synchronous, not spanning an `.await` — with `matchExactCase` set to `exact`, so every matcher compiled
/// inside it (an expectation's, and its nested OpenAPI alternatives and conditional branches) matches the method,
/// the path and a `REGEX` body case-sensitively on the data plane (`HttpRequestPropertiesMatcher.apply`,
/// `BodyMatcherBuilder`). Upstream decides this when it builds the matcher, from the value the server started with:
/// a later `PUT /mockserver/configuration` changes neither existing nor new expectations (oracle scenario
/// `match_exact_case`). Control-plane filters are compiled outside it and stay case-insensitive.
pub fn with_exact_case<R>(exact: bool, f: impl FnOnce() -> R) -> R {
    let previous = EXACT_CASE.with(|c| c.replace(exact));
    let result = f();
    EXACT_CASE.with(|c| c.set(previous));
    result
}

pub(crate) fn exact_case() -> bool {
    EXACT_CASE.with(std::cell::Cell::get)
}

/// `MatchDifference.Field` names in declaration order (`clientIp` since 9.2.0): the order differing fields are
/// listed in, and its length is the field count the diagnostics report (`Field.values().length`).
pub const FIELDS: [&str; 19] = [
    "method", "path", "pathParameters", "queryParameters", "cookies", "headers", "body", "secure", "protocol", "clientCertificate", "jwt",
    "keep-alive", "operation", "openapi", "dnsName", "dnsType", "dnsClass", "binaryBody", "clientIp",
];

/// `HttpRequestDTO.buildObject` (`HttpRequest.withClientIp`): the message `ClientIpMatcher.compile` throws for a
/// request definition's invalid `clientIp`, which its serializer reports after reading the DTO.
pub(crate) fn client_ip_failure(definition: &Value) -> Option<String> {
    definition.get("clientIp").filter(|c| !c.is_null()).and_then(|c| client_ip::ClientIpMatcher::compile(c).err())
}

/// `NottableStringDeserializer` reading a request definition's date-time values (`before`, `after`,
/// `equalToDateTime`): the first one it refuses, in the order the fields are read, as the message it throws and the
/// rest of the reference chain Jackson adds below the definition (`->java.lang.Object[][i]` for the `i`th of a
/// multimap entry's values).
pub(crate) fn date_time_failure(definition: &Value) -> Option<(String, String)> {
    let Value::Object(fields) = definition else { return None };
    let failure = |v: &Value| match v {
        Value::Object(o) => crate::model::DateTimeValue::read(o).and_then(Result::err),
        _ => None,
    };
    let in_values = |values: &Value| -> Option<(String, String)> {
        let values = match values {
            Value::Object(styled) => styled.get("values")?,
            other => other,
        };
        let items = values.as_array()?;
        items.iter().enumerate().find_map(|(i, v)| failure(v).map(|cause| (cause, format!("->java.lang.Object[][{i}]"))))
    };
    fields.iter().find_map(|(key, value)| match key.as_str() {
        "method" | "path" => failure(value).map(|cause| (cause, String::new())),
        "headers" | "queryStringParameters" | "pathParameters" => match value {
            Value::Object(map) => map.iter().filter(|(k, _)| k.as_str() != "keyMatchStyle").find_map(|(_, v)| in_values(v)),
            Value::Array(items) => items.iter().find_map(|item| in_values(item.get("values")?)),
            _ => None,
        },
        "body" => body_date_time_failure(value).map(|cause| (cause, String::new())),
        "cookies" => match value {
            Value::Object(map) => map.values().find_map(failure).map(|cause| (cause, String::new())),
            Value::Array(items) => items.iter().find_map(|item| failure(item.get("value")?)).map(|cause| (cause, String::new())),
            _ => None,
        },
        _ => None,
    })
}

/// `BodyDateTimeField.forBody`: a JSON_PATH or XPATH body's `dateTime` must be a date-time comparison; on a body of
/// another explicit `type` it is refused, on an untyped body it is content.
fn body_date_time_failure(body: &Value) -> Option<String> {
    let Value::Object(o) = body else { return None };
    let date_time = crate::canonical::field(o, "dateTime").filter(|v| !v.is_null())?;
    let kind = crate::canonical::body_type(o)?;
    if kind == "JSON_PATH" || kind == "XPATH" {
        let Value::Object(fields) = date_time else {
            return Some("a body dateTime is an object such as {\"after\": \"now -1 days\"}".into());
        };
        return match crate::model::DateTimeValue::read(fields) {
            Some(Ok(_)) => None,
            Some(Err(cause)) => Some(cause),
            None => Some("a body dateTime needs one of before, after or equalToDateTime".into()),
        };
    }
    crate::canonical::field(o, "type").is_some().then(|| format!("a body dateTime applies only to JSON_PATH and XPATH bodies, not {kind}"))
}

#[derive(Debug)]
pub struct RequestMatcher {
    not: bool,
    method: Option<StringMatcher>,
    path: Option<PathMatcher>,
    path_parameters: MultiMapMatcher,
    query: MultiMapMatcher,
    headers: MultiMapMatcher,
    cookies: MultiMapMatcher,
    body: Option<BodyMatcher>,
    /// The canonical definition this matcher was compiled from (the filter's own body and headers, which the
    /// control plane matches other definitions' bodies against).
    definition: Value,
    keep_alive: Option<bool>,
    secure: Option<bool>,
    /// `protocol`: `HTTP_1_1` or `HTTP_2`, compared exactly (`ExactStringMatcher`).
    protocol: Option<String>,
    /// `clientCertificate`: criteria on the leaf of the request's TLS client certificate chain.
    client_certificate: Option<client_cert::ClientCertificateMatcher>,
    /// `clientIp`: an IP address or CIDR range the request's peer address must (or, negated, must not) fall in.
    client_ip: Option<client_ip::ClientIpMatcher>,
    /// `jwt`: criteria on the decoded JSON Web Token in a request header.
    jwt: Option<jwt::JwtMatcher>,
    /// A matcher kind this server does not evaluate here (binary, DNS): never matches.
    unsupported: bool,
    /// An OpenAPI matcher: one alternative per operation (and body content type), or why the spec failed to load.
    openapi: Option<Result<Vec<RequestMatcher>, String>>,
    /// Each OpenAPI alternative's log description and request matcher as its log lines print it.
    operations: Vec<(String, Value)>,
    /// A compound request definition (`if`/`then`/`else`, or `anyOf`); every other field is then unset.
    conditional: Option<Box<Conditional>>,
    /// A DNS request definition (`dnsName`), which only DNS queries and DNS definitions can satisfy.
    dns: Option<crate::dns::DnsMatcher>,
    /// `matchExactCase` (see [`with_exact_case`]): the data plane matches the method case-sensitively.
    exact_case: bool,
}

/// A compound request matcher, made of branches that are request matchers of their own.
#[derive(Debug)]
pub enum Conditional {
    /// `ConditionalRequestMatcher`: the `if` branch picks `then` or `else`; a missing `then`/`else` matches, a
    /// missing `if` never does.
    IfThenElse { guard: Option<Box<Branch>>, then: Option<Box<Branch>>, otherwise: Option<Box<Branch>> },
    /// `AnyOfRequestMatcher`: the branches in order, the first that matches wins; none (or no branch) fails.
    AnyOf(Vec<Branch>),
}

impl Conditional {
    /// The branches' verdict, each branch judged by `branch_matches`, before the compound's own `not`.
    pub fn evaluate(&self, mut branch_matches: impl FnMut(&RequestMatcher) -> bool) -> bool {
        match self {
            Conditional::IfThenElse { guard, then, otherwise } => {
                let Some(guard) = guard else { return false };
                let chosen = if branch_matches(&guard.matcher) { then } else { otherwise };
                chosen.as_ref().is_none_or(|b| branch_matches(&b.matcher))
            }
            Conditional::AnyOf(branches) => branches.iter().any(|b| branch_matches(&b.matcher)),
        }
    }

    fn any_of(&self) -> Option<&[Branch]> {
        match self {
            Conditional::AnyOf(branches) => Some(branches),
            Conditional::IfThenElse { .. } => None,
        }
    }
}

/// One branch of a conditional or an anyOf. On the data plane upstream wraps it in a throwaway expectation (a fresh
/// id, no action), which is what its match-result log lines name.
#[derive(Debug)]
pub struct Branch {
    matcher: RequestMatcher,
    id: String,
    expectation: Value,
}

impl Branch {
    fn compile(v: &Value) -> Branch {
        let id = uuid::Uuid::new_v4().to_string();
        let expectation = serde_json::json!({
            "httpRequest": canonical::request_definition(v),
            "id": id,
            "priority": 0,
            "timeToLive": {"unlimited": true},
            "times": {"unlimited": true},
        });
        Branch { matcher: RequestMatcher::compile(v), id, expectation }
    }
}

thread_local! {
    /// The differences control-plane matches noted while [`tracing_received`] runs on this thread, with their request.
    static RECEIVED_TRACE: std::cell::RefCell<Option<Vec<(String, Traced)>>> = const { std::cell::RefCell::new(None) };
    /// Set by [`as_received`]: the next control-plane match is of a `RECEIVED_REQUEST` entry's request.
    static RECEIVED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Runs `f`, collecting (when `on`) the TRACE differences of the control-plane matches it makes of received requests
/// ([`as_received`]) and of verification diffs ([`RequestMatcher::note_fail_fast`]); [`take_received_trace`] takes
/// them on the way, the rest is returned. Nested calls collect into the outermost.
pub(crate) fn tracing_received<R>(on: bool, f: impl FnOnce() -> R) -> (R, Vec<(String, Traced)>) {
    let outermost = on && RECEIVED_TRACE.with(|t| {
        let mut t = t.borrow_mut();
        let outermost = t.is_none();
        if outermost {
            *t = Some(Vec::new());
        }
        outermost
    });
    let result = f();
    let rest = if outermost { RECEIVED_TRACE.with(|t| t.borrow_mut().take()).unwrap_or_default() } else { Vec::new() };
    (result, rest)
}

/// The differences [`tracing_received`] has collected so far.
pub(crate) fn take_received_trace() -> Vec<(String, Traced)> {
    RECEIVED_TRACE.with(|t| t.borrow_mut().as_mut().map(std::mem::take).unwrap_or_default())
}

/// What a TRACE difference entry is about (`MatchDifference`'s `httpRequest`).
#[derive(Debug)]
pub(crate) enum Traced {
    /// A request (received, or a log entry's).
    Request(Box<HttpRequest>),
    /// A plain HTTP request definition an OpenAPI filter met (an expectation's, or a log entry's).
    Definition(Value),
}

/// Whether [`tracing_received`] collects on this thread.
pub(crate) fn tracing() -> bool {
    RECEIVED_TRACE.with(|t| t.borrow().is_some())
}

/// Notes for [`tracing_received`], when it runs, the differences `texts` recorded matching the definition
/// `definition`.
pub(crate) fn note_definition_differences(texts: Vec<String>, definition: &Value) {
    if texts.is_empty() {
        return;
    }
    RECEIVED_TRACE.with(|t| {
        if let Some(t) = t.borrow_mut().as_mut() {
            t.extend(texts.iter().map(|text| (string::unindented(text), Traced::Definition(definition.clone()))));
        }
    });
}

/// Notes for [`tracing_received`], when it runs, the differences `texts` recorded matching the request `request`.
pub(crate) fn note_request_differences(texts: &[String], request: &HttpRequest) {
    RECEIVED_TRACE.with(|t| {
        if let Some(t) = t.borrow_mut().as_mut() {
            t.extend(texts.iter().filter(|text| !text.is_empty()).map(|text| (string::unindented(text), Traced::Request(Box::new(request.clone())))));
        }
    });
}

/// Runs `f`, whose control-plane match is of a received request: `LogEntry.matches` gives a `RECEIVED_REQUEST`
/// entry's match a `MatchDifference` context (any other entry none), so its differences log at TRACE.
pub(crate) fn as_received<R>(f: impl FnOnce() -> R) -> R {
    if RECEIVED_TRACE.with(|t| t.borrow().is_none()) {
        return f();
    }
    let outer = RECEIVED.with(|r| r.replace(true));
    let result = f();
    RECEIVED.with(|r| r.set(outer));
    result
}

/// The differences a `MatchDifference` context holds, per field in the order first recorded.
type Context = Vec<(&'static str, Vec<Difference>)>;

fn merge(context: &mut Context, field: &'static str, differences: Vec<Difference>) {
    if differences.is_empty() {
        return;
    }
    match context.iter_mut().find(|(f, _)| *f == field) {
        Some((_, existing)) => existing.extend(differences),
        None => context.push((field, differences)),
    }
}

/// One match-result log entry (`EXPECTATION_MATCHED` / `EXPECTATION_NOT_MATCHED`) written while a conditional or
/// OpenAPI matcher is evaluated: those log from the matchers they are made of, not as the expectation.
#[derive(Debug)]
pub enum Logged {
    /// A conditional branch, as its throwaway expectation, with the `would match` DEBUG entries its data-plane
    /// `RegexStringMatcher`s write first (only collected at DEBUG), and its differences' TRACE entries (at TRACE).
    Branch { matched: bool, id: String, expectation: Value, because: String, notes: Vec<string::MatchNote> },
    /// One OpenAPI operation's request matcher: its description and the request matcher it prints.
    Operation { matched: bool, description: String, request: Value, because: String },
}

/// What a plain matcher logs as while traced.
#[derive(Clone, Copy)]
enum LogAs<'a> {
    Nothing,
    Branch(&'a Branch),
    Operation(&'a (String, Value)),
}

/// The path field: a regex matcher over the path with template parts turned into `.*`, and, when the matcher
/// declares path parameters, the template they are extracted with.
#[derive(Debug)]
struct PathMatcher {
    matcher: StringMatcher,
    template: Option<PathTemplate>,
    /// `matchExactCase` (see [`with_exact_case`]): the data plane matches the path case-sensitively.
    exact_case: bool,
}

/// A path given with path parameters: its value and, per non-blank part, the parameter it names (if any).
#[derive(Debug)]
struct PathTemplate {
    value: String,
    parts: Vec<Option<String>>,
}

/// How strictly to match: the data plane follows MockServer's defaults; control-plane filters (verify, clear,
/// retrieve) are always case-insensitive (§3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    DataPlane,
    ControlPlane,
}

impl RequestMatcher {
    /// Matches every request (an expectation without `httpRequest`, or an empty filter).
    pub fn any() -> RequestMatcher {
        RequestMatcher::compile(&Value::Object(Default::default()))
    }

    /// From a request matcher in input or canonical form.
    pub fn compile(input: &Value) -> RequestMatcher {
        let v = canonical::request_definition(input);
        let empty = serde_json::Map::new();
        let o = v.as_object().unwrap_or(&empty);
        let unsupported = ["binaryData", "dnsName"].iter().any(|k| o.contains_key(*k));
        let mut operations = Vec::new();
        let openapi = o.contains_key("specUrlOrPayload").then(|| {
            crate::openapi::described_request_matchers(o).map(|alternatives| {
                alternatives
                    .into_iter()
                    .map(|(request, description)| {
                        // `addRequestMatcher` builds the operation's matcher with `update(httpRequest)` (control plane)
                        // before `setControlPlaneMatcher`, so its method and path `RegexStringMatcher`s keep matching
                        // the request's value read as a regex.
                        let mut matcher = RequestMatcher::compile(&request);
                        matcher.method = matcher.method.take().map(StringMatcher::reversed);
                        if let Some(p) = matcher.path.as_mut() {
                            p.matcher = std::mem::replace(&mut p.matcher, StringMatcher::from_text("")).reversed();
                        }
                        operations.push((description, canonical::request_definition(&request)));
                        matcher
                    })
                    .collect()
            })
        });
        let conditional = canonical::is_conditional_request(&v).then(|| {
            if canonical::is_any_of_request(&v) {
                let branches = input.get("anyOf").or_else(|| o.get("anyOf")).and_then(Value::as_array);
                return Box::new(Conditional::AnyOf(branches.into_iter().flatten().filter(|b| b.is_object()).map(Branch::compile).collect()));
            }
            let branch = |key: &str| input.get(key).or_else(|| o.get(key)).filter(|b| b.is_object()).map(|b| Box::new(Branch::compile(b)));
            Box::new(Conditional::IfThenElse { guard: branch("if"), then: branch("then"), otherwise: branch("else") })
        });
        RequestMatcher {
            not: o.get("not").and_then(Value::as_bool).unwrap_or(false),
            method: o.get("method").map(StringMatcher::compile),
            // `normalisePathWithParametersForMatching`: `{name}` parts are placeholders only when path parameters are given.
            path: o.get("path").map(|p| PathMatcher::compile(p, o.get("pathParameters").is_some_and(|pp| pp.as_object().is_some_and(|m| !m.is_empty()) || pp.as_array().is_some_and(|a| !a.is_empty())))),
            // Compiled from the canonical form, then put back in the input's key order, which is the order upstream's
            // matcher compares in (the canonical echo sorts keys).
            path_parameters: o.get("pathParameters").map(|v| MultiMapMatcher::compile(v).in_order_of(input.get("pathParameters"))).unwrap_or_default(),
            query: o.get("queryStringParameters").map(|v| MultiMapMatcher::compile(v).in_order_of(input.get("queryStringParameters"))).unwrap_or_default(),
            headers: o.get("headers").map(|v| MultiMapMatcher::compile(v).for_headers().in_order_of(input.get("headers"))).unwrap_or_default(),
            cookies: o.get("cookies").map(|v| MultiMapMatcher::compile_single(v).in_order_of(input.get("cookies"))).unwrap_or_default(),
            body: o.get("body").map(|b| BodyMatcher::compile(b).in_order_of(input.get("body"))),
            keep_alive: o.get("keepAlive").and_then(Value::as_bool),
            secure: o.get("secure").and_then(Value::as_bool),
            protocol: o.get("protocol").and_then(Value::as_str).map(str::to_string),
            client_certificate: o.get("clientCertificate").and_then(client_cert::ClientCertificateMatcher::compile),
            jwt: o.get("jwt").and_then(jwt::JwtMatcher::compile),
            client_ip: o.get("clientIp").and_then(|c| client_ip::ClientIpMatcher::compile(c).ok()),
            unsupported,
            openapi,
            operations,
            conditional,
            dns: crate::dns::DnsMatcher::compile(&v),
            definition: v,
            exact_case: exact_case(),
        }
    }

    /// The conditional (`if`/`then`/`else`), when this is a conditional request definition.
    pub fn conditional(&self) -> Option<&Conditional> {
        self.conditional.as_deref()
    }

    /// The definition's own `not`.
    pub fn is_not(&self) -> bool {
        self.not
    }

    /// The bytes of a binary request definition (`binaryData`), when this is one.
    pub fn binary_data(&self) -> Option<Vec<u8>> {
        use base64::Engine;
        let data = self.definition.get("binaryData")?.as_str()?;
        Some(base64::engine::general_purpose::STANDARD.decode(data).unwrap_or_default())
    }

    /// The DNS matcher, when this is a DNS request definition.
    pub fn dns(&self) -> Option<&crate::dns::DnsMatcher> {
        self.dns.as_ref()
    }

    /// Why an OpenAPI matcher's spec could not be loaded (the oracle rejects such an expectation with 400).
    pub fn load_error(&self) -> Option<&str> {
        match &self.openapi {
            Some(Err(e)) => Some(e),
            _ => None,
        }
    }

    /// Why the body matcher cannot be built (an unreadable XML schema): upstream's constructor throws, so the
    /// expectation is rejected with the exception's message.
    pub fn body_error(&self) -> Option<String> {
        self.body.as_ref().and_then(BodyMatcher::load_error)
    }

    /// Whether [`RequestMatcher::body_error`] is a `JSON_SCHEMA` body's schema networknt cannot build.
    pub fn body_schema_unbuilt(&self) -> bool {
        self.body.as_ref().is_some_and(BodyMatcher::schema_unbuilt)
    }

    /// An `IllegalArgumentException` of the body matcher's constructor (see [`BodyMatcher::argument_error`]).
    pub fn body_argument_error(&self) -> Option<&'static str> {
        self.body.as_ref().and_then(BodyMatcher::argument_error)
    }

    /// `XmlSchemaValidator`'s ERROR entry for the schema [`RequestMatcher::body_error`] reports.
    pub fn body_error_entry(&self) -> Option<crate::recorded::LogEntry> {
        let (schema, error) = self.body.as_ref().and_then(BodyMatcher::schema_error)?;
        Some(
            crate::recorded::LogEntry::at(crate::recorded::Level::Error, "exception parsing schema{}")
                .args([schema])
                .throwable(error.throwable_text())
                .throwable_bean(error.throwable_bean()),
        )
    }

    /// An OpenAPI (`specUrlOrPayload`) matcher: `HttpRequestsPropertiesMatcher`, one matcher per operation.
    pub fn is_openapi(&self) -> bool {
        self.openapi.is_some()
    }

    pub(crate) fn alternatives(&self) -> Option<&[RequestMatcher]> {
        match &self.openapi {
            Some(Ok(a)) => Some(a),
            Some(Err(_)) => Some(&[]),
            None => None,
        }
    }

    /// `PathParametersDecoder.extractPathParameters(this, request)`: the request's values for this matcher's path
    /// parameters, an error when the path has a different number of parts; `None` when it declares none.
    pub(crate) fn extract_path_parameters(&self, request: &HttpRequest) -> Option<Result<MultiMap, String>> {
        self.path.as_ref()?.extract(&request.path, &request.path_parameters)
    }

    pub fn matches(&self, request: &HttpRequest, mode: Mode) -> bool {
        string::with_control_plane(mode == Mode::ControlPlane, || self.matches_in(request, mode))
    }

    fn matches_in(&self, request: &HttpRequest, mode: Mode) -> bool {
        if mode == Mode::ControlPlane && RECEIVED.with(|r| r.replace(false)) {
            // `LogEntry.matches` for a `RECEIVED_REQUEST` entry: a context, whose differences log.
            let matched = self.matches(request, mode);
            // (An OpenAPI filter's operations note their own, below.)
            if self.openapi.is_none() {
                self.note_fail_fast(request);
            }
            RECEIVED.with(|r| r.set(true));
            return matched;
        }
        if self.unsupported {
            return false;
        }
        if let Some(c) = &self.conditional {
            return c.evaluate(|b| b.matches(request, mode)) != self.not;
        }
        if let Some(alternatives) = self.alternatives() {
            if mode == Mode::ControlPlane {
                // `HttpRequestsPropertiesMatcher.matches`: at TRACE an OpenAPI filter gives each request it meets a
                // context, received or not, so every operation tried logs its differences.
                return alternatives.iter().any(|a| {
                    a.note_fail_fast(request);
                    a.matches(request, mode)
                });
            }
            return alternatives.iter().any(|a| a.matches(request, mode));
        }
        self.all_fields_match(request, mode) != self.not
    }

    fn all_fields_match(&self, request: &HttpRequest, mode: Mode) -> bool {
        let body_ci = mode == Mode::ControlPlane;
        let control_plane = mode == Mode::ControlPlane;
        let method_ok = match &self.method {
            Some(m) if control_plane => request.method.is_empty() || m.matches_control_plane(&request.method),
            Some(m) => request.method.is_empty() || m.matches(&request.method, !self.exact_case),
            None => true,
        };
        if !method_ok {
            return false;
        }
        let mut path_parameters = MultiMap::new();
        let path_ok = match &self.path {
            Some(p) => {
                let regex = request.path.is_empty() || if control_plane { p.matcher.matches_control_plane(&request.path) } else { p.matches_regex(&request.path) };
                match p.extract(&request.path, &request.path_parameters) {
                    Some(Ok(extracted)) => {
                        path_parameters = extracted;
                        regex
                    }
                    Some(Err(_)) => false,
                    None => regex,
                }
            }
            None => true,
        };
        if !path_ok {
            return false;
        }
        if self.client_ip_difference(request).is_some() {
            return false;
        }
        if let Some(b) = &self.body {
            // `bodyMatches` on the control plane: a body whose string form equals this one's matches outright
            // (a filter body against another matcher's body definition).
            let same_definition = control_plane
                && !request.body.is_empty()
                && self.definition.get("body").is_some_and(|b| definition::body_to_string(b).to_lowercase() == request.body_str().to_lowercase());
            if !same_definition && !b.matches(request, body_ci) {
                return false;
            }
        }
        if !self.headers.matches(&request.headers, true) {
            return false;
        }
        if !self.cookies.is_empty() {
            let cookies: MultiMap = request.cookies.iter().map(|(k, v)| (k.clone(), vec![v.clone()])).collect();
            if !self.cookies.matches(&cookies, true) {
                return false;
            }
        }
        if !self.path_parameters.is_empty() && self.has_path() {
            let path_parameters = if control_plane { path_parameters } else { self.path_parameters.split_values(&path_parameters) };
            if !self.path_parameters.matches(&path_parameters, true) {
                return false;
            }
        }
        let query = if control_plane { std::borrow::Cow::Borrowed(&request.query) } else { std::borrow::Cow::Owned(self.query.split_values(&request.query)) };
        if !self.query.matches(&*query, true) {
            return false;
        }
        // `BooleanMatcher`: a null keep-alive (HTTP/3) satisfies no keepAlive matcher.
        if self.keep_alive.is_some_and(|k| Some(k) != request.keep_alive_flag()) {
            return false;
        }
        if self.secure.is_some_and(|s| s != request.secure) {
            return false;
        }
        if self.protocol.as_deref().is_some_and(|p| p != request.protocol) {
            return false;
        }
        self.client_certificate_difference(request).is_none() && self.jwt_difference(request).is_none()
    }

    /// `ClientIpMatcher.matches` against the request's peer address: `None` when it matches.
    fn client_ip_difference(&self, request: &HttpRequest) -> Option<Difference> {
        self.client_ip.as_ref()?.difference(&request.remote_address)
    }

    /// `ClientCertificateMatcher.matches` against the request's chain: `None` when it matches.
    fn client_certificate_difference(&self, request: &HttpRequest) -> Option<Difference> {
        self.client_certificate.as_ref()?.difference(&request.client_certificates)
    }

    /// `JwtMatcher.matches` against the first value of the token header (`getFirstHeader`): `None` when it matches.
    fn jwt_difference(&self, request: &HttpRequest) -> Option<Difference> {
        let jwt = self.jwt.as_ref()?;
        let name = jwt.header_name();
        let value = request.headers.first(name);
        jwt.difference(value)
    }
}

impl RequestMatcher {
    /// Whether a request whose lower-cased path is not [`RequestMatcher::index_key`] fails this matcher at its path,
    /// with nothing evaluated before it able to time out: a plain method (or none) and no condition.
    pub fn fails_by_literal_path(&self) -> bool {
        self.conditional.is_none() && self.method.as_ref().is_none_or(StringMatcher::is_plain) && self.index_key().is_some()
    }

    /// The lower-cased path when this matcher only matches requests with exactly that path; used to index
    /// expectations. `None` for regex, template, negated or absent paths, or a negated matcher.
    pub fn index_key(&self) -> Option<String> {
        if self.not || self.unsupported || self.openapi.is_some() {
            return None;
        }
        match &self.path {
            Some(p) if p.template.as_ref().is_none_or(|t| !t.value.contains('{')) => p.matcher.literal_key(),
            _ => None,
        }
    }

    /// What a template sees of the path this matcher matched: path parameters (only when the matcher declares
    /// `pathParameters`, as upstream extracts them) and the capture groups of a regex path
    /// (`PathGroupExtractor`).
    pub fn path_match(&self, request: &HttpRequest) -> crate::templates::PathMatch {
        if let Some(alternatives) = self.alternatives() {
            let matched = alternatives.iter().find(|a| a.matches(request, Mode::DataPlane));
            return matched.map(|a| a.path_match(request)).unwrap_or_default();
        }
        let mut out = crate::templates::PathMatch::default();
        if !self.path_parameters.is_empty() && let Some(p) = &self.path {
            let mut parameters = request.path_parameters.clone();
            p.matches(&request.path, &mut parameters);
            out.parameters = self.path_parameters.split_values(&parameters);
        }
        let pattern = match &self.path {
            Some(p) if p.template.is_none() && p.matcher.value.contains('(') => &p.matcher.value,
            _ => return out,
        };
        // `PathGroupExtractor`: `DOTALL` only under `matchExactCase`.
        let flags = if self.path.as_ref().is_some_and(|p| p.exact_case) { "s" } else { "si" };
        let Ok(regex) = fancy_regex::Regex::new(&format!("(?{flags})^(?:{pattern})$")) else { return out };
        let Ok(Some(caps)) = regex.captures(&request.path) else { return out };
        if caps.len() <= 1 {
            return out;
        }
        out.groups = (0..caps.len()).map(|i| caps.get(i).map(|m| m.as_str().to_string())).collect();
        let declared = fancy_regex::Regex::new(r"\(\?<([a-zA-Z][a-zA-Z0-9]*)>").expect("static regex");
        for d in declared.captures_iter(pattern).flatten() {
            let name = d.get(1).expect("group 1").as_str();
            if let Some(m) = caps.name(name) {
                out.named_groups.push((name.to_string(), m.as_str().to_string()));
            }
        }
        out
    }

    /// Why `request` does not match, as upstream's fail-fast `MatchDifference` records it: at most the first
    /// failing field, in matching order. A mismatch caused only by a top-level `not` records nothing (which makes
    /// upstream omit the closest-match hint). Empty also when the request matches.
    pub fn differences(&self, request: &HttpRequest) -> Vec<(&'static str, Difference)> {
        if self.unsupported {
            return Vec::new();
        }
        if self.conditional.is_some() {
            // One context across the branches: each field's first recorded difference, in the order recorded
            // (upstream keeps them in an enum-keyed `HashMap`, identity hash order); an anyOf's closest branch's.
            let context = self.closest_branch_context(request).unwrap_or_else(|| self.traced_context(request));
            return context.into_iter().filter_map(|(field, ds)| ds.into_iter().next().map(|d| (field, d))).collect();
        }
        if let Some(alternatives) = self.alternatives() {
            // `HttpRequestsPropertiesMatcher` merges every operation's differences per field. Upstream keeps them
            // in a `HashMap` keyed by an enum (identity hash order); here the fields come in operation order.
            let mut merged: Vec<(&'static str, Difference)> = Vec::new();
            for a in alternatives {
                for (field, d) in a.differences(request) {
                    if !merged.iter().any(|(f, _)| *f == field) {
                        merged.push((field, d));
                    }
                }
            }
            return merged;
        }
        // The fields evaluated up to the first failing one, each that recorded a difference: a map field that
        // matched after failed comparisons counts too (its first recorded line), then the failing field. A negated
        // matcher fails exactly when every field matched: what the fields recorded on the way is all there is.
        let mut out = Vec::new();
        for (field, difference) in self.field_results_until(request, !self.not) {
            match difference {
                None => {
                    if let Some(first) = self.recorded_texts(field, request, None).into_iter().next() {
                        out.push((field, Difference::Text(first)));
                    }
                }
                Some(d) => {
                    if self.not {
                        // A failing field makes a negated matcher match.
                        return Vec::new();
                    }
                    if !matches!(d, Difference::None) {
                        out.push((field, d));
                    }
                    return out;
                }
            }
        }
        if self.not { out } else { Vec::new() }
    }

    /// Whether [`RequestMatcher::differences`] is exactly one difference because the method or the path fails, told
    /// without building it (the closest-match scan only needs the count of every expectation that cannot
    /// be closer than one difference). Those are the first two fields, so nothing is recorded before them, and their
    /// failures always record a difference. `false` says nothing.
    pub fn fails_at_method_or_path(&self, request: &HttpRequest) -> bool {
        if self.unsupported || self.not || self.conditional.is_some() || self.openapi.is_some() {
            return false;
        }
        // as `field_results_until` evaluates them
        if self.method.as_ref().is_some_and(|m| !request.method.is_empty() && !m.matches(&request.method, !self.exact_case)) {
            return true;
        }
        // `path_differences` is not empty
        self.path.as_ref().is_some_and(|p| (!request.path.is_empty() && !p.matches_regex(&request.path)) || matches!(p.extract(&request.path, &[]), Some(Err(_))))
    }

    /// Every field in upstream's matching order (`HttpRequestPropertiesMatcher.matches`), each with its
    /// difference when it fails.
    fn field_results(&self, request: &HttpRequest) -> Vec<(&'static str, Option<Difference>)> {
        self.field_results_until(request, false)
    }

    /// [`RequestMatcher::field_results`], stopping after the first field that fails when `fail_fast`: the fields
    /// after it are never evaluated (`failFast`), so nothing they would log while evaluating is met (a schema that
    /// throws).
    fn field_results_until(&self, request: &HttpRequest, fail_fast: bool) -> Vec<(&'static str, Option<Difference>)> {
        let mut out: Vec<(&'static str, Option<Difference>)> = Vec::with_capacity(12);
        macro_rules! stop {
            () => {
                if fail_fast && out.last().is_some_and(|(_, d)| d.is_some()) {
                    return out;
                }
            };
        }
        out.push(("method", self.method.as_ref().filter(|m| !request.method.is_empty() && !m.matches(&request.method, !self.exact_case)).map(|m| {
            // A schema-valued method records its schema report (`NottableSchemaString`).
            match m.schema() {
                Some(schema) => multimap::schema_difference(schema, &schema.instance_text(&request.method), &schema.errors(&request.method)),
                None => Difference::String { expected: m.value.clone(), found: request.method.clone() },
            }
        })));
        stop!();
        out.push(("path", self.path_differences(request).into_iter().next()));
        stop!();
        // `clientIp` is compared after method and path, before the body, and only when the matcher has one.
        if self.client_ip.is_some() {
            out.push(("clientIp", self.client_ip_difference(request)));
            stop!();
        }
        // A negated body that fails records no difference upstream.
        out.push(("body", self.body.as_ref().filter(|b| !b.matches(request, false)).map(|b| b.difference(request).unwrap_or(Difference::None))));
        stop!();
        for &field in MAP_FIELDS {
            let skipped = field == "pathParameters" && (!self.has_path() || self.control_plane_parts_differ(request));
            // an empty matcher matches whatever the request holds: its map is not built
            if skipped || self.map_matcher(field).is_some_and(MultiMapMatcher::is_empty) {
                out.push((field, None));
                continue;
            }
            let (matcher, actual, kind) = self.map_field(field, request).expect("a map field");
            let failed = !matcher.matches(&actual, true);
            out.push((field, failed.then(|| matcher.field_difference(&actual, kind))));
            stop!();
        }
        // `BooleanMatcher` records `boolean match failed expected:{}found:{}`.
        let boolean = |expected: bool, found: Option<bool>| {
            let found = found.map_or_else(|| "null".to_string(), |f| f.to_string());
            Difference::Text(format_log_message(1, "boolean match failed expected:{}found:{}", &[&expected.to_string(), &found]))
        };
        let keep_alive = request.keep_alive_flag();
        out.push(("keep-alive", self.keep_alive.filter(|k| Some(*k) != keep_alive).map(|k| boolean(k, keep_alive))));
        out.push(("secure", self.secure.filter(|s| *s != request.secure).map(|s| boolean(s, Some(request.secure)))));
        out.push((
            "protocol",
            self.protocol.as_deref().filter(|p| *p != request.protocol).map(|p| Difference::ExactString { expected: p.to_string(), found: request.protocol.to_string() }),
        ));
        out.push(("clientCertificate", self.client_certificate_difference(request)));
        out.push(("jwt", self.jwt_difference(request)));
        out
    }

    /// The `because` of a data-plane mismatch log entry (`failFast` building its `becauseBuilder`): one line per
    /// evaluated field, the failing field's differences and hints, stopping at the first failure unless the
    /// matcher is negated (then every field is evaluated).
    pub fn because(&self, request: &HttpRequest) -> String {
        self.because_with(request, Reasons::Full)
    }

    /// [`RequestMatcher::because`] as a match without a `MatchDifference` context words it (drift detection's
    /// `matches(requestDefinition)`): the fields alone, no differences or hints.
    pub fn because_brief(&self, request: &HttpRequest) -> String {
        self.because_with(request, Reasons::Brief)
    }

    pub fn because_with(&self, request: &HttpRequest, reasons: Reasons) -> String {
        self.because_after(request, reasons, &Context::new())
    }

    /// [`RequestMatcher::because_with`] with `prior` already in the `MatchDifference` context (earlier branches
    /// of a conditional): a field prints what it holds there before its own differences.
    fn because_after(&self, request: &HttpRequest, reasons: Reasons, prior: &Context) -> String {
        let (detailed, hints) = (reasons == Reasons::Full, reasons != Reasons::Brief);
        if self.unsupported || self.openapi.is_some() || self.conditional.is_some() {
            return String::new();
        }
        let prior_texts = |field: &str| -> Vec<String> {
            prior.iter().filter(|(f, _)| *f == field).flat_map(|(_, ds)| ds.iter().map(Difference::log_text)).filter(|t| !t.is_empty()).collect()
        };
        // a field's texts after those the context held for it (most often none)
        let with_prior = |mut prior: Vec<String>, own: Vec<String>| if prior.is_empty() { own } else { prior.extend(own); prior };
        // `before` and the texts on lines of their own; with `unless_blank`, nothing when they join to nothing
        let texts_into = |out: &mut String, texts: &[String], before: &str, unless_blank: bool| {
            if unless_blank && texts.len() == 1 && texts[0].is_empty() {
                return;
            }
            for (i, text) in texts.iter().enumerate() {
                out.push_str(if i == 0 { before } else { "\n" });
                out.push_str(text);
            }
        };
        // one line per field, written straight into the text
        let mut out = String::with_capacity(256);
        // Most often the method matched and the path did not: its lines are written without evaluating every field.
        if prior.is_empty() && !self.not && self.fails_at_method_or_path(request) && !self.method.as_ref().is_some_and(|m| !request.method.is_empty() && !m.matches(&request.method, !self.exact_case)) {
            out.push_str("method matched\npath didn't match");
            if detailed {
                let texts: Vec<String> = self.path_differences(request).iter().map(Difference::log_text).filter(|t| !t.is_empty()).collect();
                texts_into(&mut out, &texts, ": \n\n", true);
            }
            if hints {
                for hint in self.hints("path", request) {
                    out.push('\n');
                    out.push_str(&hint);
                }
            }
            return out;
        }
        for (field, difference) in self.field_results_until(request, !self.not) {
            if !out.is_empty() {
                out.push('\n');
            }
            out.push_str(field);
            let Some(difference) = difference else {
                // What a field recorded on its way to a match is printed too (`failFast`).
                out.push_str(" matched");
                if detailed {
                    texts_into(&mut out, &with_prior(prior_texts(field), self.recorded_texts(field, request, None)), ": \n\n", false);
                }
                continue;
            };
            out.push_str(" didn't match");
            if detailed {
                texts_into(&mut out, &with_prior(prior_texts(field), self.recorded_texts(field, request, Some(&difference))), ": \n\n", true);
            }
            if hints {
                for hint in self.hints(field, request) {
                    out.push('\n');
                    out.push_str(&hint);
                }
            }
            if self.not {
                out.push_str(",\nexpectation's request 'not' operator is enabled");
            }
            if !self.not {
                break;
            }
        }
        out
    }

    /// Every field's recorded differences with nothing failing fast (`MatchDifference.collectAllDifferences`), as
    /// `debugMismatch` reports them; fields that fail without recording a difference are left out.
    pub fn all_differences(&self, request: &HttpRequest) -> Vec<(&'static str, Vec<String>)> {
        if let Some(branches) = self.conditional.as_ref().and_then(|c| c.any_of()) {
            // `AnyOfRequestMatcher.matchesKeepingClosestBranch` with every difference collected.
            let mut closest: Option<Vec<(&'static str, Vec<String>)>> = None;
            for b in branches {
                if b.matcher.matches(request, Mode::DataPlane) {
                    return Vec::new();
                }
                let differences = b.matcher.all_differences(request);
                if closest.as_ref().is_none_or(|c| differences.len() < c.len()) {
                    closest = Some(differences);
                }
            }
            return closest.unwrap_or_default();
        }
        if self.conditional.is_some() {
            let context = self.traced_context(request);
            return context.into_iter().map(|(field, ds)| (field, ds.iter().map(Difference::log_text).collect())).collect();
        }
        if let Some(alternatives) = self.alternatives() {
            // `HttpRequestsPropertiesMatcher` matches each operation with a fresh, fail-fast context and adds what it
            // recorded to the shared one, each field's texts in operation order. Upstream iterates the enum-keyed
            // `HashMap` in identity hash order; here the fields come in matching order, as the oracle printed them.
            let mut merged: Vec<(&'static str, Vec<String>)> = Vec::new();
            for a in alternatives {
                for (field, texts) in a.fail_fast_differences(request) {
                    match merged.iter_mut().find(|(f, _)| *f == field) {
                        Some((_, recorded)) => recorded.extend(texts),
                        None => merged.push((field, texts)),
                    }
                }
            }
            let order: Vec<&str> = ["method", "path", "body"].into_iter().chain(MAP_FIELDS.iter().copied()).collect();
            merged.sort_by_key(|(field, _)| order.iter().position(|f| f == field).unwrap_or(order.len()));
            return merged;
        }
        self.field_results(request)
            .into_iter()
            .filter_map(|(field, difference)| {
                // A field that matched after failed comparisons is listed with what it recorded, as upstream counts it.
                let texts = self.recorded_texts(field, request, difference.as_ref());
                (!texts.is_empty()).then_some((field, texts))
            })
            .collect()
    }

    /// The lines `MatchDifferenceFormatter` prints for `field` in a verification's closest match diff: every
    /// difference a map field recorded against `request` (its comparisons, then its map failure), else `first`, the
    /// one [`RequestMatcher::differences`] reported.
    pub fn verification_lines(&self, field: &str, request: &HttpRequest, first: &Difference) -> Vec<String> {
        if self.conditional.is_none() && self.alternatives().is_none() && MAP_FIELDS.contains(&field) {
            let failed = self.field_results_until(request, true).into_iter().find(|(f, _)| *f == field).and_then(|(_, d)| d);
            let texts = self.recorded_texts(field, request, failed.as_ref());
            if !texts.is_empty() {
                return texts.iter().map(|t| diff_line(t)).collect();
            }
        }
        // a form or multipart body's maps record every comparison too, an XPath body the parser rejects two differences
        let several = |b: &BodyMatcher| b.records_maps() || b.records_parse_failure(request);
        if field == "body" && self.conditional.is_none() && self.alternatives().is_none() && self.body.as_ref().is_some_and(several) {
            let texts = self.recorded_texts(field, request, Some(first));
            if !texts.is_empty() {
                return texts.iter().map(|t| diff_line(t)).collect();
            }
        }
        vec![diff_line(&first.verification_line())]
    }

    /// What a field records while it is matched: `failed` is its difference when it failed. A map field records its
    /// comparisons (and, failing, its map failure); any other field records only its difference, when it fails.
    fn recorded_texts(&self, field: &str, request: &HttpRequest, failed: Option<&Difference>) -> Vec<String> {
        if field == "path" {
            return self.path_differences(request).iter().map(Difference::log_text).filter(|t| !t.is_empty()).collect();
        }
        // an empty control-plane `pathParameters` matcher compares nothing
        if field == "pathParameters" && self.control_plane_parts_differ(request) {
            return Vec::new();
        }
        // A body matcher can record more than one difference (a JSON body that throws, then fails).
        if let (Some(_), "body", Some(body)) = (failed, field, self.body.as_ref()) {
            return body.recorded_differences(request);
        }
        // A negated body that matches recorded why its inner matcher failed.
        if let (None, "body", Some(body)) = (failed, field, self.body.as_ref()) {
            return body.negated_inner_differences(request);
        }
        // an empty map matcher records nothing ([`MultiMapMatcher::recorded`]): its map is not built
        if self.map_matcher(field).is_some_and(MultiMapMatcher::is_empty) {
            return Vec::new();
        }
        match self.map_field(field, request) {
            Some((matcher, actual, kind)) => matcher.recorded(&actual, failed.is_none(), kind),
            None => failed.map(Difference::log_text).filter(|t| !t.is_empty()).into_iter().collect(),
        }
    }

    /// A map field's matcher (`MAP_FIELDS`).
    fn map_matcher(&self, field: &str) -> Option<&MultiMapMatcher> {
        Some(match field {
            "headers" => &self.headers,
            "cookies" => &self.cookies,
            "pathParameters" => &self.path_parameters,
            "queryParameters" => &self.query,
            _ => return None,
        })
    }

    /// A map field's matcher, the actual map it is matched against and how its failure prints (`MAP_FIELDS`).
    fn map_field(&self, field: &str, request: &HttpRequest) -> Option<(&MultiMapMatcher, MultiMap, multimap::MapKind)> {
        use multimap::MapKind;
        Some(match field {
            "headers" => (&self.headers, request.headers.to_multimap(), MapKind::Headers),
            "cookies" => (&self.cookies, request.cookies.iter().map(|(k, v)| (k.clone(), vec![v.clone()])).collect(), MapKind::Cookies),
            "pathParameters" => {
                // a path with another number of parts extracts nothing: the parameters are matched against none
                let failed = self.path.as_ref().filter(|p| p.template.is_some()).and_then(|p| p.extract(&request.path, &request.path_parameters)).is_some_and(|r| r.is_err());
                let kind = if failed { MapKind::Parameters } else { MapKind::PathParameters };
                (&self.path_parameters, self.path_parameters.split_values(&self.path_parameter_values(request)), kind)
            }
            // Upstream keeps them in arrival order (Netty's `QueryStringDecoder.parameters()`) and matches them in it.
            "queryParameters" => (&self.query, self.query.split_values(&request.query), MapKind::Parameters),
            _ => return None,
        })
    }

    /// A control-plane match builds its `pathParameters` matcher from the recorded request's own path parameters
    /// (`extractPathParameters(request, httpRequest)`); when the request has some and its path has a different number
    /// of parts than this one, that throws and the matcher is empty, so `pathParameters` matches.
    fn control_plane_parts_differ(&self, request: &HttpRequest) -> bool {
        let Some(path) = self.path.as_ref().filter(|_| string::in_control_plane() && !request.path_parameters.is_empty()) else { return false };
        template_parts(&request.path).count() != template_parts(path.original()).count()
    }

    /// Whether the expectation's path is non-blank: upstream matches `pathParameters` only then.
    fn has_path(&self) -> bool {
        self.path.as_ref().is_some_and(|p| !p.original().is_empty())
    }

    /// What the path step records when it fails (`request.path` blank passes the regex but not a part count).
    fn path_differences(&self, request: &HttpRequest) -> Vec<Difference> {
        let Some(p) = &self.path else { return Vec::new() };
        let mut differences = p.differences(&request.path);
        if request.path.is_empty() {
            differences.retain(|d| !matches!(d, Difference::String { .. }));
        }
        differences
    }

    /// The path parameters the path matcher extracts from the request's path.
    fn path_parameter_values(&self, request: &HttpRequest) -> MultiMap {
        let mut values = request.path_parameters.clone();
        // Without a template there is nothing to extract; skipping the regex keeps it to one evaluation (and one
        // regex timeout WARN) per field, as upstream.
        if let Some(p) = self.path.as_ref().filter(|p| p.template.is_some()) {
            p.matches(&request.path, &mut values);
        }
        values
    }

    /// `MatchFailureHints.generateHints` for the path and `Content-Type` header.
    fn hints(&self, field: &str, request: &HttpRequest) -> Vec<String> {
        let mut hints = Vec::new();
        match field {
            "path" => {
                let Some(expected) = self.path.as_ref().map(|p| p.original()) else { return hints };
                let found = request.path.as_str();
                if expected.ends_with('/') != found.ends_with('/') && expected.trim_end_matches('/') == found.trim_end_matches('/') {
                    let describe = |p: &str| if p.ends_with('/') { "ends with '/'" } else { "has no trailing '/'" };
                    hints.push(format!("HINT: trailing slash mismatch - expected path {} but received path {}", describe(expected), describe(found)));
                }
                if expected.contains('.') && !expected.contains("\\.") && expected != found {
                    hints.push("HINT: path contains '.' which matches any character in regex - if you want a literal dot, use '\\.' instead".into());
                }
            }
            "headers" => {
                let expected = self.headers.values_of("content-type");
                let found: Vec<&str> =
                    request.headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case("content-type")).flat_map(|(_, vs)| vs.iter()).collect();
                for e in &expected {
                    for a in &found {
                        let base = |v: &str| v.split(';').next().unwrap_or_default().trim().to_string();
                        if e != a && base(e).eq_ignore_ascii_case(&base(a)) && !e.contains(';') && a.contains("charset") {
                            hints.push(format!(
                                "HINT: Content-Type base type '{}' matches but received value includes charset: '{a}' - consider using a substring matcher or including the charset in the expectation",
                                base(e)
                            ));
                        }
                    }
                }
            }
            _ => {}
        }
        hints
    }

    /// How many of the ten fields upstream counts for an HTTP request (`HTTP_APPLICABLE_FIELDS`) this matcher
    /// satisfies, every field evaluated (`countMatchedApplicableFields`).
    pub fn matched_field_count(&self, request: &HttpRequest) -> usize {
        /// `HTTP_APPLICABLE_FIELDS`: `clientCertificate` and `jwt` are evaluated but not counted.
        const APPLICABLE_FIELDS: [&str; 10] =
            ["method", "path", "pathParameters", "queryParameters", "cookies", "headers", "body", "secure", "protocol", "keep-alive"];
        const APPLICABLE: usize = APPLICABLE_FIELDS.len();
        // A compound's branches share the one fail-fast context (an anyOf's every branch tried, not the closest).
        if self.conditional.is_some() && !self.unsupported {
            return APPLICABLE - self.traced_context(request).len().min(APPLICABLE);
        }
        if self.openapi.is_some() || self.unsupported || self.conditional.is_some() {
            return APPLICABLE - self.differences(request).len().min(APPLICABLE);
        }
        // Every field with a recorded difference counts, one that matched after failed comparisons included.
        let failed = self.all_differences(request).iter().filter(|(field, _)| APPLICABLE_FIELDS.contains(field)).count();
        APPLICABLE - failed
    }

    /// The `matcher{}would match{}if matcher was used for control plane` DEBUG entries a data-plane match of
    /// `request` writes (`RegexStringMatcher.matchesByStrings`): one per string comparison that fails
    /// but would succeed with the request's value read as a regex, in matching order, up to the first failing field
    /// when `fail_fast` (the scan, `findClosestMatchHint`), every field otherwise (`countMatchedApplicableFields`).
    /// With `trace`, each difference the match records is noted too, after its field's `would match` entries: the
    /// TRACE entry `MatchDifference.addDifference(mockServerLogger, …)` writes for it.
    /// A conditional writes its evaluated branches' (`if`, then the chosen one), fail-fast only: the scan logs them
    /// with the branches' match results ([`Logged::Branch`]), and its closest-match re-evaluation writes none. An
    /// OpenAPI matcher writes none: its operations' matchers are control-plane matchers, which never log it.
    pub fn match_notes(&self, request: &HttpRequest, fail_fast: bool, trace: bool) -> Vec<MatchNote> {
        if let Some(c) = self.conditional.as_ref().filter(|_| fail_fast && !self.unsupported) {
            return match &**c {
                Conditional::IfThenElse { guard, then, otherwise } => {
                    let Some(guard) = guard else { return Vec::new() };
                    let mut out = guard.matcher.match_notes(request, true, trace);
                    let chosen = if guard.matcher.matches(request, Mode::DataPlane) { then } else { otherwise };
                    if let Some(branch) = chosen {
                        out.extend(branch.matcher.match_notes(request, true, trace));
                    }
                    out
                }
                // Each branch in order up to the first that matches.
                Conditional::AnyOf(branches) => {
                    let mut out = Vec::new();
                    for b in branches {
                        out.extend(b.matcher.match_notes(request, true, trace));
                        if b.matcher.matches(request, Mode::DataPlane) {
                            break;
                        }
                    }
                    out
                }
            };
        }
        if self.unsupported || self.openapi.is_some() || self.conditional.is_some() {
            return Vec::new();
        }
        let results = self.field_results_until(request, fail_fast && !self.not);
        string::collecting_would_match(|| {
            for (field, difference) in results {
                let map_field = !matches!(field, "method" | "path" | "body");
                match field {
                    "method" => {
                        if let Some(m) = self.method.as_ref().filter(|_| !request.method.is_empty()) {
                            string::note_would_match(m, &request.method, self.exact_case);
                        }
                    }
                    "path" => {
                        if let Some(p) = self.path.as_ref().filter(|_| !request.path.is_empty()) {
                            string::note_would_match(&p.matcher, &request.path, p.exact_case);
                        }
                    }
                    "body" => {
                        if let Some(b) = &self.body {
                            b.note_would_match(request);
                        }
                    }
                    _ => {
                        if let Some((matcher, actual, kind)) = self.map_field(field, request)
                            && !(field == "pathParameters" && !self.has_path())
                        {
                            let texts = matcher.recorded(&actual, difference.is_none(), kind);
                            if trace {
                                string::note_differences(&texts);
                            }
                        }
                    }
                }
                if trace && !map_field {
                    let texts = string::not_collecting(|| self.recorded_texts(field, request, difference.as_ref()));
                    string::note_differences(&texts);
                }
                if fail_fast && difference.is_some() && !self.not {
                    break;
                }
            }
        })
        .1
    }

    /// Notes for [`tracing_received`], when it runs, the differences a fail-fast match of `request` records: each
    /// logs at TRACE (`MatchDifference.addDifference(mockServerLogger, …)`). Whether any were noted (none when
    /// nothing collects).
    pub(crate) fn note_fail_fast(&self, request: &HttpRequest) -> bool {
        if RECEIVED_TRACE.with(|t| t.borrow().is_none()) {
            return false;
        }
        let texts: Vec<String> = self.fail_fast_differences(request).into_iter().flat_map(|(_, texts)| texts).filter(|t| !t.is_empty()).collect();
        let recorded = !texts.is_empty();
        RECEIVED_TRACE.with(|t| {
            if let Some(t) = t.borrow_mut().as_mut() {
                t.extend(texts.iter().map(|text| (string::unindented(text), Traced::Request(Box::new(request.clone())))));
            }
        });
        recorded
    }

    /// What a fail-fast match of `request` records per field (`findClosestMatchHint`'s detailed `MatchDifference`):
    /// the fields evaluated up to the first failing one, each that recorded something, with all it recorded.
    pub fn fail_fast_differences(&self, request: &HttpRequest) -> Vec<(&'static str, Vec<String>)> {
        // A conditional's branches record into one shared context (`ConditionalRequestMatcher.matches`).
        if self.conditional.is_some() && !self.unsupported {
            let context = self.closest_branch_context(request).unwrap_or_else(|| self.traced_context(request));
            return context.into_iter().map(|(field, ds)| (field, ds.iter().map(Difference::log_text).collect())).collect();
        }
        if self.unsupported || self.openapi.is_some() || self.conditional.is_some() {
            return self.differences(request).into_iter().map(|(field, d)| (field, vec![d.log_text()])).collect();
        }
        let mut out = Vec::new();
        for (field, difference) in self.field_results_until(request, !self.not) {
            let texts = self.recorded_texts(field, request, difference.as_ref());
            if !texts.is_empty() {
                out.push((field, texts));
            }
            if difference.is_some() && !self.not {
                break;
            }
        }
        out
    }
}

impl RequestMatcher {
    /// A binary or DNS definition (`binaryData`, `dnsName`), which a data-plane HTTP request never matches.
    pub fn is_unsupported(&self) -> bool {
        self.unsupported
    }

    /// Neither conditional nor OpenAPI: [`RequestMatcher::match_logs`] is `None`, and the match logs as the expectation.
    pub fn logs_as_expectation(&self) -> bool {
        self.conditional.is_none() && self.openapi.is_none()
    }

    /// The match-result log entries a data-plane match writes, for a conditional or OpenAPI matcher (`None` for
    /// any other: it logs as the expectation). `reasons`: what the mismatch reasons carry.
    pub fn match_logs(&self, request: &HttpRequest, reasons: Reasons, debug: bool, trace: bool) -> Option<Vec<Logged>> {
        if self.conditional.is_none() && self.openapi.is_none() {
            return None;
        }
        let mut logs = Vec::new();
        self.trace(request, &mut Context::new(), Some((&mut logs, reasons, debug, trace)), LogAs::Nothing);
        Some(logs)
    }

    /// `AnyOfRequestMatcher.matchesKeepingClosestBranch` (a diagnostic context): the first matching branch's context
    /// (none), else that of the branch with the fewest differing fields, the earlier on a tie. `None` for any other
    /// matcher.
    fn closest_branch_context(&self, request: &HttpRequest) -> Option<Context> {
        let branches = self.conditional.as_ref()?.any_of()?;
        let mut closest: Option<Context> = None;
        for b in branches {
            if b.matcher.matches(request, Mode::DataPlane) {
                return Some(Context::new());
            }
            let context = b.matcher.traced_context(request);
            if closest.as_ref().is_none_or(|c| context.len() < c.len()) {
                closest = Some(context);
            }
        }
        Some(closest.unwrap_or_default())
    }

    /// `RequestMatchExplainer.addAnyOfBranches`, for an anyOf that did not match `request`: every branch compared
    /// with every difference collected, and the closest one (the first matching, else the fewest differing fields,
    /// the earlier on a tie). `None` for any other matcher, or an anyOf without branches.
    pub fn any_of_branches(&self, request: &HttpRequest) -> Option<Value> {
        let branches = self.conditional.as_ref()?.any_of()?;
        if branches.is_empty() {
            return None;
        }
        let mut compared = Vec::new();
        for b in branches {
            let matches = b.matcher.matches(request, Mode::DataPlane);
            let fields: Vec<&str> = if matches { Vec::new() } else { b.matcher.all_differences(request).into_iter().map(|(f, _)| f).collect() };
            compared.push((matches, fields));
        }
        // `AnyOfRequestMatcher.closestBranch`
        let closest = compared.iter().position(|(matches, _)| *matches).or_else(|| (0..compared.len()).min_by_key(|i| compared[*i].1.len()));
        let out: Vec<Value> = compared
            .iter()
            .enumerate()
            .map(|(index, (matches, fields))| serde_json::json!({"branch": index, "matches": matches, "differingFieldCount": fields.len(), "differingFields": fields}))
            .collect();
        Some(serde_json::json!({"closestBranch": closest.map_or(-1, |i| i as i64), "branches": out}))
    }

    /// The `MatchDifference` context a data-plane match leaves behind.
    fn traced_context(&self, request: &HttpRequest) -> Context {
        let mut context = Context::new();
        self.trace(request, &mut context, None, LogAs::Nothing);
        context
    }

    /// A data-plane match that records into one shared `context` (a conditional's branches share it) and, given
    /// `logs`, writes the log entries of the matchers it is made of.
    fn trace(&self, request: &HttpRequest, context: &mut Context, mut logs: Option<(&mut Vec<Logged>, Reasons, bool, bool)>, log_as: LogAs) -> bool {
        if self.unsupported {
            return false;
        }
        if let Some(c) = &self.conditional {
            let matched = match &**c {
                Conditional::IfThenElse { guard, then, otherwise } => {
                    let Some(guard) = guard else { return self.not };
                    let guard_matches = guard.matcher.trace(request, context, logs.as_mut().map(|(l, d, w, t)| (&mut **l, *d, *w, *t)), LogAs::Branch(guard));
                    let chosen = if guard_matches { then } else { otherwise };
                    chosen.as_ref().is_none_or(|b| b.matcher.trace(request, context, logs.as_mut().map(|(l, d, w, t)| (&mut **l, *d, *w, *t)), LogAs::Branch(b)))
                }
                // `AnyOfRequestMatcher.matches`: the caller's context through each branch, up to the first match.
                Conditional::AnyOf(branches) => {
                    branches.iter().any(|b| b.matcher.trace(request, context, logs.as_mut().map(|(l, d, w, t)| (&mut **l, *d, *w, *t)), LogAs::Branch(b)))
                }
            };
            return matched != self.not;
        }
        if let Some(alternatives) = self.alternatives() {
            // `HttpRequestsPropertiesMatcher`: each operation against a fresh context, merged into this one.
            for (alternative, operation) in alternatives.iter().zip(&self.operations) {
                let mut single = Context::new();
                let matched = alternative.trace(request, &mut single, logs.as_mut().map(|(l, d, w, t)| (&mut **l, *d, *w, *t)), LogAs::Operation(operation));
                for (field, ds) in single {
                    merge(context, field, ds);
                }
                if matched {
                    return true;
                }
            }
            return false;
        }
        let matched = self.matches(request, Mode::DataPlane);
        if let Some((logs, reasons, debug, trace)) = logs {
            let because = if matched { String::new() } else { self.because_after(request, reasons, context) };
            match log_as {
                LogAs::Nothing => {}
                LogAs::Branch(b) => {
                    // A branch is a data-plane matcher of its own (`new Expectation(branch)`): its fail-fast match
                    // writes `would match` entries before its result.
                    let notes = if debug { self.match_notes(request, true, trace) } else { Vec::new() };
                    logs.push(Logged::Branch { matched, id: b.id.clone(), expectation: b.expectation.clone(), because, notes })
                }
                LogAs::Operation((description, request)) => {
                    logs.push(Logged::Operation { matched, description: description.clone(), request: request.clone(), because })
                }
            }
        }
        for (field, ds) in self.recorded(request) {
            merge(context, field, ds);
        }
        matched
    }

    /// What a plain matcher records into a `MatchDifference` context, field by field up to the first failing one
    /// (every field under a `not`): a map field its comparisons, any other field its difference.
    fn recorded(&self, request: &HttpRequest) -> Context {
        let mut out = Context::new();
        for (field, difference) in self.field_results_until(request, !self.not) {
            let failed = difference.is_some();
            let differences = match difference {
                _ if field == "path" => self.path_differences(request),
                _ if self.map_field(field, request).is_some() => {
                    self.recorded_texts(field, request, difference.as_ref()).into_iter().map(Difference::Text).collect()
                }
                None | Some(Difference::None) => Vec::new(),
                Some(d) => vec![d],
            };
            merge(&mut out, field, differences);
            if failed && !self.not {
                break;
            }
        }
        out
    }
}

/// What the `because` of a mismatch log entry carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reasons {
    /// Each field's differences and hints: a detailed `MatchDifference` context.
    Full,
    /// Hints but no differences: a context under `detailedMatchFailures=false`, which records nothing.
    Hints,
    /// The fields alone: no context at all.
    Brief,
}

/// One field's mismatch. Only string/regex failures reproduce upstream's wording exactly.
#[derive(Debug, Clone)]
pub enum Difference {
    String { expected: String, found: String },
    ExactString { expected: String, found: String },
    Other(&'static str),
    /// A message already formatted by `format_log_message` (newlines collapse to spaces in the hint).
    Text(String),
    /// The field failed but upstream records nothing (negated matchers).
    None,
}

impl Difference {
    /// As a verification failure's "closest match diff" line (`MatchDifferenceFormatter`).
    pub fn verification_line(&self) -> String {
        match self {
            // `diff_line` flattens the logged text, so an empty value prints with no indent of its own
            Difference::String { .. } | Difference::ExactString { .. } => self.log_text(),
            Difference::Other(m) => format!("  {m}"),
            Difference::Text(t) => t.clone(),
            Difference::None => String::new(),
        }
    }

    /// As a field's differences in a mismatch log entry's `because` (`MatchDifference.addDifference`).
    pub fn log_text(&self) -> String {
        match self {
            Difference::String { expected, found } => {
                format_log_message(1, "string or regex match failed expected:{}found:{}", &[expected, found])
            }
            Difference::ExactString { expected, found } => format_log_message(1, "exact string match failed expected:{}found:{}", &[expected, found]),
            Difference::Other(m) => format_log_message(1, m, &[]),
            Difference::Text(t) => t.clone(),
            Difference::None => String::new(),
        }
    }

    /// As the reason inside `x-mockserver-closest-match-hint`.
    pub fn hint_reason(&self) -> String {
        // `attachClosestMatchHint`: the recorded difference with its line breaks (`[\r\n]+`) collapsed to a space.
        match self {
            Difference::Other(m) => (*m).to_string(),
            Difference::None => String::new(),
            _ => collapse_line_breaks(self.log_text()),
        }
    }
}

/// `text` with each run of line breaks (`[\r\n]+`) replaced by one space.
fn collapse_line_breaks(text: String) -> String {
    if !text.contains(['\r', '\n']) {
        return text;
    }
    let mut out = String::with_capacity(text.len());
    let mut in_breaks = false;
    for c in text.chars() {
        if c == '\r' || c == '\n' {
            if !in_breaks {
                out.push(' ');
            }
            in_breaks = true;
        } else {
            out.push(c);
            in_breaks = false;
        }
    }
    out
}

/// `StringFormatter.formatLogMessage(indent, message, arguments)`: each `{}` becomes its argument on its own
/// lines, indented one level deeper than the message.
pub fn format_log_message(indent: usize, message: &str, arguments: &[&str]) -> String {
    // the arguments' lines take an indent each; a guess that saves most of the growing
    let mut out = String::with_capacity(message.len() + arguments.iter().map(|a| a.len() + a.len() / 8 + 4 + 2 * (indent + 1)).sum::<usize>() + 2 * indent);
    format_log_message_into(&mut out, indent, message, arguments.len(), |i, write| write(arguments[i]));
    out
}

/// [`format_log_message`] appended to `out`, with `arguments` arguments, each handed in as its turn comes by
/// `argument(index, write)` calling `write` with its text: a caller that renders its arguments itself (the console)
/// can render each into one reused buffer and keep no text per argument.
pub fn format_log_message_into(out: &mut String, indent: usize, message: &str, arguments: usize, mut argument: impl FnMut(usize, &mut dyn FnMut(&str))) {
    format_log_message_blocks_into(out, indent, message, arguments, |i, out| argument(i, &mut |text: &str| argument_block_into(out, indent, text)));
}

/// [`format_log_message_into`] with each argument handed in as its whole block ([`argument_block_into`]), which a
/// caller printing the same argument in many messages works out once.
pub fn format_log_message_blocks_into(out: &mut String, indent: usize, message: &str, arguments: usize, mut block: impl FnMut(usize, &mut String)) {
    // `String.split` drops trailing empty parts: the parts of the message without its trailing `{}`s.
    let mut parts = message.trim_end_matches("{}").split("{}").enumerate().peekable();
    while let Some((i, part)) = parts.next() {
        out.push_str(INDENTS[indent]);
        out.push_str(part);
        if i < arguments {
            block(i, out);
        }
        if let Some((_, next)) = parts.peek() {
            out.push('\n');
            if !next.starts_with(' ') {
                out.push(' ');
            }
        }
    }
}

const INDENTS: [&str; 5] = ["", "  ", "    ", "      ", "        "];

/// An argument as a formatted message shows it at `indent`: on lines of its own, each indented one step further.
pub fn argument_block_into(out: &mut String, indent: usize, argument: &str) {
    // `replaceAll("(?m)^", indent)`: every line start but one at the very end of the text, after any of
    // Java's line terminators (`\n`, `\r\n`, `\r`, U+0085, U+2028, U+2029).
    out.push_str("\n\n");
    if !argument.is_empty() {
        out.push_str(INDENTS[indent + 1]);
    }
    // Scanned as bytes, not chars: a terminator is `\n`, `\r` not before `\n`, or the UTF-8 of U+0085
    // (`C2 85`), U+2028 (`E2 80 A8`) or U+2029 (`E2 80 A9`); every other byte is copied as it is.
    let bytes = argument.as_bytes();
    let (mut start, mut at) = (0, 0);
    while let Some(found) = bytes[at..].iter().position(|b| matches!(b, b'\n' | b'\r' | 0xC2 | 0xE2)) {
        let i = at + found;
        let length = match (bytes[i], bytes.get(i + 1), bytes.get(i + 2)) {
            (b'\n', ..) => 1,
            (b'\r', next, _) => usize::from(next != Some(&b'\n')),
            (0xC2, Some(0x85), _) => 2,
            (0xE2, Some(0x80), Some(0xA8 | 0xA9)) => 3,
            _ => 0,
        };
        let end = i + length;
        if length > 0 && end < bytes.len() {
            out.push_str(&argument[start..end]);
            out.push_str(INDENTS[indent + 1]);
            start = end;
        }
        at = i + 1;
    }
    out.push_str(&argument[start..]);
    out.push('\n');
}

impl PathMatcher {
    /// The regex the path is matched with (`normalisePathWithParametersForMatching`), as differences quote it.
    fn value(&self) -> &str {
        &self.matcher.value
    }

    /// The path as the expectation gives it (`MatchFailureHints` looks at this, not the regex).
    fn original(&self) -> &str {
        self.template.as_ref().map(|t| t.value.as_str()).unwrap_or(&self.matcher.value)
    }

    fn compile(v: &Value, has_parameters: bool) -> PathMatcher {
        let plain = StringMatcher::compile(v);
        if !has_parameters {
            return PathMatcher { matcher: plain, template: None, exact_case: exact_case() };
        }
        // `NottableString.getValue()`: the normalised path keeps no `!`, even for a template-free path the
        // matcher is rebuilt from (upstream reuses the path itself there, so the negation stays).
        let value = plain.value.clone();
        let matcher = if value.contains('{') { StringMatcher::from_text(&normalise_path_template(&value)) } else { plain };
        let template = PathTemplate { parts: template_parts(&value).map(|part| path_variable_name(part).map(str::to_string)).collect(), value };
        PathMatcher { matcher, template: Some(template), exact_case: exact_case() }
    }

    /// The regex match alone.
    fn matches_regex(&self, path: &str) -> bool {
        self.matcher.matches(path, !self.exact_case)
    }

    /// The whole path step of `HttpRequestPropertiesMatcher.matches`: the regex, then (when the matcher declares
    /// path parameters) `extractPathParameters` on top of the request's own (`parameters`), whose part-count failure
    /// fails the path too.
    fn matches(&self, path: &str, parameters: &mut MultiMap) -> bool {
        let regex = self.matches_regex(path);
        match self.extract(path, parameters) {
            Some(Ok(extracted)) => {
                *parameters = extracted;
                regex
            }
            Some(Err(_)) => false,
            None => regex,
        }
    }

    /// Everything the path step records when it fails: the regex failure, then the part-count failure.
    fn differences(&self, path: &str) -> Vec<Difference> {
        let mut out = Vec::new();
        if !self.matches_regex(path) {
            out.push(Difference::String { expected: self.value().to_string(), found: path.to_string() });
        }
        if let Some(Err(message)) = self.extract(path, &[]) {
            out.push(Difference::Text(format_log_message(1, &message, &[])));
        }
        out
    }

    /// `PathParametersDecoder.extractPathParameters`, `None` without declared path parameters: the request's own
    /// path parameters (`seed`, set by an earlier match) with each template part's new values added, or the
    /// part-count failure.
    fn extract(&self, path: &str, seed: &[(String, Vec<String>)]) -> Option<Result<MultiMap, String>> {
        let template = self.template.as_ref()?;
        let matched: Vec<&str> = template_parts(path).collect();
        if template.parts.len() != matched.len() {
            let n = matched.len();
            return Some(Err(format!(
                "expected path {} has {} parts but path {path} has {n} part{}",
                template.value,
                template.parts.len(),
                if n > 1 { "s " } else { " " }
            )));
        }
        let mut parameters: MultiMap = seed.to_vec();
        for (name, segment) in template.parts.iter().zip(matched) {
            let Some(name) = name else { continue };
            let existing: Vec<String> = parameters.iter().filter(|(k, _)| k == name).flat_map(|(_, vs)| vs.clone()).collect();
            for value in segment_values(name, segment).into_iter().filter(|v| !existing.contains(v)) {
                crate::request::push(&mut parameters, name, value);
            }
        }
        Some(Ok(parameters))
    }
}

/// `PATH_VARIABLE_NAME_PATTERN` (`\{[.;]?([^*]+)\*?}`) matched against a whole path part: the parameter's name.
fn path_variable_name(part: &str) -> Option<&str> {
    static VARIABLE: std::sync::LazyLock<fancy_regex::Regex> =
        std::sync::LazyLock::new(|| fancy_regex::Regex::new(r"^\{[.;]?([^*]+)\*?\}$").expect("static regex"));
    VARIABLE.captures(part).ok().flatten().and_then(|c| c.get(1)).map(|m| m.as_str())
}

/// `normalisePathWithParametersForMatching`: each template part becomes `.*`. Java's `String.split("/")` drops
/// trailing empty parts; a trailing `/` is put back.
fn normalise_path_template(value: &str) -> String {
    let mut parts: Vec<&str> = value.split('/').collect();
    while parts.last().is_some_and(|p| p.is_empty()) {
        parts.pop();
    }
    let joined: Vec<&str> = parts.into_iter().map(|p| if path_variable_name(p).is_some() { ".*" } else { p }).collect();
    format!("{}{}", joined.join("/"), if value.ends_with('/') { "/" } else { "" })
}

/// `getPathParts`: the path without its leading `/`, split on `/`, blank parts dropped.
fn template_parts(path: &str) -> impl Iterator<Item = &str> {
    path.strip_prefix('/').unwrap_or(path).split('/').filter(|p| !p.trim().is_empty())
}

/// A path segment's values for parameter `name` (`[.;]?(?:name=)?([^,]++)[.,;]?`, found repeatedly): label (`.a`)
/// and matrix (`;name=a`) prefixes dropped, comma-separated values apart. Exploded styles are split further by
/// `ExpandedParameterDecoder.splitParameters` ([`MultiMapMatcher::split_values`]).
fn segment_values(name: &str, segment: &str) -> Vec<String> {
    let pattern = format!(r"[.;]?(?:{}=)?([^,]++)[.,;]?", fancy_regex::escape(name));
    let Ok(regex) = fancy_regex::Regex::new(&pattern) else { return vec![segment.to_string()] };
    regex.captures_iter(segment).flatten().filter_map(|c| c.get(1).map(|m| m.as_str().to_string())).collect()
}

#[cfg(test)]
mod tests {
    use super::{MatchNote, Mode, RequestMatcher};
    use crate::request::HttpRequest;
    use serde_json::json;

    fn get(path: &str) -> HttpRequest {
        HttpRequest { method: "GET".into(), path: path.into(), ..HttpRequest::default() }
    }

    /// `RegexStringMatcher`'s data-plane `would match`: the request's value read as a regex, only where
    /// equality and the matcher's own regex failed; the scan stops at the first failing field, the closest-match
    /// re-evaluation does not.
    #[test]
    fn would_match_notes_request_values_that_match_as_a_regex() {
        let m = RequestMatcher::compile(&json!({"path": "/abc", "headers": {"x-key": ["abcdef"]}}));
        let pairs = |r: &HttpRequest, fail_fast: bool| -> Vec<(String, String)> {
            m.match_notes(r, fail_fast, false)
                .into_iter()
                .map(|n| match n {
                    MatchNote::WouldMatch(w) => (w.matcher, w.matched),
                    MatchNote::Difference(d) => panic!("a difference noted without trace: {d}"),
                })
                .collect()
        };
        let mut request = get("/a.c");
        request.headers = vec![("x-key".into(), vec!["ab.*".into()])].into();
        assert_eq!(pairs(&request, true), vec![("/abc".to_string(), "/a.c".to_string())]);
        assert_eq!(pairs(&request, false), vec![("/abc".to_string(), "/a.c".to_string()), ("abcdef".to_string(), "ab.*".to_string())]);
        // A plain literal is never read as a regex, and a value that matches outright notes nothing.
        let mut literal = get("/abd");
        literal.headers = vec![("x-key".into(), vec!["abcdef".into()])].into();
        assert!(pairs(&literal, false).is_empty());
    }

    /// At TRACE each recorded difference is noted as its own entry's message (indent 0), after its
    /// field's `would match` notes; fail-fast stops at the first failing field.
    #[test]
    fn match_notes_carry_each_recorded_difference_when_traced() {
        let m = RequestMatcher::compile(&json!({"method": "POST", "path": "/abc"}));
        let differences = |fail_fast: bool| -> Vec<String> {
            m.match_notes(&get("/a.c"), fail_fast, true)
                .into_iter()
                .filter_map(|n| match n {
                    MatchNote::Difference(d) => Some(d),
                    MatchNote::WouldMatch(_) => None,
                })
                .collect()
        };
        let method = "string or regex match failed expected:\n\n  POST\n\n found:\n\n  GET\n".to_string();
        let path = "string or regex match failed expected:\n\n  /abc\n\n found:\n\n  /a.c\n".to_string();
        assert_eq!(differences(true), vec![method.clone()]);
        assert_eq!(differences(false), vec![method, path]);
    }

    #[test]
    fn path_templates_extract_parameters() {
        let m = RequestMatcher::compile(&json!({"path": "/users/{id}", "pathParameters": {"id": ["[0-9]+"]}}));
        assert!(m.matches(&get("/users/42"), Mode::DataPlane));
        assert!(!m.matches(&get("/users/abc"), Mode::DataPlane));
    }

    /// `HttpRequestsPropertiesMatcherTest.shouldMatchByPathWith*PathParameter`: a template with one `minimum: 1`
    /// integer parameter in `style`.
    fn styled(path: &str, params: &[(&str, &str)]) -> RequestMatcher {
        let mut path_parameters = serde_json::Map::new();
        path_parameters.insert("keyMatchStyle".into(), json!("MATCHING_KEY"));
        for (name, style) in params {
            path_parameters.insert(name.to_string(), json!({"parameterStyle": style, "values": [{"schema": {"minimum": 1, "type": "integer"}}]}));
        }
        RequestMatcher::compile(&json!({"method": "GET", "path": path, "pathParameters": path_parameters}))
    }

    fn hint(m: &RequestMatcher, path: &str) -> Option<(&'static str, String)> {
        m.differences(&get(path)).into_iter().next().map(|(field, d)| (field, d.hint_reason()))
    }

    #[test]
    fn path_parameter_styles_match() {
        let cases: &[(&str, &str, &[&str], &[&str])] = &[
            ("/somePath/{someParam}", "SIMPLE", &["/somePath/1", "/somePath/1,2,3"], &["/somePath/0", "/somePath/a,1"]),
            ("/somePath/{someParam*}", "SIMPLE_EXPLODED", &["/somePath/1,2,3", "/somePath/1"], &["/somePath/0,1,2", "/somePath/a,1,2"]),
            ("/somePath/{.someParam}", "LABEL", &["/somePath/.1,2,3", "/somePath/.1"], &["/somePath/.0,1,2", "/somePath/.a,1,2"]),
            ("/somePath/{.someParam*}", "LABEL_EXPLODED", &["/somePath/.1.2.3", "/somePath/.1"], &["/somePath/.0.1.2", "/somePath/.a.1.2"]),
            ("/somePath/{;someParam}", "MATRIX", &["/somePath/;someParam=1,2,3", "/somePath/;someParam=1"], &["/somePath/;someParam=0,1", "/somePath/;someOtherParam=1"]),
            (
                "/somePath/{;someParam*}",
                "MATRIX_EXPLODED",
                &["/somePath/;someParam=1;someParam=2;someParam=3", "/somePath/;someParam=1"],
                &["/somePath/;someParam=0;someParam=1", "/somePath/;someOtherParam=1;someOtherParam=2"],
            ),
        ];
        for (template, style, matching, failing) in cases {
            let m = styled(template, &[("someParam", style)]);
            for path in *matching {
                assert!(m.matches(&get(path), Mode::DataPlane), "{style}: {path}");
            }
            for path in *failing {
                assert!(!m.matches(&get(path), Mode::DataPlane), "{style}: {path}");
                assert_eq!(hint(&m, path).map(|(f, _)| f), Some("pathParameters"), "{style}: {path}");
            }
        }
    }

    #[test]
    fn mixed_path_parameter_styles_match() {
        let m = styled("/somePath/{.someLabelParam}/{;someMatrixParam*}", &[("someMatrixParam", "MATRIX_EXPLODED"), ("someLabelParam", "LABEL")]);
        assert!(m.matches(&get("/somePath/.1,2,3/;someMatrixParam=1;someMatrixParam=2"), Mode::DataPlane));
        assert!(!m.matches(&get("/somePath/.0,1/;someMatrixParam=1"), Mode::DataPlane));
        assert!(!m.matches(&get("/somePath/.1/;someMatrixParam=0"), Mode::DataPlane));
    }

    /// `fails_at_method_or_path` claims exactly one difference only where `differences` has exactly one.
    #[test]
    fn fails_at_method_or_path_means_one_difference() {
        let matchers = [
            json!({"method": "GET", "path": "/e1"}),
            json!({"method": "POST", "path": "/e1"}),
            json!({"path": "/e.*"}),
            json!({"method": "!GET", "path": "/e1"}),
            json!({"method": {"type": "string", "pattern": "^P"}, "path": "/e1"}),
            json!({"method": "GET", "path": "/e1", "headers": {"x-a": ["b"]}}),
            json!({"method": "GET", "path": "/somePath/{p}", "pathParameters": {"p": ["1"]}}),
            json!({"method": "GET", "path": "/e1", "not": true}),
            json!({"path": "/e1", "body": {"not": true, "type": "STRING", "string": "x"}}),
            json!({"path": "/e1", "queryStringParameters": {"q": ["1"]}}),
        ];
        let mut requests = vec![get("/e1"), get("/none"), get(""), get("/somePath/"), get("/somePath/1"), get("/somePath/2")];
        let mut post = get("/e1");
        post.method = "POST".into();
        requests.push(post);
        let mut headed = get("/none");
        headed.headers = vec![("x-a".into(), vec!["c".into()])].into();
        requests.push(headed);
        let mut claimed = 0;
        for definition in &matchers {
            let m = RequestMatcher::compile(definition);
            for r in &requests {
                if m.fails_at_method_or_path(r) {
                    claimed += 1;
                    assert!(!m.matches(r, Mode::DataPlane), "{definition} {} {}", r.method, r.path);
                    assert_eq!(m.differences(r).len(), 1, "{definition} {} {}", r.method, r.path);
                }
            }
        }
        assert!(claimed > 10, "{claimed}");
    }

    #[test]
    fn a_literal_path_that_differs_fails_the_matcher_at_its_path() {
        let matchers = [
            json!({"method": "GET", "path": "/e1"}),
            json!({"path": "/E1", "headers": {"x-a": ["b"]}}),
            json!({"method": "!POST", "path": "/e1", "body": "x"}),
            json!({"method": "P.*", "path": "/e1"}),
            json!({"path": "/e.*"}),
            json!({"path": "/somePath/{p}", "pathParameters": {"p": ["1"]}}),
            json!({"path": "/e1", "not": true}),
            json!({"path": "!/e1"}),
            json!({"path": "/e1", "matchExactCase": true}),
        ];
        let requests = [get("/e1"), get("/E1"), get("/e2"), get("/none"), get("/e1/"), get("/somePath/1")];
        let mut claimed = 0;
        for definition in &matchers {
            let m = RequestMatcher::compile(definition);
            if !m.fails_by_literal_path() {
                continue;
            }
            let key = m.index_key().expect("a literal path");
            for r in requests.iter().filter(|r| r.path.to_ascii_lowercase() != key) {
                claimed += 1;
                assert!(m.fails_at_method_or_path(r), "{definition} {}", r.path);
                assert!(!m.matches(r, Mode::DataPlane), "{definition} {}", r.path);
                assert!(!m.differences(r).is_empty(), "{definition} {}", r.path);
            }
        }
        assert!(claimed > 10, "{claimed}");
        for unplain in [json!({"method": "P.*", "path": "/e1"}), json!({"path": "/e.*"}), json!({"path": "/e1", "not": true})] {
            assert!(!RequestMatcher::compile(&unplain).fails_by_literal_path(), "{unplain}");
        }
    }

    #[test]
    fn path_template_differences_quote_the_regex_or_the_part_count() {
        let m = styled("/somePath/{someParam}", &[("someParam", "SIMPLE")]);
        // `.*` matches the empty part, so only the part count fails.
        assert_eq!(hint(&m, "/somePath/"), Some(("path", "  expected path /somePath/{someParam} has 2 parts but path /somePath/ has 1 part ".into())));
        // Both fail; the regex failure is recorded first.
        assert_eq!(hint(&m, "/somePath"), Some(("path", "  string or regex match failed expected:     /somePath/.*    found:     /somePath ".into())));
        let two = styled("/somePath/{a}/{.b*}", &[("a", "SIMPLE"), ("b", "LABEL_EXPLODED")]);
        assert_eq!(hint(&two, "/somePath/a").map(|(_, h)| h), Some("  string or regex match failed expected:     /somePath/.*/.*    found:     /somePath/a ".into()));
    }

    #[test]
    fn path_parameter_schema_failure_is_the_hint() {
        let m = styled("/somePath/{;someParam*}", &[("someParam", "MATRIX_EXPLODED")]);
        let (field, reason) = hint(&m, "/somePath/;someParam=0;someParam=1;someParam=2").expect("a difference");
        assert_eq!(field, "pathParameters");
        assert!(reason.starts_with("  schema match failed expect:"), "{reason}");
        assert!(reason.contains("found:     0 "), "{reason}");
    }

    #[test]
    fn path_parameters_without_a_path_are_not_matched() {
        // `HttpRequestPropertiesMatcherTest.shouldMatchPathParameterInParameterObject`: upstream skips the map when
        // the expectation's path is blank.
        let m = RequestMatcher::compile(&json!({"pathParameters": {"someKey": ["someValue"]}}));
        assert!(m.matches(&get("/"), Mode::DataPlane));
    }

    #[test]
    fn missing_path_parameters_fail_with_the_whole_map() {
        let m = styled("/somePath", &[("someParam", "SIMPLE")]);
        let (field, reason) = hint(&m, "/somePath").expect("a difference");
        assert_eq!(field, "pathParameters");
        assert!(reason.starts_with("  multimap match failed expected:     {       \"keyMatchStyle\" : \"MATCHING_KEY\",       \"someParam\" : {         \"parameterStyle\" : \"SIMPLE\",         \"values\" : [ {"), "{reason}");
        // `extractPathParameters` always yields an object: an empty one, not `none`.
        assert!(reason.contains("found:     { }    failed because:     multimap values don't match"), "{reason}");
    }

    #[test]
    fn negated_matcher_and_method() {
        let m = RequestMatcher::compile(&json!({"not": true, "path": "/negated"}));
        assert!(m.matches(&get("/other"), Mode::DataPlane));
        assert!(!m.matches(&get("/negated"), Mode::DataPlane));
        let not_get = RequestMatcher::compile(&json!({"method": "!GET"}));
        assert!(!not_get.matches(&get("/x"), Mode::DataPlane));
    }

    #[test]
    fn path_is_case_insensitive_and_not_percent_decoded() {
        let m = RequestMatcher::compile(&json!({"path": "/case/Path"}));
        assert!(m.matches(&get("/CASE/path"), Mode::DataPlane));
        let space = RequestMatcher::compile(&json!({"path": "/enc path"}));
        assert!(!space.matches(&get("/enc%20path"), Mode::DataPlane));
    }

    #[test]
    fn list_form_input_is_accepted() {
        let m = RequestMatcher::compile(&json!({"headers": [{"name": "X-A", "values": ["1"]}]}));
        let mut r = get("/");
        r.headers = vec![("x-a".into(), vec!["1".into()])].into();
        assert!(m.matches(&r, Mode::DataPlane));
    }

    // `ConditionalRequestMatcherTest`.

    fn request(method: &str, path: &str, headers: &[(&str, &str)]) -> HttpRequest {
        let headers = headers.iter().map(|(k, v)| (k.to_string(), vec![v.to_string()])).collect();
        HttpRequest { method: method.into(), path: path.into(), headers, ..HttpRequest::default() }
    }

    fn matches(conditional: serde_json::Value, request: &HttpRequest) -> bool {
        RequestMatcher::compile(&conditional).matches(request, Mode::DataPlane)
    }

    #[test]
    fn conditional_guard_true_requires_then() {
        let c = json!({"if": {"method": "GET"}, "then": {"path": "/admin"}});
        assert!(matches(c.clone(), &request("GET", "/admin", &[])));
        assert!(!matches(c, &request("GET", "/public", &[])));
    }

    #[test]
    fn conditional_guard_false_requires_else() {
        let c = json!({"if": {"method": "GET"}, "then": {"path": "/admin"}, "else": {"path": "/public"}});
        assert!(matches(c.clone(), &request("POST", "/public", &[])));
        assert!(!matches(c, &request("POST", "/admin", &[])));
    }

    #[test]
    fn conditional_missing_branches() {
        // Guard false and no else: matches. Guard true and no then: matches.
        let no_else = json!({"if": {"method": "GET"}, "then": {"path": "/admin"}});
        assert!(matches(no_else.clone(), &request("POST", "/anything", &[])));
        assert!(!matches(no_else, &request("GET", "/anything", &[])));
        assert!(matches(json!({"if": {"method": "GET"}}), &request("GET", "/anything", &[])));
    }

    #[test]
    fn conditional_compound_branches() {
        let c = json!({"if": {"method": "GET", "headers": {"X-Env": ["prod"]}}, "then": {"path": "/v2", "headers": {"X-Trace": ["abc"]}}});
        assert!(matches(c.clone(), &request("GET", "/v2", &[("X-Env", "prod"), ("X-Trace", "abc")])));
        assert!(!matches(c.clone(), &request("GET", "/v2", &[("X-Env", "prod")])));
        assert!(matches(c, &request("GET", "/v2", &[("X-Env", "staging")])));
    }

    #[test]
    fn conditional_nested() {
        let c = json!({"if": {"method": "GET"}, "then": {"if": {"headers": {"X-Env": ["prod"]}}, "then": {"path": "/admin"}}});
        assert!(matches(c.clone(), &request("GET", "/admin", &[("X-Env", "prod")])));
        assert!(!matches(c.clone(), &request("GET", "/other", &[("X-Env", "prod")])));
        assert!(matches(c, &request("GET", "/other", &[("X-Env", "staging")])));
    }

    #[test]
    fn conditional_without_guard_never_matches() {
        // The schema requires `if`; a definition built without one (`ConditionalRequestDefinition.withThen`) fails.
        let m = RequestMatcher { conditional: Some(Box::new(super::Conditional::IfThenElse { guard: None, then: None, otherwise: None })), ..RequestMatcher::any() };
        assert!(!m.matches(&request("GET", "/admin", &[]), Mode::DataPlane));
    }

    #[test]
    fn conditional_not_negates_the_result() {
        let c = json!({"not": true, "if": {"method": "GET"}, "then": {"path": "/admin"}});
        assert!(!matches(c.clone(), &request("GET", "/admin", &[])));
        assert!(matches(c.clone(), &request("GET", "/other", &[])));
        assert!(!matches(c, &request("POST", "/anything", &[])));
    }

    #[test]
    fn conditional_branches_share_one_difference_context() {
        // The closest-match hint of a failing `then` also carries what the matched guard recorded (its header
        // comparisons), as upstream's single `MatchDifference` does.
        let c = RequestMatcher::compile(&json!({"if": {"headers": {"X-Tenant": ["a"]}}, "then": {"path": "/a"}}));
        let r = request("GET", "/b", &[("host", "h"), ("X-Tenant", "a")]);
        let fields: Vec<&str> = c.differences(&r).iter().map(|(f, _)| *f).collect();
        assert_eq!(fields, ["headers", "path"]);
    }

    // `AnyOfRequestMatcherTest`.

    #[test]
    fn any_of_matches_when_any_branch_matches() {
        let a = json!({"anyOf": [{"method": "GET", "path": "/a"}, {"path": "/b"}, {"path": "/c", "headers": {"X-Flag": ["on"]}}]});
        assert!(matches(a.clone(), &request("GET", "/a", &[])));
        assert!(matches(a.clone(), &request("POST", "/b", &[])));
        assert!(matches(a.clone(), &request("GET", "/c", &[("X-Flag", "on")])));
        assert!(!matches(a.clone(), &request("POST", "/a", &[])));
        assert!(!matches(a, &request("GET", "/c", &[])));
    }

    #[test]
    fn any_of_without_branches_matches_nothing() {
        assert!(!matches(json!({"anyOf": []}), &request("GET", "/a", &[])));
    }

    #[test]
    fn any_of_not_matches_when_no_branch_matches() {
        let a = json!({"not": true, "anyOf": [{"path": "/a"}, {"path": "/b"}]});
        assert!(!matches(a.clone(), &request("GET", "/a", &[])));
        assert!(!matches(a.clone(), &request("GET", "/b", &[])));
        assert!(matches(a, &request("GET", "/c", &[])));
    }

    #[test]
    fn any_of_composes_with_nested_any_of_and_conditional_branches() {
        let a = json!({"anyOf": [{"anyOf": [{"path": "/x"}, {"path": "/y"}]}, {"if": {"method": "PUT"}, "then": {"path": "/z"}}]});
        assert!(matches(a.clone(), &request("GET", "/y", &[])));
        assert!(matches(a.clone(), &request("PUT", "/z", &[])));
        // the conditional's guard fails and it has no else: it matches
        assert!(matches(a.clone(), &request("GET", "/other", &[])));
        assert!(!matches(a, &request("PUT", "/other", &[])));
    }

    #[test]
    fn any_of_hint_reports_the_closest_branch() {
        // Diagnostics keep the branch with the fewest differing fields, the earlier on a tie.
        let a = RequestMatcher::compile(&json!({"anyOf": [{"method": "GET", "path": "/a"}, {"path": "/b"}]}));
        let fields: Vec<&str> = a.differences(&request("POST", "/b", &[])).iter().map(|(f, _)| *f).collect();
        assert!(fields.is_empty());
        // fail fast, each branch differs on one field (the first on its method): the first branch
        let fields: Vec<&str> = a.differences(&request("POST", "/c", &[])).iter().map(|(f, _)| *f).collect();
        assert_eq!(fields, ["method"]);
        // every difference collected, the first differs on two fields, the second on one
        let branches = a.any_of_branches(&request("POST", "/c", &[])).unwrap();
        assert_eq!(branches["closestBranch"], 1);
        assert_eq!(branches["branches"][0]["differingFieldCount"], 2);
        assert_eq!(branches["branches"][1]["differingFields"], json!(["path"]));
    }

    /// `format_log_message` indents each line of an argument after every Java line terminator but a final one, as the
    /// char-by-char version it replaced did.
    #[test]
    fn format_log_message_indents_every_argument_line_after_java_line_terminators() {
        fn reference(indent: usize, message: &str, arguments: &[&str]) -> String {
            const INDENTS: [&str; 5] = ["", "  ", "    ", "      ", "        "];
            let mut parts: Vec<&str> = message.split("{}").collect();
            while parts.len() > 1 && parts.last() == Some(&"") {
                parts.pop();
            }
            let mut out = String::new();
            for (i, part) in parts.iter().enumerate() {
                out.push_str(INDENTS[indent]);
                out.push_str(part);
                if let Some(argument) = arguments.get(i) {
                    let chars: Vec<char> = argument.chars().collect();
                    let mut indented = String::from(if chars.is_empty() { "" } else { INDENTS[indent + 1] });
                    for (n, c) in chars.iter().enumerate() {
                        indented.push(*c);
                        let terminator = matches!(c, '\n' | '\u{85}' | '\u{2028}' | '\u{2029}') || (*c == '\r' && chars.get(n + 1) != Some(&'\n'));
                        if terminator && n + 1 < chars.len() {
                            indented.push_str(INDENTS[indent + 1]);
                        }
                    }
                    out.push_str(&format!("\n\n{indented}\n"));
                }
                if i < parts.len() - 1 {
                    out.push('\n');
                    if !parts[i + 1].starts_with(' ') {
                        out.push(' ');
                    }
                }
            }
            out
        }
        let arguments = [
            "",
            "plain",
            "{\n  \"a\" : 1\n}",
            "a\r\nb\rc\u{85}d\u{2028}e\u{2029}f\n",
            "\r",
            "x\r",
            "\n\n",
            "é\nü\u{2028}",
            "\u{85}x\u{85}",
            "a\r\n",
            "\r\n\r\nb",
            "\u{2028}\u{2029}\u{2027}\u{202A}Â€",
        ];
        for indent in 0..3 {
            for a in arguments {
                for b in arguments {
                    for message in ["request:{}matched expectation:{}", "{}{}", "a{} b{}", "only{}"] {
                        assert_eq!(super::format_log_message(indent, message, &[a, b]), reference(indent, message, &[a, b]), "{indent} {message:?} {a:?} {b:?}");
                    }
                }
            }
        }
    }
}
