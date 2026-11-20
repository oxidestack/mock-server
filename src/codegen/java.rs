//! `retrieve?format=JAVA`: MockServer's `serialization.java` package (`ExpectationToJavaSerializer` and friends),
//! reproduced line for line from the model in [`super::model`].
//!
//! `Err` carries the message of the `NullPointerException` upstream throws for the same input (the oracle answers
//! `400` with it).

use base64::Engine;
use java_compat::escape_java;
use serde_json::{Map, Value};

use crate::model::{self, Body, Entries, NString, ResponseBody, get};

const INDENT: usize = 8;

type Result<T> = std::result::Result<T, String>;

fn nl(out: &mut String, spaces: usize) -> &mut String {
    out.push('\n');
    out.extend(std::iter::repeat_n(' ', spaces));
    out
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn str_of<'a>(o: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    get(o, key).and_then(Value::as_str)
}

fn not_blank(s: Option<&str>) -> Option<&str> {
    s.filter(|s| !s.trim().is_empty())
}

/// Java's `String.valueOf(Integer/Long/Boolean)` of a JSON scalar.
fn scalar(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// One expectation to generate: its input JSON, its id (`None` for recorded expectations, which upstream writes
/// without one: `new ExpectationToJavaSerializer(false)`) and its current `times` (with the remaining count).
pub struct Source<'a> {
    pub input: &'a Value,
    pub id: Option<&'a str>,
    pub times: &'a Value,
    pub time_to_live: &'a Value,
}

/// `ExpectationToJavaSerializer.serialize(List)`.
pub fn expectations(list: &[Source]) -> Result<String> {
    let mut out = String::new();
    for e in list {
        out.push_str(&expectation(0, e)?);
        out.push_str("\n\n");
    }
    Ok(out)
}

/// A serializer of one model object at an indent.
type Writer = fn(usize, &Value) -> Result<String>;

/// An action's call in the `.when(...)` form, in the `.upsert(...)` form, and its serializer.
type ActionCall = (&'static str, &'static str, Writer);

/// The actions after the response (list), in the order `ExpectationToJavaSerializer.write` writes them: the input
/// key, the call each is written with (`.when(...)` form, `.upsert(...)` form) and its serializer. `None` for the
/// object callbacks, which are a comment and not counted as actions.
const ACTIONS: &[(&str, Option<ActionCall>)] = &[
    ("httpResponseTemplate", Some((".respond(", ".thenRespond(", template))),
    ("httpResponseClassCallback", Some((".respond(", ".thenRespond(", class_callback))),
    ("httpResponseObjectCallback", None),
    ("httpForward", Some((".forward(", ".thenForward(", forward))),
    ("httpOverrideForwardedRequest", Some((".forward(", ".thenForward(", override_forwarded))),
    ("httpForwardTemplate", Some((".forward(", ".thenForward(", template))),
    ("httpForwardClassCallback", Some((".forward(", ".thenForward(", class_callback))),
    ("httpForwardObjectCallback", None),
    ("httpForwardValidateAction", Some((".thenForwardValidate(", ".thenForwardValidate(", forward_validate))),
    ("httpForwardWithFallback", Some((".forwardWithFallback(", ".thenForwardWithFallback(", forward_with_fallback))),
    ("httpError", Some((".error(", ".thenError(", error))),
    ("httpSseResponse", Some((".respondWithSse(", ".thenRespondWithSse(", sse_response))),
    ("httpLlmResponse", Some((".respondWithLlm(", ".thenRespondWithLlm(", llm_response))),
    ("httpWebSocketResponse", Some((".respondWithWebSocket(", ".thenRespondWithWebSocket(", web_socket_response))),
    ("grpcStreamResponse", Some((".respondWithGrpcStream(", ".thenRespondWithGrpcStream(", grpc_stream_response))),
    ("grpcBidiResponse", Some((".respondWithGrpcBidi(", ".thenRespondWithGrpcBidi(", grpc_bidi_response))),
    ("binaryResponse", Some((".respondWithBinary(", ".thenRespondWithBinary(", binary_response))),
    ("dnsResponse", Some((".respondWithDns(", ".thenRespondWithDns(", dns_response))),
];

/// `generatedActionCount`: the response (list) counts once, then every action but the object callbacks.
fn action_count(o: &Map<String, Value>) -> usize {
    let responses = get(o, "httpResponses").and_then(Value::as_array).is_some_and(|a| !a.is_empty()) || get(o, "httpResponse").is_some();
    usize::from(responses) + ACTIONS.iter().filter(|(key, w)| w.is_some() && get(o, key).is_some()).count()
}

/// `ExpectationToJavaSerializer.metadataToJava`: a scalar the fluent API takes as is, anything else as JSON text.
fn metadata_call(key: &str, value: &Value) -> String {
    let literal = |text: &str| format!("\"{}\"", escape_java(text));
    let argument = match value {
        Value::Null => Some("(Object) null".to_string()),
        Value::String(text) => Some(literal(text)),
        Value::Bool(b) => Some(b.to_string()),
        Value::Number(n) => match n.as_i64() {
            Some(i) if i32::try_from(i).is_ok() => Some(i.to_string()),
            Some(i) => Some(format!("{i}L")),
            None if n.is_f64() => Some(java_compat::double_to_string(n.as_f64().unwrap_or_default())),
            None => None,
        },
        _ => None,
    };
    match argument {
        Some(argument) => format!(".withMetadata({}, {argument})", literal(key)),
        None => {
            fn without_nulls(v: &Value) -> Value {
                match v {
                    Value::Object(o) => Value::Object(o.iter().filter(|(_, v)| !v.is_null()).map(|(k, v)| (k.clone(), without_nulls(v))).collect()),
                    Value::Array(items) => Value::Array(items.iter().map(without_nulls).collect()),
                    other => other.clone(),
                }
            }
            format!(".withMetadataJson({}, {})", literal(key), literal(&without_nulls(value).to_string()))
        }
    }
}

fn expectation(n: usize, e: &Source) -> Result<String> {
    let empty = Map::new();
    let o = e.input.as_object().unwrap_or(&empty);
    // `when(...)` takes one terminal action, and has none for forward-validate, a rate limit or steps alone.
    let actions = action_count(o);
    let steps = get(o, "steps");
    let upsert =
        actions > 1 || get(o, "httpForwardValidateAction").is_some() || get(o, "rateLimit").is_some() || actions == 0 && steps.is_some();
    let i = if upsert { n + 1 } else { n };
    let mut out = String::new();
    nl(&mut out, n * INDENT).push_str("new MockServerClient(\"localhost\", 1080)");
    if upsert {
        nl(&mut out, n * INDENT).push_str(".upsert(");
        nl(&mut out, i * INDENT).push_str("new org.mockserver.mock.Expectation(");
    } else {
        nl(&mut out, i * INDENT).push_str(".when(");
    }
    if let Some(Value::Object(r)) = get(o, "httpRequest") {
        request_definition(&mut out, i + 1, r)?;
    }
    out.push(',');
    out.push_str(&times(i + 1, e.times));
    out.push(',');
    out.push_str(&time_to_live(i + 1, e.time_to_live)?);
    out.push(',');
    nl(&mut out, (i + 1) * INDENT).push_str(&get(o, "priority").map(scalar).unwrap_or_else(|| "0".into()));
    nl(&mut out, i * INDENT).push(')');
    if let Some(id) = e.id {
        nl(&mut out, i * INDENT).push_str(&format!(".withId(\"{}\")", escape_java(id)));
    }
    if let Some(p) = get(o, "percentage") {
        nl(&mut out, i * INDENT).push_str(&format!(".withPercentage({})", scalar(p)));
    }
    for (key, method) in [
        ("namespace", "withNamespace"),
        ("metadata", ""),
        ("scenarioName", "withScenarioName"),
        ("scenarioState", "withScenarioState"),
        ("newScenarioState", "withNewScenarioState"),
    ] {
        if key == "metadata" {
            // One call per entry (`metadataToJava`); an empty map is no metadata.
            if let Some(Value::Object(entries)) = get(o, key) {
                for (k, v) in entries {
                    nl(&mut out, i * INDENT).push_str(&metadata_call(k, v));
                }
            }
            continue;
        }
        // `withNamespace` trims.
        let value = if key == "namespace" { str_of(o, key).map(str::trim) } else { str_of(o, key) };
        if let Some(v) = not_blank(value) {
            nl(&mut out, i * INDENT).push_str(&format!(".{method}(\"{}\")", escape_java(v)));
        }
    }
    if let Some(mode) = str_of(o, "responseMode") {
        nl(&mut out, i * INDENT).push_str(&format!(".withResponseMode(org.mockserver.mock.ResponseMode.{mode})"));
    }
    if let Some(Value::Array(weights)) = get(o, "responseWeights").filter(|w| w.as_array().is_some_and(|a| !a.is_empty())) {
        let joined = weights.iter().map(scalar).collect::<Vec<_>>().join(", ");
        nl(&mut out, i * INDENT).push_str(&format!(".withResponseWeights(java.util.Arrays.asList({joined}))"));
    }
    if let Some(s) = get(o, "switchAfter") {
        nl(&mut out, i * INDENT).push_str(&format!(".withSwitchAfter({})", scalar(s)));
    }
    if let Some(c) = get(o, "chaos") {
        call(&mut out, i, ".withChaos(", &chaos(i + 1, c)?);
    }
    if let Some(r) = get(o, "rateLimit") {
        call(&mut out, i, ".withRateLimit(", &rate_limit(i + 1, r)?);
    }
    each(&mut out, i, ".withCapture(", get(o, "capture"), capture_rule, ")")?;
    each(&mut out, i, ".withCrossProtocolScenarios(java.util.Arrays.asList(", get(o, "crossProtocolScenarios"), cross_protocol_scenario, "))")?;
    each(&mut out, i, ".withSteps(", steps, step, ")")?;
    each(&mut out, i, ".withBeforeActions(", get(o, "beforeActions"), after_action, ")")?;
    each(&mut out, i, ".withAfterActions(", get(o, "afterActions"), after_action, ")")?;
    let respond = if upsert { ".thenRespond(" } else { ".respond(" };
    match get(o, "httpResponses").and_then(Value::as_array).filter(|a| !a.is_empty()) {
        Some(responses) => {
            nl(&mut out, i * INDENT).push_str(respond);
            out.push_str("java.util.Arrays.asList(");
            for (k, r) in responses.iter().enumerate() {
                nl(&mut out, (i + 1) * INDENT);
                out.push_str(&response(i + 2, r)?);
                if k < responses.len() - 1 {
                    out.push(',');
                }
            }
            nl(&mut out, i * INDENT).push_str("))");
        }
        None => {
            if let Some(r) = get(o, "httpResponse") {
                action(&mut out, i, respond, &response(i + 1, r)?, r);
            }
        }
    }
    for (key, writer) in ACTIONS {
        let Some(v) = get(o, key) else { continue };
        match writer {
            Some((when, then, write)) => action(&mut out, i, if upsert { then } else { when }, &write(i + 1, v)?, v),
            None => {
                nl(&mut out, i * INDENT).push_str("/*NOT POSSIBLE TO GENERATE CODE FOR OBJECT CALLBACK*/");
            }
        }
    }
    if upsert {
        nl(&mut out, n * INDENT).push(')');
    }
    out.push(';');
    Ok(out)
}

/// `appendAction`: the call, the action, `.withPrimary(true)` for a primary one, and the closing parenthesis.
fn action(out: &mut String, n: usize, open: &str, inner: &str, action: &Value) {
    nl(out, n * INDENT).push_str(open);
    out.push_str(inner);
    if action.get("primary").and_then(Value::as_bool) == Some(true) {
        nl(out, (n + 2) * INDENT).push_str(".withPrimary(true)");
    }
    nl(out, n * INDENT).push(')');
}

/// `appendCall`.
fn call(out: &mut String, n: usize, open: &str, inner: &str) {
    nl(out, n * INDENT).push_str(open);
    out.push_str(inner);
    nl(out, n * INDENT).push(')');
}

/// `appendEach`: a non-empty list, each item written at the next indent, comma-separated.
fn each(out: &mut String, n: usize, open: &str, values: Option<&Value>, write: Writer, close: &str) -> Result<()> {
    // `ACCEPT_SINGLE_VALUE_AS_ARRAY`: a single object is a list of one.
    let values = match values {
        Some(Value::Array(a)) => a.clone(),
        Some(v @ Value::Object(_)) => vec![v.clone()],
        _ => Vec::new(),
    };
    if values.is_empty() {
        return Ok(());
    }
    nl(out, n * INDENT).push_str(open);
    for (k, v) in values.iter().enumerate() {
        if k > 0 {
            out.push(',');
        }
        out.push_str(&write(n + 1, v)?);
    }
    nl(out, n * INDENT).push_str(close);
    Ok(())
}

fn times(n: usize, t: &Value) -> String {
    let mut out = String::new();
    nl(&mut out, n * INDENT);
    match t.get("remainingTimes").and_then(Value::as_i64) {
        Some(_) if t.get("unlimited").and_then(Value::as_bool) == Some(true) => out.push_str("Times.unlimited()"),
        Some(1) => out.push_str("Times.once()"),
        Some(r) => out.push_str(&format!("Times.exactly({r})")),
        None => out.push_str("Times.unlimited()"),
    }
    out
}

fn time_to_live(n: usize, t: &Value) -> Result<String> {
    let mut out = String::new();
    nl(&mut out, n * INDENT);
    if t.get("unlimited").and_then(Value::as_bool) == Some(true) || t.get("timeToLive").is_none() {
        out.push_str("TimeToLive.unlimited()");
    } else {
        let unit = t.get("timeUnit").and_then(Value::as_str).ok_or_else(|| npe("org.mockserver.matchers.TimeToLive.getTimeUnit()"))?;
        out.push_str(&format!("TimeToLive.exactly(TimeUnit.{unit}, {}L)", scalar(&t["timeToLive"])));
    }
    Ok(out)
}

/// The message of a `NullPointerException` from calling `name()` on a null enum getter.
fn npe(getter: &str) -> String {
    format!("Cannot invoke \"java.util.concurrent.TimeUnit.name()\" because the return value of \"{getter}\" is null")
}

fn null_nottable() -> String {
    "Cannot invoke \"org.mockserver.model.NottableString.isOptional()\" because \"nottableString\" is null".into()
}

/// `ExpectationToJavaSerializer.writeRequestDefinition`: an `HttpRequest`, an OpenAPI matcher, an anyOf or a
/// conditional (each branch through `writeBranch`); a DNS or binary definition writes nothing. Returns whether it wrote.
fn request_definition(out: &mut String, n: usize, r: &Map<String, Value>) -> Result<bool> {
    // `RequestDefinitionDTODeserializer`: `anyOf`, then `if`, then the other kinds.
    let not = get(r, "not").and_then(Value::as_bool) == Some(true);
    let compound = if r.contains_key("anyOf") {
        let branches: Vec<Option<&Value>> = get(r, "anyOf").and_then(Value::as_array).map(|a| a.iter().filter(|b| !b.is_null()).map(Some).collect()).unwrap_or_default();
        Some(("org.mockserver.model.AnyOfRequestDefinition.requestAnyOf(", branches))
    } else if r.contains_key("if") {
        let mut branches: Vec<Option<&Value>> = ["if", "then", "else"].iter().map(|k| get(r, k)).collect();
        while branches.len() > 1 && branches.last().is_some_and(Option::is_none) {
            branches.pop();
        }
        Some(("org.mockserver.model.ConditionalRequestDefinition.requestIf(", branches))
    } else {
        None
    };
    if let Some((open, branches)) = compound {
        nl(out, n * INDENT).push_str(if not { "org.mockserver.model.Not.not(" } else { "" });
        out.push_str(open);
        for (index, branch) in branches.iter().enumerate() {
            let written = match branch {
                Some(Value::Object(b)) => request_definition(out, n + 1, b)?,
                _ => false,
            };
            if !written {
                // an absent branch, or one with no Java form, keeps the argument list compilable
                nl(out, (n + 1) * INDENT).push_str("null");
            }
            if index + 1 < branches.len() {
                out.push(',');
            }
        }
        nl(out, n * INDENT).push_str(if not { "))" } else { ")" });
        return Ok(true);
    }
    if r.contains_key("specUrlOrPayload") {
        out.push_str(&open_api(n, r));
        return Ok(true);
    }
    if ["binaryData", "dnsName"].iter().any(|k| r.contains_key(*k)) {
        return Ok(false);
    }
    out.push_str(&request(n, r)?);
    Ok(true)
}

/// `OpenAPIMatcherToJavaSerializer` (neither value is escaped, and the operation id is not quoted).
fn open_api(n: usize, r: &Map<String, Value>) -> String {
    let mut out = String::new();
    nl(&mut out, n * INDENT).push_str("openAPIMatcher()");
    if let Some(spec) = get(r, "specUrlOrPayload") {
        let spec = match spec {
            Value::String(s) => s.clone(),
            other => crate::json::pretty(other),
        };
        nl(&mut out, (n + 1) * INDENT).push_str(&format!(".withSpecUrlOrPayload(\"{spec}\")"));
    }
    if let Some(id) = get(r, "operationId") {
        nl(&mut out, (n + 1) * INDENT).push_str(&format!(".withOperationId({})", scalar(id)));
    }
    out
}

/// `HttpRequestToJavaSerializer.serialize(int, HttpRequest)`.
pub fn request(n: usize, r: &Map<String, Value>) -> Result<String> {
    let mut out = String::new();
    nl(&mut out, n * INDENT).push_str("request()");
    for (key, method) in [("method", "withMethod"), ("path", "withPath")] {
        let value = get(r, key).and_then(NString::from_json).and_then(|s| s.value);
        if let Some(v) = not_blank(value.as_deref()) {
            nl(&mut out, (n + 1) * INDENT).push_str(&format!(".{method}(\"{}\")", escape_java(v)));
        }
    }
    let n1 = n + 1;
    if let Some(h) = get(r, "headers").map(model::multi_values).filter(|e| !e.is_empty()) {
        nl(&mut out, n1 * INDENT).push_str(".withHeaders(");
        out.push_str(&multi("Header", n1 + 1, &h)?);
        nl(&mut out, n1 * INDENT).push(')');
    }
    if let Some(c) = get(r, "cookies").map(model::key_values).filter(|e| !e.is_empty()) {
        nl(&mut out, n1 * INDENT).push_str(".withCookies(");
        out.push_str(&cookies(n1 + 1, &c)?);
        nl(&mut out, n1 * INDENT).push(')');
    }
    if let Some(q) = get(r, "queryStringParameters").map(model::multi_values).filter(|e| !e.is_empty()) {
        nl(&mut out, n1 * INDENT).push_str(".withQueryStringParameters(");
        out.push_str(&multi("Parameter", n1 + 1, &q)?);
        nl(&mut out, n1 * INDENT).push(')');
    }
    // `withSocketAddress` sets `secure` when the socket address scheme is HTTPS.
    let socket = get(r, "socketAddress").and_then(Value::as_object);
    let https = socket.and_then(|s| str_of(s, "scheme")) == Some("HTTPS");
    let secure = if https { Some("true".to_string()) } else { get(r, "secure").map(scalar) };
    if let Some(s) = secure {
        nl(&mut out, n1 * INDENT).push_str(&format!(".withSecure({s})"));
    }
    if let Some(k) = get(r, "keepAlive") {
        nl(&mut out, n1 * INDENT).push_str(&format!(".withKeepAlive({})", scalar(k)));
    }
    if let Some(p) = str_of(r, "protocol") {
        nl(&mut out, n1 * INDENT).push_str(&format!(".withProtocol(Protocol.{p})"));
    }
    // an IP address never starts with '!', so the negation marker in the string form is unambiguous
    if let Some(ip) = get(r, "clientIp").and_then(model::NString::from_json) {
        nl(&mut out, n1 * INDENT).push_str(&format!(".withClientIp(\"{}\")", escape_java(&format!("{}{}", if ip.not { "!" } else { "" }, ip.value.unwrap_or_default()))));
    }
    if let Some(s) = socket {
        nl(&mut out, n1 * INDENT).push_str(".withSocketAddress(");
        out.push_str(&socket_address(n + 2, s));
        nl(&mut out, n1 * INDENT).push(')');
    }
    if let Some(body) = get(r, "body").and_then(model::request_body) {
        out.push_str(&request_body(n, &body, get(r, "body").and_then(Value::as_object))?);
    }
    Ok(out)
}

/// A JSON_PATH or XPATH body's `dateTime` field (`BodyDateTimeField`), as the comparison it reads to.
fn body_date_time(raw: Option<&Map<String, Value>>) -> Option<NString> {
    let raw = raw?;
    let (_, v) = raw.iter().find(|(k, _)| k.eq_ignore_ascii_case("dateTime"))?;
    NString::from_json(v).filter(|s| s.date_time.is_some())
}

/// The `namespacePrefixes` map of an XPATH body, in the order given.
fn namespace_prefixes(raw: Option<&Map<String, Value>>) -> Vec<(String, String)> {
    let Some((_, Value::Object(m))) = raw.and_then(|r| r.iter().find(|(k, _)| k.eq_ignore_ascii_case("namespacePrefixes"))) else {
        return Vec::new();
    };
    m.iter().map(|(k, v)| (k.clone(), scalar(v))).collect()
}

fn request_body(n: usize, body: &Body, raw: Option<&Map<String, Value>>) -> Result<String> {
    let mut out = String::new();
    let simple = |out: &mut String, text: String| {
        nl(out, (n + 1) * INDENT).push_str(&format!(".withBody({text})"));
    };
    let quoted = |class: &str, v: &str| format!("new {class}(\"{}\")", escape_java(v));
    match body {
        Body::Json { value, match_type, numbers_as_strings: true } => {
            simple(&mut out, format!("JsonBody.json(\"{}\", JsonBodyMatchType.{match_type}, true)", escape_java(value)))
        }
        Body::Json { value, match_type, .. } => {
            simple(&mut out, format!("new JsonBody(\"{}\", JsonBodyMatchType.{match_type})", escape_java(value)))
        }
        Body::JsonPath(v) => match body_date_time(raw) {
            Some(d) => simple(&mut out, format!("new JsonPathBody(\"{}\", {})", escape_java(v), nottable(&d, false))),
            None => simple(&mut out, quoted("JsonPathBody", v)),
        },
        Body::JsonSchema(v) => simple(&mut out, quoted("JsonSchemaBody", v)),
        Body::Xml(v) => simple(&mut out, quoted("XmlBody", v)),
        Body::XPath(v) => {
            let date_time = body_date_time(raw);
            let prefixes = namespace_prefixes(raw);
            let mut text = format!("new XPathBody(\"{}\"", escape_java(v));
            if !prefixes.is_empty() {
                let entries: Vec<String> = prefixes.iter().map(|(k, v)| format!("java.util.Map.entry(\"{}\", \"{}\")", escape_java(k), escape_java(v))).collect();
                text.push_str(&format!(", java.util.Map.ofEntries({})", entries.join(", ")));
            } else if date_time.is_some() {
                text.push_str(", null");
            }
            if let Some(d) = &date_time {
                text.push_str(&format!(", {}", nottable(d, false)));
            }
            text.push(')');
            simple(&mut out, text)
        }
        Body::XmlSchema(v) => simple(&mut out, quoted("XmlSchemaBody", v)),
        Body::Regex(v) => simple(&mut out, quoted("RegexBody", v)),
        Body::Fuzzy { value, threshold, ignore_case } => simple(
            &mut out,
            format!("new FuzzyBody(\"{}\", {}d, {ignore_case})", escape_java(value), java_compat::double_to_string(*threshold)),
        ),
        Body::String(v) => simple(&mut out, quoted("StringBody", v)),
        Body::Parameters(entries) => {
            nl(&mut out, (n + 1) * INDENT).push_str(".withBody(");
            nl(&mut out, (n + 2) * INDENT).push_str("new ParameterBody(");
            out.push_str(&multi("Parameter", n + 3, entries)?);
            nl(&mut out, (n + 2) * INDENT).push(')');
            nl(&mut out, (n + 1) * INDENT).push(')');
        }
        Body::GraphQl { query, operation_name, variables_schema, selection_set_match_type } => {
            // `FluentJavaBuilder.literal`: a null value is `null`, unquoted.
            let text = |s: &Option<String>| s.as_deref().map(|s| format!("\"{}\"", escape_java(s))).unwrap_or_else(|| "null".into());
            nl(&mut out, (n + 1) * INDENT).push_str(&format!(".withBody(GraphQLBody.graphQL({}", text(query)));
            if variables_schema.is_some() {
                out.push_str(&format!(", {}, {}", text(operation_name), text(variables_schema)));
            } else if operation_name.is_some() {
                out.push_str(&format!(", {}", text(operation_name)));
            }
            out.push(')');
            if let Some(m) = selection_set_match_type {
                nl(&mut out, (n + 2) * INDENT).push_str(&format!(".withSelectionSetMatchType(SelectionSetMatchType.{m})"));
            }
            out.push(')');
        }
        Body::Binary(bytes) => {
            let bytes = bytes.as_deref().ok_or_else(|| "Cannot read the array length because \"src\" is null".to_string())?;
            simple(&mut out, format!("new Base64Converter().base64StringToBytes(\"{}\")", b64(bytes)));
        }
        Body::Unprinted => {}
    }
    Ok(out)
}

/// `NottableStringToJavaSerializer.serialize`.
fn nottable(s: &NString, always_nottable: bool) -> String {
    if let Some(d) = &s.date_time {
        return date_time(d, s.not);
    }
    let value = s.value.as_deref().map(escape_java).unwrap_or_else(|| "null".into());
    let marker = s.value.as_deref().is_some_and(|v| v.starts_with(['!', '?']));
    if s.optional {
        if marker { format!("optional(\"{value}\", {})", s.not) } else { format!("optional(\"{value}\")") }
    } else if s.not {
        format!("not(\"{value}\")")
    } else if marker {
        format!("string(\"{value}\", false)")
    } else if always_nottable {
        format!("string(\"{value}\")")
    } else {
        format!("\"{value}\"")
    }
}

/// `NottableStringToJavaSerializer.serializeDateTime`.
fn date_time(d: &model::DateTimeValue, not: bool) -> String {
    let mut out = format!("NottableDateTimeString.{}(\"{}\")", d.operator, escape_java(d.expected.as_deref().unwrap_or("null")));
    for (method, value) in [("withActualFormat", &d.actual_format), ("withTruncateExpected", &d.truncate_expected), ("withTruncateActual", &d.truncate_actual)] {
        if let Some(value) = value {
            out.push_str(&format!(".{method}(\"{}\")", escape_java(value)));
        }
    }
    if let Some(last) = d.apply_truncation_last {
        out.push_str(&format!(".withApplyTruncationLast({last})"));
    }
    if let Some(zone) = &d.zone {
        out.push_str(&format!(".withZone(\"{}\")", escape_java(zone)));
    }
    if not {
        out.push_str(".withNot(true)");
    }
    out
}

/// `NottableStringToJavaSerializer.needsNottableKey`.
fn needs_nottable_key<'a>(values: impl IntoIterator<Item = &'a Option<NString>>) -> bool {
    values.into_iter().any(|v| v.as_ref().is_some_and(|v| v.date_time.is_some()))
}

/// `HeaderToJavaSerializer` / `ParameterToJavaSerializer.serializeAsJava`.
fn multi(class: &str, n: usize, entries: &Entries) -> Result<String> {
    let mut out = String::new();
    for (i, (name, values)) in entries.iter().enumerate() {
        nl(&mut out, n * INDENT);
        let key = nottable(name, needs_nottable_key(values));
        out.push_str(&format!("new {class}({key}"));
        for v in values {
            let v = v.as_ref().ok_or_else(null_nottable)?;
            out.push_str(&format!(", {}", nottable(v, key.ends_with(')'))));
        }
        out.push(')');
        if i < entries.len() - 1 {
            out.push(',');
        }
    }
    Ok(out)
}

/// `CookieToJavaSerializer.serializeAsJava`.
fn cookies(n: usize, entries: &Entries) -> Result<String> {
    let mut out = String::new();
    for (i, (name, values)) in entries.iter().enumerate() {
        let value = values.first().cloned().flatten().ok_or_else(null_nottable)?;
        nl(&mut out, n * INDENT).push_str(&format!("new Cookie({}, {})", nottable(name, value.date_time.is_some()), nottable(&value, false)));
        if i < entries.len() - 1 {
            out.push(',');
        }
    }
    Ok(out)
}

/// `SocketAddressToJavaSerializer`; upstream's `SocketAddress` defaults to port 80 and scheme HTTP.
fn socket_address(n: usize, s: &Map<String, Value>) -> String {
    let mut out = String::new();
    nl(&mut out, n * INDENT).push_str("new SocketAddress()");
    if let Some(host) = get(s, "host") {
        nl(&mut out, (n + 1) * INDENT).push_str(&format!(".withHost(\"{}\")", scalar(host)));
    }
    nl(&mut out, (n + 1) * INDENT).push_str(&format!(".withPort({})", get(s, "port").map(scalar).unwrap_or_else(|| "80".into())));
    nl(&mut out, (n + 1) * INDENT).push_str(&format!(".withScheme(SocketAddress.Scheme.{})", str_of(s, "scheme").unwrap_or("HTTP")));
    out
}

/// `HttpResponseToJavaSerializer`.
pub fn response(n: usize, r: &Value) -> Result<String> {
    let empty = Map::new();
    let o = r.as_object().unwrap_or(&empty);
    let mut out = String::new();
    nl(&mut out, n * INDENT).push_str("response()");
    if let Some(s) = get(o, "statusCode") {
        nl(&mut out, (n + 1) * INDENT).push_str(&format!(".withStatusCode({})", scalar(s)));
    }
    if let Some(p) = str_of(o, "reasonPhrase") {
        nl(&mut out, (n + 1) * INDENT).push_str(&format!(".withReasonPhrase(\"{}\")", escape_java(p)));
    }
    if let Some(h) = get(o, "headers").map(model::multi_values).filter(|e| !e.is_empty()) {
        nl(&mut out, (n + 1) * INDENT).push_str(".withHeaders(");
        out.push_str(&multi("Header", n + 2, &h)?);
        nl(&mut out, (n + 1) * INDENT).push(')');
    }
    if let Some(c) = get(o, "cookies").map(model::key_values).filter(|e| !e.is_empty()) {
        nl(&mut out, (n + 1) * INDENT).push_str(".withCookies(");
        out.push_str(&cookies(n + 2, &c)?);
        nl(&mut out, (n + 1) * INDENT).push(')');
    }
    match get(o, "body").and_then(model::response_body) {
        Some(ResponseBody::Binary(Some(bytes))) if !b64(&bytes).trim().is_empty() => {
            nl(&mut out, (n + 1) * INDENT).push_str(&format!(".withBody(new Base64Converter().base64StringToBytes(\"{}\"))", b64(&bytes)));
        }
        Some(ResponseBody::Text(text)) if !text.trim().is_empty() => {
            nl(&mut out, (n + 1) * INDENT).push_str(&format!(".withBody(\"{}\")", escape_java(&text)));
        }
        _ => {}
    }
    if let Some(s) = not_blank(str_of(o, "generateFromSchema")) {
        nl(&mut out, (n + 1) * INDENT).push_str(&format!(".withGenerateFromSchema(\"{}\")", escape_java(s)));
    }
    if let Some(d) = get(o, "delay") {
        nl(&mut out, (n + 1) * INDENT).push_str(&format!(".withDelay({})", delay(d)?));
    }
    if let Some(Value::Object(c)) = get(o, "connectionOptions") {
        nl(&mut out, (n + 1) * INDENT).push_str(".withConnectionOptions(");
        out.push_str(&connection_options(n + 2, c)?);
        nl(&mut out, (n + 1) * INDENT).push(')');
    }
    Ok(out)
}

/// `DelayToJavaSerializer`.
fn delay(d: &Value) -> Result<String> {
    let empty = Map::new();
    let o = d.as_object().unwrap_or(&empty);
    let unit = || str_of(o, "timeUnit").ok_or_else(|| npe("org.mockserver.model.Delay.getTimeUnit()"));
    let long = |o: &Map<String, Value>, k: &str| get(o, k).map(scalar).unwrap_or_else(|| "null".into());
    if let (Some(template), Some(kind)) = (str_of(o, "template"), str_of(o, "templateType")) {
        return Ok(format!("Delay.template(HttpTemplate.TemplateType.{kind}, \"{}\")", escape_java(template)));
    }
    if let Some(dist) = get(o, "distribution").and_then(Value::as_object).filter(|d| get(d, "type").is_some()) {
        let (a, b, f) = match str_of(dist, "type").unwrap_or_default() {
            "UNIFORM" => ("min", "max", "uniform"),
            "LOG_NORMAL" => ("median", "p99", "logNormal"),
            _ => ("mean", "stdDev", "gaussian"),
        };
        return Ok(format!("Delay.{f}(TimeUnit.{}, {}, {})", unit()?, long(dist, a), long(dist, b)));
    }
    Ok(format!("new Delay(TimeUnit.{}, {})", unit()?, get(o, "value").map(scalar).unwrap_or_else(|| "0".into())))
}

/// `ConnectionOptionsToJavaSerializer`.
fn connection_options(n: usize, c: &Map<String, Value>) -> Result<String> {
    let mut out = String::new();
    nl(&mut out, n * INDENT).push_str("connectionOptions()");
    for (key, method) in [
        ("suppressContentLengthHeader", "withSuppressContentLengthHeader"),
        ("contentLengthHeaderOverride", "withContentLengthHeaderOverride"),
        ("suppressConnectionHeader", "withSuppressConnectionHeader"),
        ("chunkSize", "withChunkSize"),
        ("chunkDelay", "withChunkDelay"),
        ("keepAliveOverride", "withKeepAliveOverride"),
        ("closeSocket", "withCloseSocket"),
        ("closeSocketDelay", "withCloseSocketDelay"),
    ] {
        if let Some(v) = get(c, key) {
            let arg = if key.ends_with("Delay") { delay(v)? } else { scalar(v) };
            nl(&mut out, (n + 1) * INDENT).push_str(&format!(".{method}({arg})"));
        }
    }
    Ok(out)
}

/// `HttpTemplateToJavaSerializer`.
fn template(n: usize, t: &Value) -> Result<String> {
    let empty = Map::new();
    let o = t.as_object().unwrap_or(&empty);
    let mut out = String::new();
    let kind = str_of(o, "templateType").ok_or_else(|| {
        "Cannot invoke \"org.mockserver.model.HttpTemplate$TemplateType.name()\" because the return value of \"org.mockserver.model.HttpTemplate.getTemplateType()\" is null".to_string()
    })?;
    nl(&mut out, n * INDENT).push_str(&format!("template(HttpTemplate.TemplateType.{kind})"));
    if let Some(s) = not_blank(str_of(o, "template")) {
        nl(&mut out, (n + 1) * INDENT).push_str(&format!(".withTemplate(\"{}\")", escape_java(s)));
    }
    if let Some(s) = not_blank(str_of(o, "templateFile")) {
        nl(&mut out, (n + 1) * INDENT).push_str(&format!(".withTemplateFile(\"{}\")", escape_java(s)));
    }
    if let Some(r) = get(o, "responseOverride") {
        nl(&mut out, (n + 1) * INDENT).push_str(".withResponseOverride(");
        out.push_str(&response(n + 2, r)?);
        nl(&mut out, (n + 1) * INDENT).push(')');
    }
    if let Some(Value::Object(m)) = get(o, "responseModifier") {
        nl(&mut out, (n + 1) * INDENT).push_str(".withResponseModifier(");
        out.push_str(&response_modifier(n + 2, m)?);
        nl(&mut out, (n + 1) * INDENT).push(')');
    }
    if let Some(d) = get(o, "delay") {
        nl(&mut out, (n + 1) * INDENT).push_str(&format!(".withDelay({})", delay(d)?));
    }
    Ok(out)
}

/// `HttpClassCallbackToJavaSerializer`.
fn class_callback(n: usize, c: &Value) -> Result<String> {
    let empty = Map::new();
    let o = c.as_object().unwrap_or(&empty);
    let mut out = String::new();
    nl(&mut out, n * INDENT).push_str("callback()");
    if let Some(class) = get(o, "callbackClass") {
        nl(&mut out, (n + 1) * INDENT).push_str(&format!(".withCallbackClass(\"{}\")", scalar(class)));
    }
    if let Some(d) = get(o, "delay") {
        nl(&mut out, (n + 1) * INDENT).push_str(&format!(".withDelay({})", delay(d)?));
    }
    Ok(out)
}

/// `HttpForwardToJavaSerializer`; `HttpForward` defaults to port 80 and scheme HTTP.
fn forward(n: usize, f: &Value) -> Result<String> {
    let empty = Map::new();
    let o = f.as_object().unwrap_or(&empty);
    let mut out = String::new();
    nl(&mut out, n * INDENT).push_str("forward()");
    if let Some(host) = get(o, "host") {
        nl(&mut out, (n + 1) * INDENT).push_str(&format!(".withHost(\"{}\")", scalar(host)));
    }
    nl(&mut out, (n + 1) * INDENT).push_str(&format!(".withPort({})", get(o, "port").map(scalar).unwrap_or_else(|| "80".into())));
    nl(&mut out, (n + 1) * INDENT).push_str(&format!(".withScheme(HttpForward.Scheme.{})", str_of(o, "scheme").unwrap_or("HTTP")));
    if let Some(d) = get(o, "delay") {
        nl(&mut out, (n + 1) * INDENT).push_str(&format!(".withDelay({})", delay(d)?));
    }
    Ok(out)
}

/// `HttpOverrideForwardedRequestToJavaSerializer`; the legacy `{httpRequest, httpResponse}` shape is the same
/// model.
fn override_forwarded(n: usize, f: &Value) -> Result<String> {
    let empty = Map::new();
    let o = f.as_object().unwrap_or(&empty);
    let mut out = String::new();
    nl(&mut out, n * INDENT).push_str("forwardOverriddenRequest()");
    if let Some(Value::Object(r)) = get(o, "requestOverride").or_else(|| get(o, "httpRequest")) {
        nl(&mut out, (n + 1) * INDENT).push_str(".withRequestOverride(");
        out.push_str(&request(n + 2, r)?);
        nl(&mut out, (n + 1) * INDENT).push(')');
    }
    if let Some(Value::Object(m)) = get(o, "requestModifier") {
        nl(&mut out, (n + 1) * INDENT).push_str(".withRequestModifier(");
        out.push_str(&request_modifier(n + 2, m)?);
        nl(&mut out, (n + 1) * INDENT).push(')');
    }
    if let Some(r) = get(o, "responseOverride").or_else(|| get(o, "httpResponse")) {
        nl(&mut out, (n + 1) * INDENT).push_str(".withResponseOverride(");
        out.push_str(&response(n + 2, r)?);
        nl(&mut out, (n + 1) * INDENT).push(')');
    }
    if let Some(Value::Object(m)) = get(o, "responseModifier") {
        nl(&mut out, (n + 1) * INDENT).push_str(".withResponseModifier(");
        out.push_str(&response_modifier(n + 2, m)?);
        nl(&mut out, (n + 1) * INDENT).push(')');
    }
    if let Some(t) = get(o, "responseTemplate") {
        nl(&mut out, (n + 1) * INDENT).push_str(".withResponseTemplate(");
        out.push_str(&template(n + 2, t)?);
        nl(&mut out, (n + 1) * INDENT).push(')');
    }
    if let Some(d) = get(o, "delay") {
        nl(&mut out, (n + 1) * INDENT).push_str(".withDelay(");
        out.push_str(&delay(d)?);
        out.push(')');
    }
    Ok(out)
}

/// The `add`, `replace` and `remove` arguments of a modifier's `withHeaders` / `withCookies` /
/// `withQueryStringParameters`.
fn modifier_group(out: &mut String, n: usize, class: &str, factory: &str, group: &Map<String, Value>, single: bool) -> Result<()> {
    for key in ["add", "replace"] {
        let entries = get(group, key).map(|v| if single { model::key_values(v) } else { model::multi_values(v) }).unwrap_or_default();
        if entries.is_empty() {
            nl(out, (n + 2) * INDENT).push_str("null,");
        } else {
            nl(out, (n + 2) * INDENT).push_str(&format!("{factory}("));
            out.push_str(&if single { cookies(n + 3, &entries)? } else { multi(class, n + 3, &entries)? });
            nl(out, (n + 2) * INDENT).push_str("),");
        }
    }
    match get(group, "remove").and_then(Value::as_array).filter(|r| !r.is_empty()) {
        Some(remove) => {
            let joined = remove.iter().map(|s| format!("\"{}\"", scalar(s))).collect::<Vec<_>>().join(",");
            nl(out, (n + 2) * INDENT).push_str(&format!("ImmutableList.of({joined})"));
        }
        None => {
            nl(out, (n + 2) * INDENT).push_str("null");
        }
    }
    Ok(())
}

/// `HttpRequestModifierToJavaSerializer` (the path regex and substitution are not escaped).
fn request_modifier(n: usize, m: &Map<String, Value>) -> Result<String> {
    let mut out = String::new();
    nl(&mut out, n * INDENT).push_str("requestModifier()");
    if let Some(Value::Object(p)) = get(m, "path") {
        let text = |k: &str| get(p, k).map(scalar).unwrap_or_else(|| "null".into());
        nl(&mut out, (n + 1) * INDENT).push_str(&format!(".withPath(\"{}\",\"{}\")", text("regex"), text("substitution")));
    }
    for (key, method, class, factory, single) in [
        ("queryStringParameters", "withQueryStringParameters", "Parameter", "parameters", false),
        ("headers", "withHeaders", "Header", "headers", false),
        ("cookies", "withCookies", "Cookie", "cookies", true),
    ] {
        if let Some(Value::Object(group)) = get(m, key) {
            nl(&mut out, (n + 1) * INDENT).push_str(&format!(".{method}("));
            modifier_group(&mut out, n, class, factory, group, single)?;
            nl(&mut out, (n + 1) * INDENT).push(')');
        }
    }
    Ok(out)
}

/// `HttpResponseModifierToJavaSerializer`; JSON patches print as compact JSON.
fn response_modifier(n: usize, m: &Map<String, Value>) -> Result<String> {
    let mut out = String::new();
    nl(&mut out, n * INDENT).push_str("responseModifier()");
    for (key, method, class, factory, single) in [("headers", "withHeaders", "Header", "headers", false), ("cookies", "withCookies", "Cookie", "cookies", true)] {
        if let Some(Value::Object(group)) = get(m, key) {
            nl(&mut out, (n + 1) * INDENT).push_str(&format!(".{method}("));
            modifier_group(&mut out, n, class, factory, group, single)?;
            nl(&mut out, (n + 1) * INDENT).push(')');
        }
    }
    if let Some(Value::Object(c)) = get(m, "condition") {
        nl(&mut out, (n + 1) * INDENT).push_str(".withCondition(");
        nl(&mut out, (n + 2) * INDENT).push_str("responseModifierCondition()");
        if let Some(s) = get(c, "statusCode") {
            nl(&mut out, (n + 3) * INDENT).push_str(&format!(".withStatusCode({})", scalar(s)));
        }
        for (key, method) in [
            ("statusCodeRange", "withStatusCodeRange"),
            ("responseHasHeader", "withResponseHasHeader"),
            ("requestHasHeader", "withRequestHasHeader"),
        ] {
            if let Some(v) = get(c, key) {
                nl(&mut out, (n + 3) * INDENT).push_str(&format!(".{method}(\"{}\")", scalar(v)));
            }
        }
        nl(&mut out, (n + 1) * INDENT).push(')');
    }
    if let Some(modifiers) = get(m, "modifiers").and_then(Value::as_array).filter(|a| !a.is_empty()) {
        nl(&mut out, (n + 1) * INDENT).push_str(".withModifiers(Arrays.asList(");
        for (i, inner) in modifiers.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            let empty = Map::new();
            out.push_str(&response_modifier(n + 2, inner.as_object().unwrap_or(&empty))?);
        }
        nl(&mut out, (n + 1) * INDENT).push_str("))");
    }
    for (key, method) in [("jsonPatch", "withJsonPatch"), ("jsonMergePatch", "withJsonMergePatch")] {
        if let Some(v) = get(m, key) {
            let compact = serde_json::to_string(&model::jackson_tree(v)).unwrap_or_default();
            nl(&mut out, (n + 1) * INDENT).push_str(&format!(".{method}(\"{}\")", escape_java(&compact)));
        }
    }
    Ok(out)
}

/// `HttpErrorToJavaSerializer`.
fn error(n: usize, e: &Value) -> Result<String> {
    let empty = Map::new();
    let o = e.as_object().unwrap_or(&empty);
    let mut out = String::new();
    nl(&mut out, n * INDENT).push_str("error()");
    if let Some(d) = get(o, "delay") {
        nl(&mut out, (n + 1) * INDENT).push_str(&format!(".withDelay({})", delay(d)?));
    }
    if let Some(d) = get(o, "dropConnection") {
        nl(&mut out, (n + 1) * INDENT).push_str(&format!(".withDropConnection({})", scalar(d)));
    }
    if let Some(d) = get(o, "resetConnection") {
        nl(&mut out, (n + 1) * INDENT).push_str(&format!(".withResetConnection({})", scalar(d)));
    }
    if let Some(bytes) = str_of(o, "responseBytes").and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok()) {
        nl(&mut out, (n + 1) * INDENT).push_str(&format!(".withResponseBytes(new Base64Converter().base64StringToBytes(\"{}\"))", b64(&bytes)));
    }
    if let Some(s) = get(o, "streamError") {
        nl(&mut out, (n + 1) * INDENT).push_str(&format!(".withStreamError({}L)", scalar(s)));
    }
    Ok(out)
}

/// The Java type behind a value `FluentJavaBuilder.literal` writes: JSON loses it, so each call names it.
#[derive(Clone, Copy)]
enum Lit {
    Str,
    Int,
    Long,
    Double,
    Bool,
    /// An enum constant, written with its declaring class's canonical name.
    Enum(&'static str),
}

/// `FluentJavaBuilder.literal`.
fn literal(v: &Value, kind: Lit) -> String {
    match (kind, v) {
        (_, Value::Null) => "null".into(),
        (Lit::Str, v) => format!("\"{}\"", escape_java(&scalar(v))),
        (Lit::Long, v) => format!("{}L", scalar(v)),
        (Lit::Double, Value::Number(d)) => d.as_f64().map(java_compat::double_to_string).unwrap_or_else(|| d.to_string()),
        (Lit::Double, Value::String(s)) => match s.as_str() {
            "NaN" => "Double.NaN".into(),
            "Infinity" => "Double.POSITIVE_INFINITY".into(),
            "-Infinity" => "Double.NEGATIVE_INFINITY".into(),
            s => s.parse::<f64>().map(java_compat::double_to_string).unwrap_or_else(|_| s.to_string()),
        },
        (Lit::Enum(class), v) => format!("{class}.{}", scalar(v)),
        (_, v) => scalar(v),
    }
}

/// `FluentJavaBuilder`: a static factory and a chain of `with...` calls, one per line, each written only for a
/// value that is set.
struct Fluent<'a> {
    out: String,
    n: usize,
    o: &'a Map<String, Value>,
}

impl<'a> Fluent<'a> {
    fn new(n: usize, factory: &str, v: &'a Value) -> Self {
        static EMPTY: std::sync::OnceLock<Map<String, Value>> = std::sync::OnceLock::new();
        let mut out = String::new();
        nl(&mut out, n * INDENT).push_str(factory);
        Fluent { out, n, o: v.as_object().unwrap_or_else(|| EMPTY.get_or_init(Map::new)) }
    }

    fn line(&mut self) -> &mut String {
        nl(&mut self.out, (self.n + 1) * INDENT)
    }

    fn with(mut self, method: &str, key: &str, kind: Lit) -> Self {
        if let Some(v) = get(self.o, key) {
            let text = literal(v, kind);
            self.line().push_str(&format!(".{method}({text})"));
        }
        self
    }

    fn with_delay(mut self, method: &str, key: &str) -> Result<Self> {
        if let Some(d) = get(self.o, key) {
            let text = delay(d)?;
            self.line().push_str(&format!(".{method}({text})"));
        }
        Ok(self)
    }

    /// `withBytes`: a byte array given as base64 in JSON.
    fn with_bytes(mut self, method: &str, key: &str) -> Self {
        if let Some(bytes) = str_of(self.o, key).and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok()) {
            self.line().push_str(&format!(".{method}(java.util.Base64.getDecoder().decode(\"{}\"))", b64(&bytes)));
        }
        self
    }

    fn with_headers(mut self, key: &str) -> Result<Self> {
        if let Some(h) = get(self.o, key) {
            let entries = model::multi_values(h);
            let n = self.n;
            self.line().push_str(".withHeaders(new Headers(");
            let headers = multi("Header", n + 2, &entries)?;
            self.out.push_str(&headers);
            self.line().push_str("))");
        }
        Ok(self)
    }

    /// `withLiterals`: the list's values as the arguments of one call.
    fn with_literals(mut self, method: &str, key: &str, kind: Lit) -> Self {
        if let Some(values) = get(self.o, key) {
            let joined = values.as_array().map(|a| a.iter().map(|v| literal(v, kind)).collect::<Vec<_>>().join(", ")).unwrap_or_default();
            self.line().push_str(&format!(".{method}({joined})"));
        }
        self
    }

    /// `withEach`: each item of the list written at two indents in, as the arguments of one call.
    fn with_each(mut self, method: &str, key: &str, write: Writer) -> Result<Self> {
        if let Some(values) = get(self.o, key) {
            let n = self.n;
            self.line().push_str(&format!(".{method}("));
            for (k, v) in values.as_array().map(Vec::as_slice).unwrap_or_default().iter().enumerate() {
                if k > 0 {
                    self.out.push(',');
                }
                let item = write(n + 2, v)?;
                self.out.push_str(&item);
            }
            self.line().push(')');
        }
        Ok(self)
    }

    /// `withEach` over a list its DTO builds item by item, so an empty one stays null.
    fn with_each_non_empty(self, method: &str, key: &str, write: Writer) -> Result<Self> {
        if get(self.o, key).and_then(Value::as_array).is_some_and(Vec::is_empty) {
            return Ok(self);
        }
        self.with_each(method, key, write)
    }

    /// `withObject`: one object written at two indents in.
    fn with_object(mut self, method: &str, key: &str, write: Writer) -> Result<Self> {
        if let Some(v) = get(self.o, key) {
            let item = write(self.n + 2, v)?;
            self.line().push_str(&format!(".{method}("));
            self.out.push_str(&item);
            self.line().push(')');
        }
        Ok(self)
    }

    /// `withCode`: a value written by `code`.
    fn with_code(mut self, method: &str, key: &str, code: fn(&Value) -> String) -> Self {
        if let Some(v) = get(self.o, key) {
            let text = code(v);
            self.line().push_str(&format!(".{method}({text})"));
        }
        self
    }

    fn comment(mut self, condition: bool, comment: &str) -> Self {
        if condition {
            self.line().push_str(&format!("/*{comment}*/"));
        }
        self
    }

    fn build(self) -> String {
        self.out
    }
}

/// `HttpForwardWithFallbackToJavaSerializer`.
fn forward_with_fallback(n: usize, v: &Value) -> Result<String> {
    Ok(Fluent::new(n, "HttpForwardWithFallback.forwardWithFallback()", v)
        .with_object("withForward", "httpForward", forward)?
        .with_object("withFallback", "fallbackResponse", response)?
        .with_literals("withFallbackOnStatusCodes", "fallbackOnStatusCodes", Lit::Int)
        .with("withFallbackOnTimeout", "fallbackOnTimeout", Lit::Bool)
        .with_delay("withDelay", "delay")?
        .build())
}

/// `HttpForwardValidateActionToJavaSerializer`, over the model's defaults (port 80, HTTP, both validations,
/// STRICT).
fn forward_validate(n: usize, v: &Value) -> Result<String> {
    let mut o = v.as_object().cloned().unwrap_or_default();
    for (key, default) in [
        ("port", Value::from(80)),
        ("scheme", Value::from("HTTP")),
        ("validateRequest", Value::Bool(true)),
        ("validateResponse", Value::Bool(true)),
        ("validationMode", Value::from("STRICT")),
    ] {
        if get(&o, key).is_none() {
            o.insert(key.into(), default);
        }
    }
    let v = Value::Object(o);
    Ok(Fluent::new(n, "HttpForwardValidateAction.forwardValidate()", &v)
        .with("withSpecUrlOrPayload", "specUrlOrPayload", Lit::Str)
        .with("withHost", "host", Lit::Str)
        .with("withPort", "port", Lit::Int)
        .with("withScheme", "scheme", Lit::Enum("org.mockserver.model.HttpForward.Scheme"))
        .with("withValidateRequest", "validateRequest", Lit::Bool)
        .with("withValidateResponse", "validateResponse", Lit::Bool)
        .with("withValidationMode", "validationMode", Lit::Enum("org.mockserver.model.HttpForwardValidateAction.ValidationMode"))
        .with_delay("withDelay", "delay")?
        .build())
}

/// `DnsResponseToJavaSerializer`.
fn dns_response(n: usize, v: &Value) -> Result<String> {
    Ok(Fluent::new(n, "DnsResponse.dnsResponse()", v)
        .with_each("withAnswerRecords", "answerRecords", dns_record)?
        .with_each("withAuthorityRecords", "authorityRecords", dns_record)?
        .with_each("withAdditionalRecords", "additionalRecords", dns_record)?
        .with("withResponseCode", "responseCode", Lit::Enum("org.mockserver.model.DnsResponseCode"))
        .with_delay("withDelay", "delay")?
        .build())
}

fn dns_record(n: usize, v: &Value) -> Result<String> {
    Ok(Fluent::new(n, "DnsRecord.dnsRecord()", v)
        .with("withName", "name", Lit::Str)
        .with("withType", "type", Lit::Enum("org.mockserver.model.DnsRecordType"))
        .with("withDnsClass", "dnsClass", Lit::Enum("org.mockserver.model.DnsRecordClass"))
        .with("withTtl", "ttl", Lit::Int)
        .with("withValue", "value", Lit::Str)
        .with("withPriority", "priority", Lit::Int)
        .with("withWeight", "weight", Lit::Int)
        .with("withPort", "port", Lit::Int)
        .build())
}

/// `ExpectationToJavaSerializer.serializeChaos`.
fn chaos(n: usize, v: &Value) -> Result<String> {
    Ok(Fluent::new(n, "HttpChaosProfile.httpChaosProfile()", v)
        .with("withErrorStatus", "errorStatus", Lit::Int)
        .with("withRetryAfter", "retryAfter", Lit::Str)
        .with("withErrorProbability", "errorProbability", Lit::Double)
        .with("withDropConnectionProbability", "dropConnectionProbability", Lit::Double)
        .with_delay("withLatency", "latency")?
        .with("withSeed", "seed", Lit::Long)
        .with("withSucceedFirst", "succeedFirst", Lit::Int)
        .with("withFailRequestCount", "failRequestCount", Lit::Int)
        .with("withOutageAfterMillis", "outageAfterMillis", Lit::Long)
        .with("withOutageDurationMillis", "outageDurationMillis", Lit::Long)
        .with("withTruncateBodyAtFraction", "truncateBodyAtFraction", Lit::Double)
        .with("withMalformedBody", "malformedBody", Lit::Bool)
        .with("withSlowResponseChunkSize", "slowResponseChunkSize", Lit::Int)
        .with_delay("withSlowResponseChunkDelay", "slowResponseChunkDelay")?
        .with("withQuotaName", "quotaName", Lit::Str)
        .with("withQuotaLimit", "quotaLimit", Lit::Int)
        .with("withQuotaWindowMillis", "quotaWindowMillis", Lit::Long)
        .with("withQuotaErrorStatus", "quotaErrorStatus", Lit::Int)
        .with("withDegradationRampMillis", "degradationRampMillis", Lit::Long)
        .with("withGraphqlErrors", "graphqlErrors", Lit::Bool)
        .with("withGraphqlErrorMessage", "graphqlErrorMessage", Lit::Str)
        .with("withGraphqlErrorCode", "graphqlErrorCode", Lit::Str)
        .with("withGraphqlNullifyData", "graphqlNullifyData", Lit::Bool)
        .build())
}

/// `ExpectationToJavaSerializer.serializeRateLimit`.
fn rate_limit(n: usize, v: &Value) -> Result<String> {
    Ok(Fluent::new(n, "RateLimit.rateLimit()", v)
        .with("withName", "name", Lit::Str)
        .with_code("withAlgorithm", "algorithm", |a| format!("org.mockserver.model.RateLimit.Algorithm.{}", scalar(a).to_uppercase()))
        .with("withLimit", "limit", Lit::Int)
        .with("withWindowMillis", "windowMillis", Lit::Long)
        .with("withBurst", "burst", Lit::Long)
        .with("withRefillPerSecond", "refillPerSecond", Lit::Double)
        .with("withErrorStatus", "errorStatus", Lit::Int)
        .with("withRetryAfter", "retryAfter", Lit::Str)
        .build())
}

/// `ExpectationToJavaSerializer.serializeCaptureRule`.
fn capture_rule(n: usize, v: &Value) -> Result<String> {
    Ok(Fluent::new(n, "CaptureRule.captureRule()", v)
        .with("withSource", "source", Lit::Enum("org.mockserver.model.CaptureRule.Source"))
        .with("withExpression", "expression", Lit::Str)
        .with("withInto", "into", Lit::Str)
        .build())
}

/// `ExpectationToJavaSerializer.serializeCrossProtocolScenario`.
fn cross_protocol_scenario(n: usize, v: &Value) -> Result<String> {
    Ok(Fluent::new(n, "CrossProtocolScenario.crossProtocolScenario()", v)
        .with("withTrigger", "trigger", Lit::Enum("org.mockserver.model.CrossProtocolTrigger"))
        .with("withScenarioName", "scenarioName", Lit::Str)
        .with("withTargetState", "targetState", Lit::Str)
        .with("withMatchPattern", "matchPattern", Lit::Str)
        .build())
}

fn request_value(n: usize, v: &Value) -> Result<String> {
    let empty = Map::new();
    request(n, v.as_object().unwrap_or(&empty))
}

/// `ExpectationToJavaSerializer.serializeStep`.
fn step(n: usize, v: &Value) -> Result<String> {
    let object_callback = v.get("httpObjectCallback").is_some_and(|c| !c.is_null());
    Ok(Fluent::new(n, "ExpectationStep.step()", v)
        .with_object("withHttpRequest", "httpRequest", request_value)?
        .with_object("withHttpClassCallback", "httpClassCallback", class_callback)?
        .comment(object_callback, "NOT POSSIBLE TO GENERATE CODE FOR OBJECT CALLBACK")
        .with_object("withHttpForward", "httpForward", forward)?
        .with_object("withHttpOverrideForwardedRequest", "httpOverrideForwardedRequest", override_forwarded)?
        .with_object("withHttpResponse", "httpResponse", response)?
        .with_object("withHttpError", "httpError", error)?
        .with("withResponder", "responder", Lit::Bool)
        .with_delay("withDelay", "delay")?
        .with("withBlocking", "blocking", Lit::Bool)
        .with_delay("withTimeout", "timeout")?
        .with("withFailurePolicy", "failurePolicy", Lit::Enum("org.mockserver.model.FailurePolicy"))
        .build())
}

/// `AfterActionToJavaSerializer`.
fn after_action(n: usize, v: &Value) -> Result<String> {
    let object_callback = v.get("httpObjectCallback").is_some_and(|c| !c.is_null());
    Ok(Fluent::new(n, "AfterAction.afterAction()", v)
        .with_object("withHttpRequest", "httpRequest", request_value)?
        .with_object("withHttpRequestTemplate", "httpRequestTemplate", template)?
        .with_object("withHttpClassCallback", "httpClassCallback", class_callback)?
        .comment(object_callback, "NOT POSSIBLE TO GENERATE CODE FOR OBJECT CALLBACK")
        .with_delay("withDelay", "delay")?
        .with("withBlocking", "blocking", Lit::Bool)
        .with_delay("withTimeout", "timeout")?
        .with("withFailurePolicy", "failurePolicy", Lit::Enum("org.mockserver.model.FailurePolicy"))
        .build())
}

/// `BinaryResponseToJavaSerializer`.
fn binary_response(n: usize, v: &Value) -> Result<String> {
    Ok(Fluent::new(n, "BinaryResponse.binaryResponse()", v)
        .with_bytes("withBinaryData", "binaryData")
        .with_delay("withDelay", "delay")?
        .with("withUpstream", "upstream", Lit::Enum("org.mockserver.model.BinaryResponse.Upstream"))
        .build())
}

/// `GrpcStreamResponseToJavaSerializer`.
fn grpc_stream_response(n: usize, v: &Value) -> Result<String> {
    Ok(Fluent::new(n, "GrpcStreamResponse.grpcStreamResponse()", v)
        .with("withStatusName", "statusName", Lit::Str)
        .with("withStatusMessage", "statusMessage", Lit::Str)
        .with_headers("headers")?
        .with_each_non_empty("withMessages", "messages", grpc_stream_message)?
        .with("withCloseConnection", "closeConnection", Lit::Bool)
        .with_delay("withDelay", "delay")?
        .build())
}

fn grpc_stream_message(n: usize, v: &Value) -> Result<String> {
    Ok(Fluent::new(n, "GrpcStreamMessage.grpcStreamMessage()", v)
        .with("withJson", "json", Lit::Str)
        .with("withTemplateType", "templateType", Lit::Enum("org.mockserver.model.HttpTemplate.TemplateType"))
        .with_delay("withDelay", "delay")?
        .build())
}

/// `GrpcBidiResponseToJavaSerializer`.
fn grpc_bidi_response(n: usize, v: &Value) -> Result<String> {
    Ok(Fluent::new(n, "GrpcBidiResponse.grpcBidiResponse()", v)
        .with("withStatusName", "statusName", Lit::Str)
        .with("withStatusMessage", "statusMessage", Lit::Str)
        .with_headers("headers")?
        .with_each_non_empty("withMessages", "messages", grpc_stream_message)?
        .with_each_non_empty("withRules", "rules", grpc_bidi_rule)?
        .with("withCloseConnection", "closeConnection", Lit::Bool)
        .with_delay("withDelay", "delay")?
        .build())
}

fn grpc_bidi_rule(n: usize, v: &Value) -> Result<String> {
    Ok(Fluent::new(n, "GrpcBidiRule.grpcBidiRule()", v)
        .with_code("withMatchJson", "matchJson", nottable_code)
        .with_each_non_empty("withResponses", "responses", grpc_stream_message)?
        .build())
}

/// `HttpWebSocketResponseToJavaSerializer.nottableString`: the value verbatim, with its `not` flag.
fn nottable_code(v: &Value) -> String {
    let s = NString::from_json(v);
    let (value, not, optional) = s.map(|s| (s.value, s.not, s.optional)).unwrap_or((None, false, false));
    let factory = if optional { "NottableOptionalString.optional(" } else { "NottableString.string(" };
    let value = value.map(|v| format!("\"{}\"", escape_java(&v))).unwrap_or_else(|| "null".into());
    format!("{factory}{value}, {not})")
}

/// `HttpSseResponseToJavaSerializer`.
fn sse_response(n: usize, v: &Value) -> Result<String> {
    Ok(Fluent::new(n, "HttpSseResponse.sseResponse()", v)
        .with("withStatusCode", "statusCode", Lit::Int)
        .with_headers("headers")?
        .with_each_non_empty("withEvents", "events", sse_event)?
        .with("withCloseConnection", "closeConnection", Lit::Bool)
        .with("withTemplateType", "templateType", Lit::Enum("org.mockserver.model.HttpTemplate.TemplateType"))
        .with_delay("withDelay", "delay")?
        .build())
}

fn sse_event(n: usize, v: &Value) -> Result<String> {
    Ok(Fluent::new(n, "SseEvent.sseEvent()", v)
        .with("withEvent", "event", Lit::Str)
        .with("withData", "data", Lit::Str)
        .with("withId", "id", Lit::Str)
        .with("withRetry", "retry", Lit::Int)
        .with_delay("withDelay", "delay")?
        .build())
}

/// `HttpWebSocketResponseToJavaSerializer`.
fn web_socket_response(n: usize, v: &Value) -> Result<String> {
    Ok(Fluent::new(n, "HttpWebSocketResponse.webSocketResponse()", v)
        .with("withSubprotocol", "subprotocol", Lit::Str)
        .with_each_non_empty("withMessages", "messages", web_socket_message)?
        .with_each_non_empty("withMatchers", "matchers", web_socket_matcher)?
        .with("withCloseConnection", "closeConnection", Lit::Bool)
        .with_object("withGraphqlSubscriptionFilter", "graphqlSubscriptionFilter", graphql_filter)?
        .with("withTemplateType", "templateType", Lit::Enum("org.mockserver.model.HttpTemplate.TemplateType"))
        .with_delay("withDelay", "delay")?
        .build())
}

fn web_socket_message(n: usize, v: &Value) -> Result<String> {
    Ok(Fluent::new(n, "WebSocketMessage.webSocketMessage()", v)
        .with("withText", "text", Lit::Str)
        .with_bytes("withBinary", "binary")
        .with_delay("withDelay", "delay")?
        .build())
}

fn web_socket_matcher(n: usize, v: &Value) -> Result<String> {
    // The DTO sets frame type `ANY` when none is given, and `withTextMatcher` sets `TEXT`.
    let mut o = v.as_object().cloned().unwrap_or_default();
    let frame = if get(&o, "textMatcher").is_some() { Value::from("TEXT") } else { get(&o, "frameType").cloned().unwrap_or_else(|| Value::from("ANY")) };
    o.insert("frameType".into(), frame);
    let v = Value::Object(o);
    // the text matcher first: setting it also sets the frame type, which is then set as it was
    Ok(Fluent::new(n, "WebSocketMessageMatcher.webSocketMessageMatcher()", &v)
        .with_code("withTextMatcher", "textMatcher", nottable_code)
        .with("withFrameType", "frameType", Lit::Enum("org.mockserver.model.WebSocketFrameType"))
        .with_each("withResponses", "responses", web_socket_message)?
        .build())
}

fn graphql_filter(n: usize, v: &Value) -> Result<String> {
    let lit = |k: &str| v.get(k).map(|s| literal(s, Lit::Str)).unwrap_or_else(|| "null".into());
    let factory = format!("new GraphQLBody({}, {}, {})", lit("query"), lit("operationName"), lit("variablesSchema"));
    Ok(Fluent::new(n, &factory, v)
        .with("withSelectionSetMatchType", "selectionSetMatchType", Lit::Enum("org.mockserver.model.SelectionSetMatchType"))
        .with_literals("withFields", "fields", Lit::Str)
        .with("withSchema", "schema", Lit::Str)
        .build())
}

/// `java.util.Arrays.asList(...)` of string literals (`HttpLlmResponseToJavaSerializer.stringList`).
fn string_list(v: &Value) -> String {
    let items = v.as_array().map(|a| a.iter().map(|s| literal(s, Lit::Str)).collect::<Vec<_>>().join(", ")).unwrap_or_default();
    format!("java.util.Arrays.asList({items})")
}

/// `HttpLlmResponseToJavaSerializer`.
fn llm_response(n: usize, v: &Value) -> Result<String> {
    Ok(Fluent::new(n, "HttpLlmResponse.llmResponse()", v)
        .with("withProvider", "provider", Lit::Enum("org.mockserver.model.Provider"))
        .with("withModel", "model", Lit::Str)
        .with_object("withCompletion", "completion", llm_completion)?
        .with_object("withEmbedding", "embedding", |n, v| {
            Ok(Fluent::new(n, "EmbeddingResponse.embedding()", v)
                .with("withDimensions", "dimensions", Lit::Int)
                .with("withDeterministicFromInput", "deterministicFromInput", Lit::Bool)
                .with("withSeed", "seed", Lit::Long)
                .build())
        })?
        .with_object("withRerank", "rerank", |n, v| {
            Ok(Fluent::new(n, "RerankResponse.rerank()", v)
                .with("withTopN", "topN", Lit::Int)
                .with("withDeterministicFromInput", "deterministicFromInput", Lit::Bool)
                .with("withSeed", "seed", Lit::Long)
                .build())
        })?
        .with_object("withModeration", "moderation", |n, v| {
            Ok(Fluent::new(n, "ModerationResponse.moderationResponse()", v)
                .with_code("withFlaggedCategories", "flaggedCategories", string_list)
                .with("withModel", "model", Lit::Str)
                .build())
        })?
        .with_object("withContentFilter", "contentFilter", |n, v| {
            Ok(Fluent::new(n, "LlmContentFilter.llmContentFilter()", v)
                .with("withHate", "hate", Lit::Str)
                .with("withSexual", "sexual", Lit::Str)
                .with("withViolence", "violence", Lit::Str)
                .with("withSelfHarm", "selfHarm", Lit::Str)
                .build())
        })?
        .with_object("withConversationPredicates", "conversationPredicates", llm_conversation_predicates)?
        .with_object("withChaos", "chaos", llm_chaos)?
        .with_delay("withDelay", "delay")?
        .build())
}

fn llm_completion(n: usize, v: &Value) -> Result<String> {
    Ok(Fluent::new(n, "Completion.completion()", v)
        .with("withText", "text", Lit::Str)
        .with_each("withToolCalls", "toolCalls", |n, v| {
            let name = v.get("name").map(|s| literal(s, Lit::Str)).unwrap_or_else(|| "null".into());
            Ok(Fluent::new(n, &format!("ToolUse.toolUse({name})"), v)
                .with("withId", "id", Lit::Str)
                .with("withArguments", "arguments", Lit::Str)
                .build())
        })?
        .with("withStopReason", "stopReason", Lit::Str)
        .with_object("withUsage", "usage", |n, v| {
            Ok(Fluent::new(n, "Usage.usage()", v)
                .with("withInputTokens", "inputTokens", Lit::Int)
                .with("withOutputTokens", "outputTokens", Lit::Int)
                .with("withCachedInputTokens", "cachedInputTokens", Lit::Int)
                .with("withCacheCreationTokens", "cacheCreationTokens", Lit::Int)
                .with("withReasoningTokens", "reasoningTokens", Lit::Int)
                .build())
        })?
        .with("withStreaming", "streaming", Lit::Bool)
        .with_object("withStreamingPhysics", "streamingPhysics", |n, v| {
            Ok(Fluent::new(n, "StreamingPhysics.streamingPhysics()", v)
                .with_delay("withTimeToFirstToken", "timeToFirstToken")?
                .with("withTokensPerSecond", "tokensPerSecond", Lit::Int)
                .with("withJitter", "jitter", Lit::Double)
                .with("withSeed", "seed", Lit::Long)
                .with("withSubwordStreaming", "subwordStreaming", Lit::Bool)
                .build())
        })?
        .with("withOutputSchema", "outputSchema", Lit::Str)
        .with("withEnforceOutputSchema", "enforceOutputSchema", Lit::Bool)
        .with("withModel", "model", Lit::Str)
        .with("withToolChoice", "toolChoice", Lit::Str)
        .with("withReasoningText", "reasoningText", Lit::Str)
        .with("withReasoningSignature", "reasoningSignature", Lit::Str)
        .build())
}

fn llm_conversation_predicates(n: usize, v: &Value) -> Result<String> {
    Ok(Fluent::new(n, "ConversationPredicates.conversationPredicates()", v)
        .with("withTurnIndex", "turnIndex", Lit::Int)
        .with("withLatestMessageContains", "latestMessageContains", Lit::Str)
        .with("withLatestMessageMatches", "latestMessageMatches", Lit::Str)
        .with("withLatestMessageRole", "latestMessageRole", Lit::Enum("org.mockserver.llm.ParsedMessage.Role"))
        .with("withContainsToolResultFor", "containsToolResultFor", Lit::Str)
        .with("withSemanticMatchAgainst", "semanticMatchAgainst", Lit::Str)
        .with_object("withNormalization", "normalization", |n, v| {
            Ok(Fluent::new(n, "NormalizationOptions.normalizationOptions()", v)
                .with("withCollapseWhitespace", "collapseWhitespace", Lit::Bool)
                .with("withLowercase", "lowercase", Lit::Bool)
                .with("withSortJsonKeys", "sortJsonKeys", Lit::Bool)
                .with("withDropBuiltInVolatileFields", "dropBuiltInVolatileFields", Lit::Bool)
                .with_code("withDropVolatileFields", "dropVolatileFields", string_list)
                .build())
        })?
        .build())
}

fn llm_chaos(n: usize, v: &Value) -> Result<String> {
    Ok(Fluent::new(n, "LlmChaosProfile.llmChaosProfile()", v)
        .with("withErrorStatus", "errorStatus", Lit::Int)
        .with("withRetryAfter", "retryAfter", Lit::Str)
        .with("withErrorProbability", "errorProbability", Lit::Double)
        .with("withTruncateMode", "truncateMode", Lit::Enum("org.mockserver.model.LlmChaosProfile.TruncateMode"))
        .with("withTruncateAtFraction", "truncateAtFraction", Lit::Double)
        .with("withMalformedSse", "malformedSse", Lit::Bool)
        .with("withSeed", "seed", Lit::Long)
        .with("withQuotaName", "quotaName", Lit::Str)
        .with("withQuotaLimit", "quotaLimit", Lit::Int)
        .with("withQuotaWindowMillis", "quotaWindowMillis", Lit::Long)
        .with("withQuotaErrorStatus", "quotaErrorStatus", Lit::Int)
        .with("withTokenQuotaLimit", "tokenQuotaLimit", Lit::Long)
        .with("withTokenQuotaWindowMillis", "tokenQuotaWindowMillis", Lit::Long)
        .with("withErrorKind", "errorKind", Lit::Str)
        .with("withContentFilterBlockProbability", "contentFilterBlockProbability", Lit::Double)
        .build())
}
