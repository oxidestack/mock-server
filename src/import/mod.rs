//! `PUT /mockserver/import` and `PUT /mockserver/recordings/promote` (`HttpState`): foreign documents (HAR, Postman,
//! Pact, WireMock, Mountebank, Mockoon) become expectations, a recorded-traffic NDJSON archive goes back into the
//! event log, and recorded exchanges become active mocks. Every importer builds expectations in input form (the
//! JSON `ExpectationSerializer` would write for the Java objects the upstream importer builds), then
//! `redact` (`ImportRedaction`/`FixtureRedactor`) and `consolidate` (`RecordedExpectationPostProcessor`) rework
//! them before they are upserted.

pub mod body_files;
mod consolidate;
mod har;
mod mockoon;
mod mountebank;
mod postman;
mod recording;
pub mod redact;
mod wiremock;
mod wiremock_template;

use jackson::JsonNode;
use serde_json::{Map, Value, json};

use crate::chaos::url_decode;
use crate::java_text::quote;
use crate::reply::Reply;
use crate::request::{HttpRequest, MultiMap};
use crate::state::State;
use crate::json;

pub use redact::Options;

/// An importer's outcome: expectations and, for the migration importers, their warnings (`ImportResult`).
pub struct Imported {
    pub expectations: Vec<Value>,
    pub warnings: Option<Vec<Warning>>,
}

/// `ImportWarning`, serialised with its properties sorted.
pub struct Warning {
    pub item: String,
    pub construct: String,
    pub detail: String,
}

impl Warning {
    pub fn new(item: impl Into<String>, construct: impl Into<String>, detail: impl Into<String>) -> Warning {
        Warning { item: item.into(), construct: construct.into(), detail: detail.into() }
    }

    fn json(&self) -> Value {
        json!({"construct": self.construct, "detail": self.detail, "item": self.item})
    }
}

/// `buildImportRedactionOptions`.
pub fn redaction_options(request: &HttpRequest) -> Options {
    let enabled = !query(request, "redactSensitiveData").is_some_and(|v| v.eq_ignore_ascii_case("false"));
    Options {
        enabled,
        additional_headers: split_comma_separated(query(request, "additionalRedactedHeaders")),
        additional_body_fields: split_comma_separated(query(request, "additionalRedactedBodyFields")),
    }
}

fn split_comma_separated(value: Option<&str>) -> Vec<String> {
    value.map(|v| v.split(',').map(str::trim).filter(|p| !p.is_empty()).map(str::to_string).collect()).unwrap_or_default()
}

fn query<'a>(request: &'a HttpRequest, name: &str) -> Option<&'a str> {
    crate::request::first(&request.query, name)
}

fn text(status: u32, body: impl Into<String>) -> Reply {
    Reply::api_header(status, "text/plain", body.into())
}

#[derive(Clone, Copy)]
pub enum Level {
    Warn,
    Error,
}

/// A WARN or ERROR event: the console and, at that level, `retrieve?type=LOGS`.
pub fn event(state: &State, level: Level, entry: crate::recorded::LogEntry) {
    let logged = match level {
        Level::Warn => !matches!(state.log_level.as_str(), "OFF" | "ERROR"),
        Level::Error => state.log_level.as_str() != "OFF",
    };
    if logged {
        let mut entry = entry;
        let at = match level {
            Level::Warn => {
                crate::log::entry_as(state, crate::recorded::Level::Warn, &entry);
                crate::recorded::Level::Warn
            }
            Level::Error => {
                crate::log::entry_as(state, crate::recorded::Level::Error, &entry);
                crate::recorded::Level::Error
            }
        };
        // An entry of no type of its own takes the level's.
        if entry.kind == crate::recorded::Kind::Info {
            entry = entry.kind(if at == crate::recorded::Level::Warn { crate::recorded::Kind::Warn } else { crate::recorded::Kind::Error });
        }
        state.log.message(entry.level(at));
    }
}

fn failure(state: &State, request: &HttpRequest, format: &str, message: String) -> Reply {
    let entry = crate::recorded::LogEntry::new(crate::recorded::Kind::Info, format).args([crate::recorded::Arg::from(crate::recorded::logged(request)), (&message).into()]);
    event(state, Level::Error, entry);
    text(400, message)
}

/// `PUT /mockserver/import`.
pub fn import(state: &State, request: &HttpRequest) -> Reply {
    match import_reply(state, request) {
        Ok(reply) => reply,
        Err(message) => failure(state, request, "exception handling request for import:{}error:{}", message),
    }
}

fn import_reply(state: &State, request: &HttpRequest) -> Result<Reply, String> {
    let format = query(request, "format");
    let options = redaction_options(request);
    if format.is_some_and(|f| f.eq_ignore_ascii_case("recording")) {
        return recording::import(state, request, &options);
    }
    let body = request.body_json_or_xml_str();
    if body.trim().is_empty() {
        return Err("import request body is required — must be a HAR, Postman collection, Pact contract, WireMock stub, Mountebank imposter or Mockoon environment JSON document".into());
    }
    let plain = |expectations: Vec<Value>| Imported { expectations, warnings: None };
    let imported = match format.map(str::to_ascii_lowercase).as_deref() {
        Some("har") => plain(har::import(&body, &options)?),
        Some("postman") => plain(postman::import(&body, &options)?),
        Some("pact") => plain(crate::pact::import(&body, &options)?),
        Some("wiremock") => wiremock::import(&body, &options, query(request, "filesDirectory"))?,
        Some("mountebank") => mountebank::import(&body, &options)?,
        Some("mockoon") => mockoon::import(&body, &options)?,
        Some(other) if !other.is_empty() => {
            return Err(format!("unsupported import format: {} (supported formats: har, postman, pact, wiremock, mountebank, mockoon, recording)", format.unwrap_or(other)));
        }
        _ => {
            let root = parse(&body)?;
            let at = |path: &[&str]| path.iter().fold(root.clone(), |node, key| node.path(key));
            let textual = |path: &[&str]| at(path).is_textual();
            if !at(&["log", "entries"]).is_missing() {
                plain(har::import(&body, &options)?)
            } else if !at(&["info"]).is_missing() && !at(&["item"]).is_missing() {
                plain(postman::import(&body, &options)?)
            } else if at(&["interactions"]).is_array() {
                plain(crate::pact::import(&body, &options)?)
            } else if at(&["mappings"]).is_array()
                || textual(&["request", "urlPath"])
                || textual(&["request", "urlPathPattern"])
                || textual(&["request", "urlPattern"])
                || at(&["response", "jsonBody"]).is_object()
                || textual(&["response", "fault"])
            {
                wiremock::import(&body, &options, query(request, "filesDirectory"))?
            } else if at(&["imposters"]).is_array() || (textual(&["protocol"]) && at(&["stubs"]).is_array()) {
                mountebank::import(&body, &options)?
            } else if at(&["routes"]).is_array() {
                mockoon::import(&body, &options)?
            } else {
                return Err("unable to auto-detect import format — use ?format=har, ?format=postman, ?format=pact, ?format=wiremock, ?format=mountebank, ?format=mockoon or ?format=recording query parameter".into());
            }
        }
    };
    let flag = |name: &str| query(request, name).is_some_and(|v| v.eq_ignore_ascii_case("true"));
    let mut expectations = imported.expectations;
    if flag("consolidate") || flag("parameterize") {
        expectations = consolidate::consolidate(&expectations, flag("parameterize"));
    }
    let upserted = crate::control::add_generated(state, &expectations);
    Ok(match imported.warnings {
        None => Reply::api_body(201, "application/json", expectations_json(&upserted)),
        Some(warnings) => {
            let body = json!({
                "expectations": Value::Array(upserted),
                "warnings": Value::Array(warnings.iter().map(Warning::json).collect()),
            });
            Reply::api_body(201, "application/json", json::pretty(&body))
        }
    })
}

/// `PUT /mockserver/pact/import`.
pub fn pact_import(state: &State, request: &HttpRequest) -> Reply {
    let result = (|| {
        let body = request.body_json_or_xml_str();
        if body.trim().is_empty() {
            return Err("Pact import request body is required — must be a Pact v3 contract JSON document".to_string());
        }
        let expectations = crate::pact::import(&body, &redaction_options(request))?;
        Ok(expectations_json(&crate::control::add_generated(state, &expectations)))
    })();
    match result {
        Ok(body) => Reply::api_body(201, "application/json", body),
        Err(message) => failure(state, request, "exception handling request for pact import:{}error:{}", message),
    }
}

/// `PUT /mockserver/recordings/promote`.
pub fn promote(state: &State, request: &HttpRequest) -> Reply {
    let result = (|| {
        let body = request.body_json_or_xml_str();
        let filter = if body.trim().is_empty() {
            None
        } else {
            // `JsonSchemaValidator.isValid` reports a document it cannot read as the exception.
            if let Err(e) = crate::jnode::read_tree(&body) {
                event(state, Level::Error, crate::recorded::LogEntry::at(crate::recorded::Level::Error, "exception validating JSON"));
                let class = e.class.rsplit('.').next().unwrap_or_default();
                return Err(crate::schema::incorrect_request_matcher(&body, &format!("{class} - {}", e.message)));
            }
            let v = json::parse_lenient(body.as_bytes()).map_err(|e| e.to_string())?;
            if let Err(report) = crate::schema::validate_request_definition(&v) {
                return Err(crate::schema::incorrect_request_matcher(&body, &report));
            }
            // SECURITY: carries the server's remote-`$ref` policy into the compile.
            Some(crate::matcher::string::with_remote_refs_policy(state.json_schema_allow_remote_refs(), || crate::matcher::RequestMatcher::compile(&v)))
        };
        let options = redaction_options(request);
        let off = |name: &str| query(request, name).is_some_and(|v| v.eq_ignore_ascii_case("false"));
        Ok(promote_recordings(state, filter.as_ref(), !off("consolidate"), !off("parameterize"), &options))
    })();
    match result {
        Ok(activated) => Reply::api_body(201, "application/json", expectations_json(&activated)),
        Err(message) => failure(state, request, "exception handling request to promote recordings:{}error:{}", message),
    }
}

/// `HttpState.promoteRecordings`: the recorded expectations matching `filter`, redacted, then consolidated (or
/// each made unlimited), upserted; their canonical form.
pub fn promote_recordings(state: &State, filter: Option<&crate::matcher::RequestMatcher>, consolidate: bool, parameterize: bool, options: &Options) -> Vec<Value> {
    let recorded: Vec<Value> = state.log.matching(filter).iter().filter_map(|x| recorded_expectation(x.recorded_input.as_ref()?, x.recorded.as_ref()?)).collect();
    let mut recorded = redact::redact(recorded, options);
    // A promoted mock serves applications calling MockServer directly, with their own Host: no transport headers, no Host.
    for e in recorded.iter_mut() {
        crate::transport_headers::strip_expectation(e, true);
    }
    let produced = if consolidate {
        consolidate::consolidate(&recorded, parameterize)
    } else {
        recorded
            .iter()
            .map(|e| {
                let mut o = Map::new();
                if let Some(r) = e.get("httpRequest") {
                    o.insert("httpRequest".into(), r.clone());
                }
                if let Some(r) = e.get("httpResponse") {
                    o.insert("httpResponse".into(), r.clone());
                }
                o.insert("times".into(), json!({"unlimited": true}));
                o.insert("timeToLive".into(), json!({"unlimited": true}));
                Value::Object(o)
            })
            .collect()
    };
    crate::control::add_generated(state, &produced)
}

/// `HttpState.postProcessRecordedExpectations` on `retrieve?type=RECORDED_EXPECTATIONS`, up to its redaction step:
/// `?captureHeaders=a,b` (present, even empty) keeps only those request headers, `?repeatsAsScenarios=true` turns
/// a request recorded with different responses into one response sequence, then `?consolidate` or `?parameterize`
/// (`true`, any case) consolidates, or else the startup property `deduplicateRecordedExpectations` deduplicates and
/// templatizes (generalising volatile values under `templatizeRecordedValues`); the last two log their counts. An
/// expectation kept as recorded keeps its exchange; a changed one is the first exchange with the new recorded
/// forms (the retrieve formats read only those), under its own id or a new one.
pub fn post_process_recorded(state: &State, request: &HttpRequest, recorded: Vec<std::sync::Arc<crate::recorded::Exchange>>) -> Vec<std::sync::Arc<crate::recorded::Exchange>> {
    let flag = |name: &str| query(request, name).is_some_and(|v| v.eq_ignore_ascii_case("true"));
    let (consolidate_flag, parameterize) = (flag("consolidate"), flag("parameterize"));
    let captured = captured_header_names(request);
    let repeats = flag("repeatsAsScenarios");
    let deduplicate = !(consolidate_flag || parameterize) && state.config.deduplicate_recorded_expectations();
    if captured.is_none() && !repeats && !(consolidate_flag || parameterize) && !deduplicate {
        return recorded;
    }
    // Each expectation as its model, with the index of the exchange it still is (`None` once changed).
    let mut items: Vec<(Option<usize>, Value)> = recorded
        .iter()
        .enumerate()
        .map(|(i, x)| (Some(i), x.recorded_input.as_ref().zip(x.recorded.as_ref()).and_then(|(i, c)| recorded_expectation(i, c)).unwrap_or(Value::Null)))
        .collect();
    fn apply(items: Vec<(Option<usize>, Value)>, step: impl FnOnce(&[Value]) -> Vec<consolidate::Processed>) -> Vec<(Option<usize>, Value)> {
        let models: Vec<Value> = items.iter().map(|(_, m)| m.clone()).collect();
        step(&models)
            .into_iter()
            .map(|p| match p {
                consolidate::Processed::Kept(i) => items[i].clone(),
                consolidate::Processed::Built(model) => (None, model),
            })
            .collect()
    }
    if let Some(names) = &captured {
        items = apply(items, |m| consolidate::capture_headers(m, names));
    }
    if repeats {
        items = apply(items, consolidate::sequence_repeats);
    }
    let counted = if consolidate_flag || parameterize {
        let before = items.len();
        items = apply(items, |m| consolidate::consolidate_indexed(m, parameterize));
        Some(("consolidated", before))
    } else if deduplicate {
        let before = items.len();
        items = apply(items, |m| consolidate::deduplicate_and_templatize(m, state.config.templatize_recorded_values()));
        Some(("deduplicated and templatized", before))
    } else {
        None
    };
    let out: Vec<_> = items
        .into_iter()
        .map(|(kept, model)| match kept {
            Some(i) => recorded[i].clone(),
            None => {
                let mut exchange = (*recorded[0]).clone();
                let id = model.get("id").and_then(Value::as_str).map(str::to_string).unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
                let canonical = model.as_object().map(|o| crate::canonical::expectation(o, &id)).unwrap_or_default();
                exchange.recorded = Some(recording::typed_bodies(canonical));
                exchange.recorded_input = Some(model);
                std::sync::Arc::new(exchange)
            }
        })
        .collect();
    if let Some((verb, before)) = counted {
        let message = format!("{verb} recorded expectations from {before} to {}", out.len());
        state.log.message(crate::recorded::LogEntry::new(crate::recorded::Kind::Info, message));
    }
    out
}

/// `capturedHeaderNames`: the names in every `captureHeaders` value, split at commas, blank ones dropped; `None`
/// when the parameter is absent.
fn captured_header_names(request: &HttpRequest) -> Option<Vec<String>> {
    let (_, values) = request.query.iter().find(|(k, _)| k.eq_ignore_ascii_case("captureHeaders"))?;
    Some(values.iter().flat_map(|v| v.split(',')).map(str::trim).filter(|n| !n.is_empty()).map(str::to_string).collect())
}

/// A recorded expectation as the model object upstream holds: the input form (header order as received), with
/// the typed bodies and socket addresses of the recorded form.
fn recorded_expectation(input: &Value, recorded: &Value) -> Option<Value> {
    let mut e = input.as_object()?.clone();
    for key in ["httpRequest", "httpResponse"] {
        let (Some(Value::Object(message)), Some(canonical)) = (e.get_mut(key), recorded.get(key)) else { continue };
        match canonical.get("body") {
            Some(body) => {
                message.insert("body".into(), body.clone());
            }
            None => {
                message.remove("body");
            }
        }
        for address in ["localAddress", "remoteAddress"] {
            if let Some(v) = canonical.get(address) {
                message.insert(address.into(), v.clone());
            }
        }
    }
    Some(Value::Object(e))
}

/// `ExpectationSerializer.serialize` of a list: `[]` when empty.
fn expectations_json(items: &[Value]) -> String {
    if items.is_empty() { "[]".to_string() } else { json::pretty(items) }
}

// ----- reading documents ------------------------------------------------------------------------------------

/// `ObjectMapper.readTree`, failing with Jackson's message.
pub fn parse(text: &str) -> Result<JsonNode, String> {
    crate::jnode::read_tree(text).map_err(|e| e.message)
}

/// `Base64.getDecoder().decode`: padding optional.
pub fn base64_decode(text: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
    const BASIC: GeneralPurpose =
        GeneralPurpose::new(&base64::alphabet::STANDARD, GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent).with_decode_allow_trailing_bits(true));
    BASIC.decode(text).ok()
}

/// A query string split as the importers do: `name=value` pairs, `URLDecoder`-decoded; a bare name has an empty
/// value.
pub fn parse_query_string(raw: Option<&str>) -> MultiMap {
    let Some(raw) = raw.filter(|r| !r.is_empty()) else { return Vec::new() };
    let mut out = Vec::new();
    for pair in crate::java_text::split(raw, "&") {
        let (name, value) = match pair.find('=') {
            Some(eq) => (url_decode(&pair[..eq]), url_decode(&pair[eq + 1..])),
            None => (url_decode(pair), String::new()),
        };
        out.push((name, vec![value]));
    }
    out
}

/// The parts of a URL the importers read (`new URI(url)`: `getScheme`, `getHost`, `getPort`, `getPath`,
/// `getRawQuery`), or `None` where upstream's parse throws and the importer falls back.
pub struct UrlParts {
    pub scheme: Option<String>,
    pub host: Option<String>,
    pub port: i64,
    /// Decoded; `None` for an opaque URL (`mailto:x`).
    pub path: Option<String>,
    /// `getRawPath`: as written.
    pub raw_path: Option<String>,
    pub raw_query: Option<String>,
}

pub fn url_parts(s: &str) -> Option<UrlParts> {
    let uri = crate::java_uri::parse(s).ok()?;
    Some(UrlParts { path: crate::java_uri::path(&uri), scheme: uri.scheme, host: uri.host, port: uri.port as i64, raw_path: uri.raw_path, raw_query: uri.raw_query })
}

/// The importers' path and query of a URL: its decoded path (`/` when empty) and query parameters, or, when the
/// URL does not parse, the URL itself as the path if it starts with `/` (else `/`) and no parameters.
pub fn path_and_query(url: &str) -> (String, MultiMap) {
    match url_parts(url) {
        Some(parts) => (parts.path.filter(|p| !p.is_empty()).unwrap_or_else(|| "/".into()), parse_query_string(parts.raw_query.as_deref())),
        None => (if url.starts_with('/') { url.to_string() } else { "/".into() }, Vec::new()),
    }
}

/// `name.toLowerCase(ROOT).replaceAll("[^a-z0-9]+", "-").replaceAll("^-+|-+$", "")`.
pub fn slug(name: &str) -> String {
    let mut out = String::new();
    for c in name.to_lowercase().chars() {
        if c.is_ascii_lowercase() || c.is_ascii_digit() {
            out.push(c);
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    out.trim_matches('-').to_string()
}

/// The regex the migration importers build for a substring, prefix or suffix predicate, after a `(?i)` or empty
/// flag prefix.
#[derive(Clone, Copy)]
pub enum Affix {
    Contains,
    StartsWith,
    EndsWith,
}

pub fn affix_regex(affix: Affix, flags: &str, value: &str) -> String {
    let quoted = quote(value);
    match affix {
        Affix::Contains => format!("{flags}.*{quoted}.*"),
        Affix::StartsWith => format!("{flags}^{quoted}.*"),
        Affix::EndsWith => format!("{flags}.*{quoted}$"),
    }
}

/// Where a migration importer is in the source document, and the warnings it has collected.
pub struct Ctx<'a> {
    pub locator: String,
    warnings: &'a mut Vec<Warning>,
}

impl<'a> Ctx<'a> {
    pub fn new(locator: String, warnings: &'a mut Vec<Warning>) -> Ctx<'a> {
        Ctx { locator, warnings }
    }

    pub fn warn(&mut self, construct: impl Into<String>, detail: impl Into<String>) {
        self.warnings.push(Warning::new(self.locator.clone(), construct, detail));
    }

    /// The same warnings under another locator.
    pub fn at(&mut self, locator: String) -> Ctx<'_> {
        Ctx { locator, warnings: self.warnings }
    }
}

// ----- building expectations in input form --------------------------------------------------------------------

/// `withQueryStringParameter` / `withHeader` (a `LinkedListMultimap`): values join an entry of exactly the same name,
/// duplicates kept.
pub fn add(entries: &mut MultiMap, name: &str, values: Vec<String>) {
    match entries.iter_mut().find(|(n, _)| n == name) {
        Some((_, existing)) => existing.extend(values),
        None => entries.push((name.to_string(), values)),
    }
}

/// `withQueryStringParameters(list)` / `withHeaders(list)`: replaces the entries.
pub fn set(entries: &mut MultiMap, list: MultiMap) {
    entries.clear();
    for (name, values) in list {
        add(entries, &name, values);
    }
}

/// Marks a multimap value that is a date-time comparison (`NottableDateTimeString`), its input form as JSON text
/// after the marker; [`entries_json`] writes it as that object.
pub const DATE_TIME_VALUE: &str = "\u{1}dateTime:";

pub fn entries_json(entries: &[(String, Vec<String>)]) -> Value {
    let value = |v: &String| match v.strip_prefix(DATE_TIME_VALUE).and_then(|j| serde_json::from_str::<Value>(j).ok()) {
        Some(date_time) => date_time,
        None => Value::String(v.clone()),
    };
    Value::Array(entries.iter().map(|(n, vs)| json!({"name": n, "values": vs.iter().map(value).collect::<Vec<_>>()})).collect())
}

/// A request (`HttpRequest`) in input form; multimaps in list form, in insertion order.
#[derive(Default, Clone)]
pub struct Req {
    pub method: Option<String>,
    pub path: Option<String>,
    pub path_params: MultiMap,
    pub query: MultiMap,
    pub headers: MultiMap,
    pub body: Option<Value>,
}

impl Req {
    pub fn json(&self) -> Value {
        let mut o = Map::new();
        if let Some(m) = &self.method {
            o.insert("method".into(), m.clone().into());
        }
        if let Some(p) = &self.path {
            o.insert("path".into(), p.clone().into());
        }
        if !self.path_params.is_empty() {
            o.insert("pathParameters".into(), entries_json(&self.path_params));
        }
        if !self.query.is_empty() {
            o.insert("queryStringParameters".into(), entries_json(&self.query));
        }
        if !self.headers.is_empty() {
            o.insert("headers".into(), entries_json(&self.headers));
        }
        if let Some(b) = &self.body {
            o.insert("body".into(), b.clone());
        }
        Value::Object(o)
    }
}

/// A response (`HttpResponse`) in input form.
#[derive(Default, Clone)]
pub struct Resp {
    pub status: i64,
    pub headers: MultiMap,
    pub body: Option<Value>,
    pub delay_millis: Option<i64>,
}

impl Resp {
    pub fn status(status: i64) -> Resp {
        Resp { status, ..Resp::default() }
    }

    pub fn json(&self) -> Value {
        let mut o = Map::new();
        o.insert("statusCode".into(), self.status.into());
        if !self.headers.is_empty() {
            o.insert("headers".into(), entries_json(&self.headers));
        }
        if let Some(b) = &self.body {
            o.insert("body".into(), b.clone());
        }
        if let Some(d) = self.delay_millis {
            o.insert("delay".into(), json!({"timeUnit": "MILLISECONDS", "value": d}));
        }
        Value::Object(o)
    }
}

/// Response headers from an object of names to a value or an array of values (WireMock, Mountebank, Pact).
pub fn header_object(headers: &JsonNode) -> MultiMap {
    headers
        .as_object()
        .map(|o| {
            o.iter()
                .map(|(name, v)| match v.as_array() {
                    Some(items) => (name.clone(), items.iter().map(JsonNode::as_text).collect()),
                    None => (name.clone(), vec![v.as_text()]),
                })
                .collect()
        })
        .unwrap_or_default()
}

/// `StringBody(text, contentType)`.
pub fn string_body_with_type(text: &str, content_type: &str) -> Value {
    json!({"type": "STRING", "string": text, "contentType": content_type})
}

/// `StringBody.subString(text)`.
pub fn substring_body(text: &str) -> Value {
    json!({"type": "STRING", "string": text, "subString": true})
}

/// `JsonBody.json(text, matchType)`.
pub fn json_body(text: &str, match_type: &str) -> Value {
    json!({"type": "JSON", "json": text, "matchType": match_type})
}

pub fn regex_body(regex: &str) -> Value {
    json!({"type": "REGEX", "regex": regex})
}

pub fn json_path_body(path: &str) -> Value {
    json!({"type": "JSON_PATH", "jsonPath": path})
}

/// `new Expectation(request)`: unlimited times and time to live, priority 0, and the given id.
pub fn expectation(id: Option<&str>, request: &Req) -> Map<String, Value> {
    let mut o = Map::new();
    if let Some(id) = id {
        o.insert("id".into(), id.into());
    }
    o.insert("priority".into(), 0.into());
    o.insert("httpRequest".into(), request.json());
    o.insert("times".into(), json!({"unlimited": true}));
    o.insert("timeToLive".into(), json!({"unlimited": true}));
    o
}

/// `ImportIds.fromRequestMatchers`: each id, which holds its readable prefix (`har`, `postman-<slug>`), gets
/// `-` and the first 12 hex digits of the SHA-256 of `String.valueOf(httpRequest)` (the matcher's pretty JSON),
/// and requests repeated within one file are numbered in file order (`-2`, ...).
pub fn ids_from_request_matchers(mut expectations: Vec<Value>) -> Vec<Value> {
    let mut occurrences: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for e in &mut expectations {
        let Some(o) = e.as_object_mut() else { continue };
        let prefix = o.get("id").and_then(Value::as_str).unwrap_or_default().to_string();
        let matcher = o.get("httpRequest").map(crate::canonical::request_definition).map_or_else(|| "null".to_string(), |r| json::pretty(&r));
        let id = format!("{prefix}-{}", &crate::llm::sigv4::hex_sha256(matcher.as_bytes())[..12]);
        let occurrence = occurrences.entry(id.clone()).and_modify(|n| *n += 1).or_insert(1);
        let id = if *occurrence == 1 { id } else { format!("{id}-{occurrence}") };
        o.insert("id".into(), id.into());
    }
    expectations
}

/// `thenRespond(response)`.
pub fn respond(e: &mut Map<String, Value>, response: &Resp) {
    e.insert("httpResponse".into(), response.json());
}

/// `thenRespond(list).withResponseMode(mode)`.
pub fn respond_all(e: &mut Map<String, Value>, responses: &[Resp], mode: &str) {
    e.insert("httpResponses".into(), Value::Array(responses.iter().map(Resp::json).collect()));
    e.insert("responseMode".into(), mode.into());
}

/// `thenError(error().withDropConnection(true))`.
pub fn drop_connection(e: &mut Map<String, Value>) {
    e.insert("httpError".into(), json!({"dropConnection": true}));
}

/// `thenForward(forward)` to the URL's host, scheme and port (default 80/443); `HttpForward`'s defaults without one.
pub fn forward(e: &mut Map<String, Value>, url: Option<&UrlParts>) {
    let mut f = Map::new();
    match url {
        Some(url) => {
            if let Some(h) = &url.host {
                f.insert("host".into(), h.clone().into());
            }
            let https = url.scheme.as_deref().is_some_and(|s| s.eq_ignore_ascii_case("https"));
            f.insert("port".into(), (if url.port > 0 { url.port } else if https { 443 } else { 80 }).into());
            f.insert("scheme".into(), (if https { "HTTPS" } else { "HTTP" }).into());
        }
        None => {
            f.insert("port".into(), 80.into());
            f.insert("scheme".into(), "HTTP".into());
        }
    }
    e.insert("httpForward".into(), Value::Object(f));
}

pub fn set_scenario(e: &mut Map<String, Value>, key: &str, value: Option<String>) {
    if let Some(v) = value {
        e.insert(key.into(), v.into());
    }
}

/// The importers' `textOrNull` helpers (each upstream importer carries its own copy).
pub trait TextOrNull {
    /// `path(field)` as text, `None` when missing or null.
    fn text_or_null(&self, field: &str) -> Option<String>;
    /// [`TextOrNull::text_or_null`] for value nodes only (containers are `None` too).
    fn value_text(&self, field: &str) -> Option<String>;
}

impl TextOrNull for JsonNode {
    fn text_or_null(&self, field: &str) -> Option<String> {
        self.get(field).filter(|v| !v.is_null()).map(JsonNode::as_text)
    }

    fn value_text(&self, field: &str) -> Option<String> {
        self.get(field).filter(|v| !v.is_null() && v.is_value_node()).map(JsonNode::as_text)
    }
}

/// A node's `fieldNames()` printed as a `List` (the importers' warnings).
pub fn field_names(node: &JsonNode) -> String {
    format!("[{}]", node.field_names().join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_parts_and_fallback() {
        let u = url_parts("https://api.example.com:8443/a%20b/c?x=1&y=%2F#frag").unwrap();
        assert_eq!((u.scheme.as_deref(), u.host.as_deref(), u.port, u.path.as_deref(), u.raw_query.as_deref()), (Some("https"), Some("api.example.com"), 8443, Some("/a b/c"), Some("x=1&y=%2F")));
        assert!(url_parts("http://x/a b").is_none());
        assert!(url_parts("http://x/%zz").is_none());
        assert_eq!(url_parts("mailto:a@b").unwrap().path, None);
        assert_eq!(path_and_query("http://host").0, "/");
        assert_eq!(path_and_query("/users?q"), ("/users".to_string(), vec![("q".to_string(), vec![String::new()])]));
        assert_eq!(path_and_query("{{base}}/x").0, "/");
        assert_eq!(slug("Get User (v2)!"), "get-user-v2");
        assert_eq!(affix_regex(Affix::StartsWith, "(?i)", "a.b"), "(?i)^\\Qa.b\\E.*");
    }
}
