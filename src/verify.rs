//! `PUT /mockserver/verify` and `/verifySequence` (§3.5–§3.6), with MockServer's failure messages.

use serde_json::Value;

use crate::json;
use crate::matcher::{RequestMatcher, ResponseMatcher};
use crate::recorded::{self, Kind};
use crate::request::HttpRequest;
use crate::reply::Reply;
use crate::state::State;
use crate::{canonical, schema};

/// Default of `maximumNumberOfRequestToReturnInVerificationFailure`.
const MAX_REQUESTS_IN_FAILURE: usize = 10;

/// `MockServerEventLog.MAX_VERIFY_TIMEOUT_MILLIS`: the most a verification's `timeout` may wait.
const MAX_VERIFY_TIMEOUT_MILLIS: i64 = 60_000;

/// `MockServerEventLogNotifier.COALESCE_WINDOW_MILLIS`: a log listener hears of the changes of a window at its end.
const COALESCE_WINDOW_MILLIS: u64 = 250;

thread_local! {
    /// Set while a waiting verification re-evaluates: such an evaluation logs nothing (`logResult` false).
    static QUIET: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn quiet() -> bool {
    QUIET.with(std::cell::Cell::get)
}

pub enum Outcome {
    Passed,
    Failed(String),
    BadRequest(String),
}

impl Outcome {
    pub fn into_reply(self) -> Reply {
        match self {
            Outcome::Passed => Reply::api(202),
            Outcome::Failed(message) => Reply::api_header(406, "text/plain", message),
            Outcome::BadRequest(message) => Reply::api_header(400, "text/plain", message),
        }
    }
}

/// `VerificationTimes`: `-1` means unbounded.
#[derive(Clone, Copy)]
struct Times {
    at_least: i64,
    at_most: i64,
}

impl Times {
    fn parse(v: Option<&Value>) -> Times {
        // Upstream's VerificationTimesDTODeserializer leaves the DTO `null` for an object with neither
        // `atLeast` nor `atMost` present (the schema forbids any other property) — including `{}`, not just an
        // absent `times` field entirely — and VerificationDTO.buildObject() defaults a `null` times to once()
        // (`VerificationDTO.java`). A present-but-empty object must collapse to the same default as an absent one,
        // not to "unbounded both ways" (which would make verify() always pass regardless of the request log).
        let present = v.filter(|t| t.get("atLeast").is_some() || t.get("atMost").is_some());
        match present {
            None => Times { at_least: 1, at_most: 1 },
            Some(t) => Times {
                at_least: t.get("atLeast").and_then(Value::as_i64).unwrap_or(-1),
                at_most: t.get("atMost").and_then(Value::as_i64).unwrap_or(-1),
            },
        }
    }

    fn matches(self, n: i64) -> bool {
        (self.at_least == -1 || n >= self.at_least) && (self.at_most == -1 || n <= self.at_most)
    }

    fn describe(self) -> String {
        let count = |n: i64| if n == 1 { "once".to_string() } else { format!("{n} times") };
        if self.at_least == self.at_most {
            format!("exactly {}", count(self.at_most))
        } else if self.at_most == -1 {
            format!("at least {}", count(self.at_least))
        } else if self.at_least == -1 {
            format!("at most {}", count(self.at_most))
        } else {
            format!("between {} and {} times", self.at_least, self.at_most)
        }
    }

    /// `MockServerEventLog.foundTooOften`: an upper bound was exceeded.
    fn found_too_often(self, matched: i64) -> bool {
        self.at_most != -1 && matched > self.at_most
    }

    /// `MockServerEventLog.countMismatch`: the lead phrase of a count-verification failure.
    fn count_mismatch(self, subject: &str, matched: i64) -> String {
        if self.found_too_often(matched) {
            format!("{subject} found {matched} time{} but should have been found {}", if matched == 1 { "" } else { "s" }, self.describe())
        } else {
            format!("{subject} not found {}", self.describe())
        }
    }

    /// The `VERIFICATION_FAILED` entry's message format for a count mismatch of `subject` ("request", "response").
    fn mismatch_format(self, subject: &str, matched: i64) -> String {
        if self.found_too_often(matched) {
            format!("{subject} found too often, it should have been found {}, expected:{{}}but was:{{}}", self.describe())
        } else {
            format!("{subject} not found {}, expected:{{}}but was:{{}}", self.describe())
        }
    }
}

/// `what` names the document in the schema failure ("verification", "verification sequence").
impl Times {
    /// `VerificationTimes` as the verification log prints it: an unbounded side is left out.
    fn json(self) -> Value {
        let mut o = serde_json::Map::new();
        if self.at_least != -1 {
            o.insert("atLeast".into(), self.at_least.into());
        }
        if self.at_most != -1 {
            o.insert("atMost".into(), self.at_most.into());
        }
        Value::Object(o)
    }
}

/// A log line about the request matcher `subject` (every line when `None`).
fn log(state: &State, entry: recorded::LogEntry, subject: Option<&Value>) {
    if quiet() {
        return;
    }
    // The filter's regex timeouts so far come first, as upstream logs them while it evaluates.
    crate::dataplane::flush_regex_timeouts(state);
    let subject = match subject {
        Some(d) => recorded::Subject::Definition(d.clone()),
        None => recorded::Subject::None,
    };
    state.log.message_about(entry, subject);
}

/// A verification's entry: its type, correlation id and the request definition it is about. `outcome`: logged from
/// the event log's own thread (the result of a verification), which stamps no port.
fn entry(kind: recorded::Kind, format: impl Into<String>, correlation: &str, subject: Option<&Value>, outcome: bool) -> recorded::LogEntry {
    // `setHttpRequest(verification.getHttpRequest())`: the default `request()` for a response-only verification.
    let mut entry = recorded::LogEntry::new(kind, format).correlation(correlation).request_json(subject.cloned().unwrap_or_else(|| Value::Object(Default::default())));
    if outcome {
        entry = entry.without_port();
    }
    entry
}

/// Received requests as a verification failure's log argument: one alone, several (or none) as a list.
fn requests_argument(all: &[std::sync::Arc<HttpRequest>]) -> recorded::Arg {
    let json = match all {
        [one] => recorded::model_form(one),
        many => Value::Array(many.iter().map(|r| recorded::model_form(r)).collect()),
    };
    recorded::Arg::with_text(json, logged_requests(all))
}

/// [`requests_argument`] over every recorded request, a DNS or binary definition as it is.
fn received_argument(all: &[recorded::Received]) -> recorded::Arg {
    if all.iter().all(|r| r.http().is_some()) {
        return requests_argument(&http_only(all));
    }
    let one = |r: &recorded::Received| match r {
        recorded::Received::Http(r) => recorded::model_form(r),
        recorded::Received::Definition(d) => d.clone(),
    };
    let json = match all {
        [r] => one(r),
        many => Value::Array(many.iter().map(one).collect()),
    };
    let text = match all {
        [r] => json::pretty(&one(r)),
        many => java_list(many.iter().map(|r| json::pretty(&one(r)))),
    };
    recorded::Arg::with_text(json, text)
}

/// The HTTP requests among recorded ones.
fn http_only(all: &[recorded::Received]) -> Vec<std::sync::Arc<HttpRequest>> {
    all.iter().filter_map(|r| r.http().cloned()).collect()
}

/// Whether a request matcher describes DNS queries or binary messages, which only their received entries record.
fn is_dns_or_binary(filter: &Value) -> bool {
    canonical::is_dns_request(filter) || canonical::is_binary_request(filter)
}

/// Whether `filter` (compiled as `matcher`) counts recorded request `r`: an HTTP request through the matcher, a DNS
/// query's or binary message's definition only under a DNS or binary filter (`HttpRequestPropertiesMatcher` refuses
/// them).
fn counts_received(filter: &Value, matcher: &RequestMatcher, r: &recorded::Received) -> bool {
    match r {
        recorded::Received::Http(r) => !is_dns_or_binary(filter) && crate::matcher::as_received(|| matcher.matches(r, crate::matcher::Mode::ControlPlane)),
        recorded::Received::Definition(d) => is_dns_or_binary(filter) && crate::control::definition_matches_filter(d, matcher),
    }
}

/// `HttpState.rejectUnverifiable`: a DNS query or binary message has nothing but its received entry, so a verification
/// counting responses or dispositions would count zero and `never()` would pass; it is refused (400) instead.
fn reject_unverifiable<'a>(definitions: impl IntoIterator<Item = &'a Value>, how: &str) -> Result<(), Outcome> {
    match definitions.into_iter().find(|d| is_dns_or_binary(d)) {
        Some(d) => Err(Outcome::BadRequest(format!("DNS and binary requests cannot be verified {how}, found:\n{}", json::pretty(d)))),
        None => Ok(()),
    }
}

const WITH_A_RESPONSE: &str = "with a response, because they have no HTTP response";
const BY_DISPOSITION: &str = "by disposition, which counts only mocked or forwarded HTTP requests";

/// `List.toString` of JSON-printing elements, as log arguments print collections.
fn java_list(items: impl IntoIterator<Item = String>) -> String {
    format!("[{}]", items.into_iter().collect::<Vec<_>>().join(", "))
}

/// The verification as its log argument serialises: properties alphabetical.
fn verification_json(v: &Value, replacements: &[(&str, Value)]) -> Value {
    let mut o = v.as_object().cloned().unwrap_or_default();
    for (k, value) in replacements {
        o.insert((*k).to_string(), value.clone());
    }
    alphabetical(&Value::Object(o))
}

/// Received requests as a verification failure's log line lists them: one alone, several as a list.
fn logged_requests(all: &[std::sync::Arc<HttpRequest>]) -> String {
    match all {
        [one] => json::pretty(&recorded::model_form(one)),
        many => java_list(many.iter().map(|r| json::pretty(&recorded::model_form(r)))),
    }
}

fn parse(state: &State, body: &[u8], what: &str, validate: fn(&Value) -> Result<(), String>) -> Result<Value, Outcome> {
    let raw = String::from_utf8_lossy(body);
    let incorrect = |report: &str| Outcome::BadRequest(crate::schema::incorrect_json_format(what, &raw, report));
    // `JsonSchemaValidator.isValid` logs what it throws (a document it cannot read, an unresolvable schema
    // reference) and reports it as `<exception class> - <message>`.
    let thrown = || crate::log::error_event(state, recorded::LogEntry::at(recorded::Level::Error, "exception validating JSON"));
    if !raw.trim().is_empty() && let Err(e) = crate::jnode::read_tree(&raw) {
        thrown();
        let class = e.class.rsplit('.').next().unwrap_or_default();
        return Err(incorrect(&format!("{class} - {}", e.message)));
    }
    let v: Value = crate::json::parse_lenient(body).map_err(|e| Outcome::BadRequest(e.to_string()))?;
    validate(&v).map_err(|report| {
        if report.starts_with(schema::INVALID_SCHEMA_REF) {
            thrown();
        }
        incorrect(&report)
    })?;
    Ok(v)
}

/// `VerificationSerializer` / `VerificationSequenceSerializer.deserialize`: what reading the DTO throws (`cause`) is
/// logged and reported with the body as sent.
fn unreadable(state: &State, body: &[u8], class: &str, cause: &str) -> Outcome {
    let raw = String::from_utf8_lossy(body);
    let format = format!("exception while parsing{{}}for {class} {cause}");
    crate::log::error_event(state, recorded::LogEntry::at(recorded::Level::Error, &format).args([raw.as_ref()]));
    Outcome::BadRequest(format!("exception while parsing [{raw}] for {class}"))
}

/// The request matcher a verification refers to, either inline or via an expectation id.
fn resolve(state: &State, v: &Value, key: &str) -> Result<Value, Outcome> {
    if let Some(r) = v.get(key) {
        return Ok(canonical::request_definition(r));
    }
    let id = v.get("expectationId").and_then(|e| e.get("id")).and_then(Value::as_str).unwrap_or_default();
    // `RequestMatchers.retrieveRequestDefinitions` rejects a blank id before looking it up.
    if id.trim().is_empty() {
        return Err(Outcome::BadRequest(format!("No expectation id specified found \"{id}\"")));
    }
    match state.store.definition(id) {
        Some(definition) => Ok(definition),
        None => Err(Outcome::BadRequest(format!("No expectation found with id {id}"))),
    }
}

/// A request matcher as verification failures print it (`RequestDefinitionSerializer` with properties sorted).
fn alphabetical(filter: &Value) -> Value {
    match filter.as_object() {
        Some(o) => {
            let mut keys: Vec<&String> = o.keys().collect();
            keys.sort();
            Value::Object(keys.into_iter().map(|k| (k.clone(), o[k].clone())).collect())
        }
        None => filter.clone(),
    }
}

/// A request matcher as `HttpRequestPrettyPrintedDTO` prints it in verification failures: only its fields (body,
/// cookies, headers, keepAlive, method, path, protocol, queryStringParameters, secure), alphabetical, every name and
/// value as `NottableString.getValue()` gives it (no `!` or `?`, a schema as its JSON), and query parameters,
/// headers and cookies in `java.util.HashMap` iteration order. Other request definitions print as before.
fn pretty_printed(filter: &Value) -> Value {
    let Some(o) = filter.as_object() else { return filter.clone() };
    if o.contains_key("specUrlOrPayload") {
        // `OpenAPIDefinitionSerializer`: not, operationId, specUrlOrPayload, then master's contextPathPrefix
        let mut sorted = alphabetical(filter);
        if let Some(s) = sorted.as_object_mut() && let Some(prefix) = s.shift_remove("contextPathPrefix") {
            s.insert("contextPathPrefix".into(), prefix);
        }
        return sorted;
    }
    if canonical::is_conditional_request(filter) || canonical::is_binary_request(filter) || canonical::is_dns_request(filter) {
        return alphabetical(filter);
    }
    let mut out = serde_json::Map::new();
    if let Some(body) = o.get("body").filter(|b| !b.is_null()) {
        out.insert("body".into(), body.clone());
    }
    for (key, multi) in [("cookies", false), ("headers", true)] {
        if let Some(map) = pretty_multimap(o.get(key), multi) {
            out.insert(key.into(), map);
        }
    }
    for key in ["keepAlive", "method", "path", "protocol"] {
        let value = match o.get(key) {
            Some(v @ (Value::Bool(_) | Value::Null)) => v.clone(),
            Some(v) if key == "protocol" => v.clone(),
            Some(v) => Value::String(nottable_value(v)),
            None => Value::Null,
        };
        if !value.is_null() && value.as_str() != Some("") {
            out.insert(key.into(), value);
        }
    }
    if let Some(map) = pretty_multimap(o.get("queryStringParameters"), true) {
        out.insert("queryStringParameters".into(), map);
    }
    if let Some(secure) = o.get("secure").filter(|s| s.is_boolean()) {
        out.insert("secure".into(), secure.clone());
    }
    Value::Object(out)
}

/// `NottableString.getValue()`: the text without its `?`/`!` markers; a schema (`NottableSchemaString`) as its
/// JSON, pretty-printed.
fn nottable_value(v: &Value) -> String {
    match v {
        Value::String(s) => {
            let mut s = s.as_str();
            if !s.trim().is_empty() {
                s = s.strip_prefix('?').unwrap_or(s);
                s = s.strip_prefix('!').unwrap_or(s);
                s = s.strip_prefix('?').unwrap_or(s);
            }
            s.to_string()
        }
        Value::Object(o) if o.contains_key("schema") => json::pretty(&o["schema"]),
        // `NottableDateTimeString`: its description
        Value::Object(o) if let Some(Ok(date_time)) = crate::model::DateTimeValue::read(o) => date_time.describe(),
        Value::Object(o) => o.get("value").map(nottable_value).unwrap_or_default(),
        other => other.to_string(),
    }
}

/// A `KeysToMultiValues` (or, `multi` false, `KeysAndValues`) field as the DTO's `HashMap` holds it: names and values
/// through [`nottable_value`], `keyMatchStyle` dropped, in `HashMap` iteration order; `None` when empty.
fn pretty_multimap(v: Option<&Value>, multi: bool) -> Option<Value> {
    let mut entries: Vec<(String, Vec<Value>)> = Vec::new();
    let mut put = |name: String, values: Vec<Value>| match entries.iter_mut().find(|(n, _)| *n == name) {
        Some(entry) => entry.1 = values,
        None => entries.push((name, values)),
    };
    let values_of = |v: &Value| -> Vec<Value> {
        match v {
            Value::Array(items) => items.iter().map(|i| Value::String(nottable_value(i))).collect(),
            other => vec![Value::String(nottable_value(other))],
        }
    };
    match v? {
        Value::Object(map) => {
            for (name, values) in map.iter().filter(|(k, _)| *k != "keyMatchStyle") {
                put(nottable_value(&Value::String(name.clone())), values_of(values));
            }
        }
        Value::Array(items) => {
            for item in items {
                let name = item.get("name").map(nottable_value).unwrap_or_default();
                let values = item.get("values").or_else(|| item.get("value")).map(values_of).unwrap_or_default();
                put(name, values);
            }
        }
        _ => return None,
    }
    if entries.is_empty() {
        return None;
    }
    let keys: Vec<String> = entries.iter().map(|(k, _)| k.clone()).collect();
    let ordered: serde_json::Map<String, Value> = recorded::java_hashmap_order(&keys)
        .into_iter()
        .map(|i| {
            let values = &entries[i].1;
            let value = if multi { Value::Array(values.clone()) } else { values.first().cloned().unwrap_or(Value::String(String::new())) };
            (keys[i].clone(), value)
        })
        .collect();
    Some(Value::Object(ordered))
}

fn all_requests_text(all: &[std::sync::Arc<HttpRequest>]) -> String {
    let requests: Vec<Value> = all.iter().map(|r| recorded::flat(r)).collect();
    // `HttpRequestSerializer.serialize` writes an empty list as `[]`.
    match requests.len() {
        0 => "[]".to_string(),
        1 => json::pretty(&requests[0]),
        _ => json::pretty(&requests),
    }
}

/// [`all_requests_text`] over every recorded request, a DNS or binary definition as `RequestDefinitionSerializer`
/// writes it.
fn received_text(all: &[recorded::Received]) -> String {
    if all.iter().all(|r| r.http().is_some()) {
        return all_requests_text(&http_only(all));
    }
    let requests: Vec<Value> = all
        .iter()
        .map(|r| match r {
            recorded::Received::Http(r) => recorded::flat(r),
            recorded::Received::Definition(d) => d.clone(),
        })
        .collect();
    match requests.len() {
        1 => json::pretty(&requests[0]),
        _ => json::pretty(&requests),
    }
}

/// `MatchDifferenceFormatter`: the fields the closest recorded request got wrong; empty when one matched. The filter
/// is a control-plane matcher, so its differences are a control-plane match's.
fn closest_match_diff(filter: &RequestMatcher, all: &[std::sync::Arc<HttpRequest>]) -> String {
    crate::matcher::with_control_plane(true, || closest_match_diff_of(filter, all))
}

fn closest_match_diff_of(filter: &RequestMatcher, all: &[std::sync::Arc<HttpRequest>]) -> String {
    // `buildClosestMatchDiff` matches each request in a detailed context (its differences log at TRACE)
    // and stops at one that records none.
    for r in all {
        if !filter.note_fail_fast(r) {
            break;
        }
    }
    let closest = all.iter().map(|r| (r, filter.differences(r))).min_by_key(|(_, d)| d.len());
    let Some((request, differences)) = closest.filter(|(_, d)| !d.is_empty()) else { return String::new() };
    let mut out = String::from("\n\nclosest match diff:\n");
    for (field, difference) in differences {
        out.push_str(&format!("  {field}:\n"));
        for line in filter.verification_lines(field, request, &difference) {
            out.push_str(&format!("    {line}\n"));
        }
    }
    out
}

pub fn verify(state: &State, body: &[u8]) -> Outcome {
    let v = match parse(state, body, "verification", schema::validate_verification) {
        Ok(v) => v,
        Err(o) => return o,
    };
    if let Some(cause) = v.get("httpRequest").and_then(crate::matcher::body_deserialization_failure) {
        return unreadable(state, body, "Verification", &format!("{cause} (through reference chain: org.mockserver.serialization.model.VerificationDTO[\"httpRequest\"])"));
    }
    if let Some((cause, chain)) = v.get("httpRequest").and_then(crate::matcher::date_time_failure) {
        let cause = format!("{cause} (through reference chain: org.mockserver.serialization.model.VerificationDTO[\"httpRequest\"]{chain})");
        return unreadable(state, body, "Verification", &cause);
    }
    if let Some(cause) = v.get("httpRequest").and_then(crate::matcher::client_ip_failure) {
        return unreadable(state, body, "Verification", &cause);
    }
    // `VerificationTimesDTO.buildObject` is `VerificationTimes.between(atLeast, atMost)`, which refuses a bound below
    // the unbounded sentinel -1; `VerificationSerializer.deserialize` reports it without the cause.
    let negative = ["atLeast", "atMost"].into_iter()
        .find_map(|k| v.get("times").and_then(|t| t.get(k)).and_then(Value::as_i64).filter(|n| *n < -1).map(|n| (k, n)));
    if let Some((bound, n)) = negative {
        let cause = format!("{bound} must not be negative but was {n} (through reference chain: org.mockserver.serialization.model.VerificationDTO[\"times\"])");
        return unreadable(state, body, "Verification", &cause);
    }
    let filter_json = if v.get("httpRequest").is_some() || v.get("expectationId").is_some() {
        // `VerificationDTO.setHttpRequest(RequestDefinitionDTO)` (upstream 9cf7dc832): an inline OpenAPI definition is
        // read as one, as expectations, retrieve, clear and verifySequence read it; 8.0.0 bound an empty request.
        match resolve(state, &v, "httpRequest") {
            Ok(f) => Some(f),
            Err(o) => return o,
        }
    } else {
        None
    };
    if v.get("httpResponse").is_some() && let Err(o) = reject_unverifiable(filter_json.iter(), WITH_A_RESPONSE) {
        return o;
    }
    if v.get("disposition").is_some() && let Err(o) = reject_unverifiable(filter_json.iter(), BY_DISPOSITION) {
        return o;
    }
    let times = Times::parse(v.get("times"));
    // T1.9: a count verify (no `httpResponse`, no `expectationId`) adds each peer's LOCAL match count when
    // cluster fan-in is on; an unreachable peer fails it closed. Asked before the verification is logged, as upstream.
    let mut remote_matches = 0_i64;
    if v.get("httpResponse").is_none() && v.get("expectationId").is_none() {
        let fan_in = state.cluster_fan_in();
        if fan_in.enabled() {
            let remote = fan_in.fan_in_requests(filter_json.as_ref());
            for (peer, error) in &remote.failures {
                crate::log::warn_event(state, recorded::LogEntry::new(Kind::Warn, "cluster verify/retrieve fan-in could not reach peer{}error:{}").args([peer.as_str(), error.as_str()]));
            }
            if remote.has_unreachable_peers() {
                return Outcome::Failed(format!("Verification could not be evaluated cluster-wide: unreachable peer(s) [{}]", remote.unreachable_peers.join(", ")));
            }
            remote_matches = remote.merged.len() as i64;
        }
    }
    let mut shown = vec![("times", times.json())];
    if let Some(f) = &filter_json {
        shown.push(("httpRequest", f.clone()));
    }
    if let Some(r) = v.get("httpResponse") {
        shown.push(("httpResponse", verification_response(r)));
    }
    let started = chrono::Local::now().timestamp_millis();
    let correlation = uuid::Uuid::new_v4().to_string();
    let verification = verification_json(&v, &shown);
    log(state, entry(Kind::Verification, "verifying requests that match:{}", &correlation, filter_json.as_ref(), false).args([&verification]), filter_json.as_ref());
    if let Some(response) = v.get("httpResponse") {
        return eventually(state, &v, || verify_response(state, &v, filter_json.as_ref(), response, times, &correlation, started));
    }
    let filter_json = filter_json.expect("the schema requires a request, an id or a response");
    eventually(state, &v, || verify_request(state, &v, &filter_json, times, remote_matches, &correlation, started))
}

/// A verification's `disposition`: how the requests it counts were handled.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    Mocked,
    Forwarded,
}

impl Disposition {
    /// The schema allows only `MOCKED` and `FORWARDED`.
    fn of(name: &str) -> Disposition {
        if name == "FORWARDED" { Disposition::Forwarded } else { Disposition::Mocked }
    }

    pub fn other(self) -> Disposition {
        match self {
            Disposition::Mocked => Disposition::Forwarded,
            Disposition::Forwarded => Disposition::Mocked,
        }
    }

    fn kind(self) -> Kind {
        match self {
            Disposition::Mocked => Kind::ExpectationResponse,
            Disposition::Forwarded => Kind::ForwardedRequest,
        }
    }

    /// As the verification summary names it.
    pub fn word(self) -> &'static str {
        match self {
            Disposition::Mocked => "mocked",
            Disposition::Forwarded => "forwarded",
        }
    }
}

/// `verifyRequest`: one evaluation of a request count verification.
fn verify_request(state: &State, v: &Value, filter_json: &Value, times: Times, remote_matches: i64, correlation: &str, started: i64) -> Outcome {
    // SECURITY: carries the server's remote-`$ref` policy into the compile.
    let filter = crate::matcher::string::with_remote_refs_policy(state.json_schema_allow_remote_refs(), || RequestMatcher::compile(filter_json));
    // By expectation id upstream counts the requests that expectation served, and lists only served requests.
    let by_id = v.get("expectationId").and_then(|e| e.get("id")).and_then(Value::as_str);
    // `Verification.withDisposition`: counts the requests mocked (`EXPECTATION_RESPONSE`) or forwarded
    // (`FORWARDED_REQUEST`) instead of every received one; by expectation id it is ignored.
    let disposition = v.get("disposition").and_then(Value::as_str).filter(|_| by_id.is_none()).map(Disposition::of);
    // DNS queries and binary messages are counted from their received entries (upstream #97, #101).
    let matched = match (by_id, disposition) {
        (Some(id), _) => state.log.recorded_requests(true).iter().filter(|r| r.expectation_id.as_deref() == Some(id)).count() as i64,
        (None, Some(d)) => state.log.handled(d.kind(), &filter) as i64 + remote_matches,
        (None, None) if is_dns_or_binary(filter_json) => {
            state.log.recorded_requests(false).iter().filter(|r| counts_received(filter_json, &filter, &r.request)).count() as i64 + remote_matches
        }
        (None, None) => state.log.matching_requests(Some(&filter)).len() as i64 + remote_matches,
    };
    if times.matches(matched) {
        if let Some((failure, loss)) = unprovable_after_eviction(state, &times, "Request") {
            let format = format!("request:{{}}could not be verified {} because the event log has evicted entries:{{}}", times.describe());
            log(state, entry(Kind::VerificationFailed, format, correlation, Some(filter_json), true).args([filter_json, &loss]), Some(filter_json));
            return Outcome::Failed(failure);
        }
        let format = format!("request:{{}}found {}", times.describe());
        log(state, entry(Kind::VerificationPassed, format, correlation, Some(filter_json), true).args([filter_json]), Some(filter_json));
        return Outcome::Passed;
    }
    // A waiting verification's in-between evaluations discard their failure message (`logResult` false).
    if quiet() {
        return Outcome::Failed(String::new());
    }
    // `retrieveAllRecordedRequests`: DNS and binary definitions too.
    let recorded_all = state.log.recorded_requests(by_id.is_some());
    let received: Vec<recorded::Received> = recorded_all.iter().map(|r| r.request.clone()).collect();
    let all = http_only(&received);
    // `verify` builds the failure message, closest match diff included (its regex timeouts too), before it logs.
    // Only for an HTTP request matcher (`verification.getHttpRequest() instanceof HttpRequest`): none for OpenAPI,
    // a conditional or an anyOf.
    let detailed = detailed(state);
    let closest = if all.is_empty() || !is_http_request(filter_json) || !detailed { String::new() } else { closest_match_diff(&filter, &all) };
    let summary = if detailed && is_http_request(filter_json) {
        // The summary's evaluation is no `RECEIVED_REQUEST` entry's match: its TRACE differences are the collect-all
        // ones `verify_summary` notes.
        let matches = |m: &RequestMatcher, r: &HttpRequest| m.matches(r, crate::matcher::Mode::ControlPlane);
        let count = recorded_all.iter().filter(|r| r.millis > started).count();
        let arrivals = crate::verify_summary::Arrivals { count, waited: waited(v) };
        // `countOtherDisposition`: the matching requests handled the other way.
        let other = disposition.map(|d| (d, state.log.handled(d.other().kind(), &filter)));
        crate::verify_summary::requests(&filter, &times.counts(matched), remote_matches, other, &received, &matches, arrivals)
    } else {
        String::new()
    };
    let format = times.mismatch_format("request", matched);
    log(state, entry(Kind::VerificationFailed, format, correlation, Some(filter_json), true).args([recorded::Arg::from(filter_json), received_argument(&received)]), Some(filter_json));
    let max = max_in_failure(v);
    let expected = json::pretty(&pretty_printed(filter_json));
    let mut message = if received.len() < max {
        format!("{}, expected:<{expected}> but was:<{}>", times.count_mismatch("Request", matched), received_text(&received))
    } else {
        format!(
            "{}, expected:<{expected}> but was found {matched} time{} among {} total requests",
            times.count_mismatch("Request", matched),
            if matched == 1 { "" } else { "s" },
            received.len()
        )
    };
    message.push_str(&closest);
    message.push_str(&summary);
    Outcome::Failed(message)
}

pub fn verify_sequence(state: &State, body: &[u8]) -> Outcome {
    let v = match parse(state, body, "verification sequence", schema::validate_verification_sequence) {
        Ok(v) => v,
        Err(o) => return o,
    };
    let requests = v.get("httpRequests").and_then(Value::as_array).into_iter().flatten();
    if let Some((i, cause)) = requests.enumerate().find_map(|(i, r)| crate::matcher::body_deserialization_failure(r).map(|c| (i, c))) {
        let chain = format!("(through reference chain: org.mockserver.serialization.model.VerificationSequenceDTO[\"httpRequests\"]->java.util.ArrayList[{i}])");
        return unreadable(state, body, "VerificationSequence", &format!("{cause} {chain}"));
    }
    let requests = v.get("httpRequests").and_then(Value::as_array).into_iter().flatten();
    if let Some((i, (cause, chain))) = requests.enumerate().find_map(|(i, r)| crate::matcher::date_time_failure(r).map(|f| (i, f))) {
        let chain = format!("(through reference chain: org.mockserver.serialization.model.VerificationSequenceDTO[\"httpRequests\"]->java.util.ArrayList[{i}]{chain})");
        return unreadable(state, body, "VerificationSequence", &format!("{cause} {chain}"));
    }
    if let Some(cause) = v.get("httpRequests").and_then(Value::as_array).into_iter().flatten().find_map(crate::matcher::client_ip_failure) {
        return unreadable(state, body, "VerificationSequence", &cause);
    }
    let has_ids = v.get("expectationIds").and_then(Value::as_array).is_some_and(|ids| !ids.is_empty());
    let mut requests: Vec<Value> = v.get("httpRequests").and_then(Value::as_array).into_iter().flatten().map(canonical::request_definition).collect();
    // `HttpState.verify` resolves the ids before the event log verifies (and logs) anything, into the sequence's
    // requests (`withRequests`), which its entries then carry.
    if has_ids {
        let mut resolved = Vec::new();
        for id in v.get("expectationIds").and_then(Value::as_array).into_iter().flatten() {
            match resolve(state, &serde_json::json!({"expectationId": id}), "httpRequest") {
                Ok(f) => resolved.push(f),
                Err(o) => return o,
            }
        }
        requests = resolved;
    }
    let mut shown = vec![("httpRequests", Value::Array(requests.clone()))];
    if let Some(responses) = v.get("httpResponses").and_then(Value::as_array) {
        shown.push(("httpResponses", Value::Array(responses.iter().map(verification_response).collect())));
    }
    if v.get("httpRequests").is_none() && !has_ids {
        shown.remove(0);
    }
    if v.get("httpResponses").and_then(Value::as_array).is_some_and(|r| !r.is_empty()) && let Err(o) = reject_unverifiable(requests.iter(), WITH_A_RESPONSE) {
        return o;
    }
    let started = chrono::Local::now().timestamp_millis();
    let correlation = uuid::Uuid::new_v4().to_string();
    let verification = verification_json(&v, &shown);
    let verifying = recorded::LogEntry::new(Kind::Verification, "verifying sequence that match:{}").correlation(&correlation).requests(requests.clone()).args([&verification]);
    state.log.message_about(verifying, recorded::Subject::Definitions(requests.clone()));
    eventually(state, &v, || verify_sequence_once(state, &v, &requests, &verification, &correlation, started))
}

/// `verifySequenceOnce`: one evaluation of a verification sequence.
fn verify_sequence_once(state: &State, v: &Value, requests: &[Value], verification: &Value, correlation: &str, started: i64) -> Outcome {
    let has_ids = v.get("expectationIds").and_then(Value::as_array).is_some_and(|ids| !ids.is_empty());
    // `verifySequenceOnce`: a sequence with no ids, requests or responses is rejected, not vacuously passed.
    let has_responses = v.get("httpResponses").and_then(Value::as_array).is_some_and(|r| !r.is_empty());
    if !has_ids && requests.is_empty() && !has_responses {
        return Outcome::Failed("No expectations, requests or responses specified in verification sequence".to_string());
    }
    let sequence_found = |state: &State| {
        if quiet() {
            return;
        }
        let listed = recorded::Arg::with_text(Value::Array(requests.to_vec()), java_list(requests.iter().map(json::pretty)));
        crate::dataplane::flush_regex_timeouts(state);
        let found = recorded::LogEntry::new(Kind::VerificationPassed, "request sequence found:{}").correlation(correlation).without_port().args([listed]);
        state.log.message(found);
    };
    if let Some(responses) = v.get("httpResponses").and_then(Value::as_array).filter(|r| !has_ids && !r.is_empty()) {
        let outcome = verify_response_sequence(state, v, responses, correlation, started);
        if matches!(outcome, Outcome::Passed) {
            sequence_found(state);
        }
        return outcome;
    }
    let filters: Vec<Value> = if let Some(requests) = v.get("httpRequests").and_then(Value::as_array) {
        requests.iter().map(canonical::request_definition).collect()
    } else {
        let mut filters = Vec::new();
        for id in v.get("expectationIds").and_then(Value::as_array).into_iter().flatten() {
            match resolve(state, &serde_json::json!({"expectationId": id}), "httpRequest") {
                Ok(f) => filters.push(f),
                Err(o) => return o,
            }
        }
        filters
    };
    if let Some(ids) = v.get("expectationIds").and_then(Value::as_array) {
        // By ids: the expectations must have served requests in this order (`retrieveAllRequests(ids)`).
        // `retrieveAllRequests(ids)`: the requests the listed expectations served.
        let listed: Vec<&str> = ids.iter().filter_map(|i| i.get("id").and_then(Value::as_str)).collect();
        // DNS queries and binary messages too, by the expectation id their received entries name (upstream #101).
        let served: Vec<_> = state.log.recorded_requests(true).into_iter().filter(|x| x.expectation_id.as_deref().is_some_and(|e| listed.contains(&e))).collect();
        let mut next = 0;
        let mut failed = None;
        for (step, id) in listed.iter().enumerate() {
            match served[next..].iter().position(|x| x.expectation_id.as_deref() == Some(*id)) {
                Some(i) => next += i + 1,
                None => {
                    failed = Some(crate::verify_summary::Step { number: step + 1, count: listed.len(), previous: step, searched_from: next });
                    break;
                }
            }
        }
        let Some(step) = failed else {
            sequence_found(state);
            return Outcome::Passed;
        };
        if quiet() {
            return Outcome::Failed(String::new());
        }
        let summary = if detailed(state) {
            let id = listed[step.number - 1];
            crate::verify_summary::expectation_id_sequence(&step, served.len(), |i| served[i].expectation_id.as_deref() == Some(id))
        } else {
            String::new()
        };
        let expected: Vec<Value> = ids
            .iter()
            .filter_map(|i| i.get("id").and_then(Value::as_str))
            .filter_map(|id| state.store.definition(id))
            .collect();
        let all: Vec<recorded::Received> = served.iter().map(|x| x.request.clone()).collect();
        // `verificationSequenceFailureMessage`, as for a sequence of requests
        let expected_list = recorded::Arg::with_text(Value::Array(requests.to_vec()), java_list(requests.iter().map(json::pretty)));
        let not_found = recorded::LogEntry::new(Kind::VerificationFailed, "request sequence not found, expected:{}but was:{}")
            .correlation(correlation)
            .requests(requests.to_vec())
            .without_port()
            .args([expected_list, received_argument(&all)]);
        state.log.message_about(not_found, recorded::Subject::Definitions(requests.to_vec()));
        return Outcome::Failed(format!(
            "Request sequence not found, expected:<{}> but was:<{}>{summary}",
            json::pretty(&expected),
            received_text(&all)
        ));
    }
    // `retrieveAllRecordedRequests(false, LogEntry::getHttpRequests)`: DNS and binary definitions too (upstream #97).
    let recorded_all = state.log.recorded_requests(false);
    let received: Vec<recorded::Received> = recorded_all.iter().map(|r| r.request.clone()).collect();
    let all = http_only(&received);
    let mut next = 0;
    let mut unmatched = None;
    let mut failed_step = None;
    for (step, f) in filters.iter().enumerate() {
        // SECURITY: carries the server's remote-`$ref` policy into the compile.
        let matcher = crate::matcher::string::with_remote_refs_policy(state.json_schema_allow_remote_refs(), || RequestMatcher::compile(f));
        // An OpenAPI filter whose spec cannot be loaded: `transformsToMatcher` throws inside the sequence's try,
        // `verificationSequenceExceptionHandler` (harvested from HttpStateOpenAPISpecLoadThreadTest).
        if let Some(error) = matcher.load_error() {
            if state.info_enabled() && !quiet() {
                let entry = recorded::LogEntry::new(Kind::Exception, "exception:{} while processing verification sequence:{}")
                    .correlation(correlation)
                    .args([recorded::Arg::from(error), recorded::Arg::from(verification)]);
                state.log.message(entry);
            }
            return Outcome::Failed(format!("exception while processing verification sequence {error}"));
        }
        let step_matches = |r: &recorded::Received| match r {
            recorded::Received::Http(r) => !is_dns_or_binary(f) && matcher.matches(r, crate::matcher::Mode::ControlPlane),
            recorded::Received::Definition(_) => counts_received(f, &matcher, r),
        };
        match received[next..].iter().position(step_matches) {
            Some(i) => next += i + 1,
            None => {
                failed_step = Some((crate::verify_summary::Step { number: step + 1, count: filters.len(), previous: step, searched_from: next }, is_http_request(f)));
                unmatched = Some(matcher);
                break;
            }
        }
    }
    let Some(unmatched) = unmatched else {
        sequence_found(state);
        return Outcome::Passed;
    };
    if quiet() {
        return Outcome::Failed(String::new());
    }
    // As in `verify`, the closest match diff (and its regex timeouts) comes before the failure is logged.
    // `unmatchedStepRequest instanceof HttpRequest`
    let http_step = failed_step.as_ref().is_none_or(|(_, http)| *http);
    let closest = if all.is_empty() || !http_step || !detailed(state) { String::new() } else { closest_match_diff(&unmatched, &all) };
    let expected_list = recorded::Arg::with_text(Value::Array(filters.clone()), java_list(filters.iter().map(json::pretty)));
    let not_found = recorded::LogEntry::new(Kind::VerificationFailed, "request sequence not found, expected:{}but was:{}")
        .correlation(correlation)
        .requests(filters.clone())
        .without_port()
        .args([expected_list, received_argument(&received)]);
    crate::dataplane::flush_regex_timeouts(state);
    state.log.message_about(not_found, recorded::Subject::Definitions(filters.clone()));
    // `buildForRequestSequence` runs after `verificationSequenceFailureMessage` has logged the failure, so the
    // summary's regex timeouts come after it.
    let summary = match failed_step {
        Some((step, http)) if detailed(state) => {
            let count = recorded_all.iter().filter(|r| r.millis > started).count();
            let arrivals = crate::verify_summary::Arrivals { count, waited: waited(v) };
            crate::verify_summary::request_sequence(&step, http.then_some(&unmatched), &received, arrivals)
        }
        _ => String::new(),
    };
    let max = max_in_failure(v);
    // `RequestDefinitionSerializer`: a DNS or binary definition as it is.
    let expected = json::pretty(&Value::Array(filters.iter().map(pretty_printed).collect()));
    let mut message = if received.len() < max {
        format!("Request sequence not found, expected:<{expected}> but was:<{}>", received_text(&received))
    } else {
        format!("Request sequence not found, expected:<{expected}> but was not found, found {} other requests", received.len())
    };
    message.push_str(&closest);
    message.push_str(&summary);
    Outcome::Failed(message)
}

/// The exchanges response verification reads (`responseVerificationLogPredicate`): responses an expectation
/// produced or a forward returned, never the server's own no-match 404s.
fn recorded_pairs(state: &State, filter: Option<&RequestMatcher>) -> Vec<std::sync::Arc<recorded::Exchange>> {
    state
        .log
        .matching(filter)
        .into_iter()
        // an `EXPECTATION_RESPONSE` or `FORWARDED_REQUEST` entry: a mock's, a forward's, or a static file's (no expectation)
        .filter(|x| x.expectation_id.is_some() || x.recorded.is_some() || x.entry.as_ref().is_some_and(|e| e.kind == Kind::ExpectationResponse))
        .collect()
}

/// A verification's `httpResponse` as upstream prints it (master's `VerificationHttpResponseDTODeserializer`):
/// its body is read as a request body matcher, so a matcher-only type (REGEX, JSON_PATH, XPATH, JSON_SCHEMA, XML_SCHEMA,
/// PARAMETERS, FUZZY, ALL_OF, …) is kept as that matcher (`ResponseMatchingBodySerializer` writes the wrapped body)
/// instead of becoming the `{ }` an expectation's response body of that type echoes. A body DTO that is already a
/// `BodyWithContentTypeDTO` (binary, JSON, string, XML, file) prints as an expectation's response body does.
fn verification_response(input: &Value) -> Value {
    let out = canonical::response(input);
    let Some(body) = input.get("body").and_then(Value::as_object) else { return out };
    // A content-typed body keeps the matching options the request-body deserializer reads (`subString`, `matchType`,
    // …) and then prints as its DTO does, as a request body echoes.
    const MATCHING: &[&str] = &["subString", "matchType", "matchNumbersAsStrings", "namespacePrefixes"];
    let matching = body.keys().any(|k| MATCHING.iter().any(|m| k.eq_ignore_ascii_case(m)));
    if !matching && canonical::body_type(body).is_none_or(|t| ["BINARY", "JSON", "STRING", "XML", "FILE"].contains(&t.as_str())) {
        return out;
    }
    let matcher = canonical::body(&Value::Object(body.clone()));
    match out {
        // in place when the response form kept a (`{ }`) body, else where `body` goes
        Value::Object(mut o) if o.contains_key("body") => {
            o.insert("body".into(), matcher);
            Value::Object(o)
        }
        other => canonical::with_response_body(&other, &matcher),
    }
}

fn responses_text(responses: &[&Value]) -> String {
    match responses {
        // `HttpResponseSerializer.serialize(HttpResponse...)` writes an empty list as `[]`.
        [] => "[]".to_string(),
        [one] => json::pretty(one),
        many => json::pretty(&Value::Array(many.iter().map(|r| (*r).clone()).collect())),
    }
}

/// `buildClosestResponseMatchDiff`: the fields the closest recorded response (fewest failing fields, first wins)
/// got wrong; empty when one matched.
fn closest_response_diff(matcher: &ResponseMatcher, responses: &[&Value], max: usize) -> String {
    let mut closest: Option<Vec<(&'static str, Vec<String>)>> = None;
    for response in responses.iter().filter(|r| !r.is_null()).take(max) {
        let differences = matcher.differences(response);
        if closest.as_ref().is_none_or(|c| differences.len() < c.len()) {
            let done = differences.is_empty();
            closest = Some(differences);
            if done {
                break;
            }
        }
    }
    let Some(differences) = closest.filter(|d| !d.is_empty()) else { return String::new() };
    let mut out = String::from("\n\nclosest match diff:\n");
    for (field, lines) in differences {
        out.push_str(&format!("  {field}:\n"));
        for line in lines {
            out.push_str(&format!("    {}\n", crate::matcher::diff_line(&line)));
        }
    }
    out
}

/// `upperBoundUnprovableAfterEviction`: a pass that rests on an upper bound (`never()`, `atMost`, `exactly`,
/// `between`) cannot be certified once the log has evicted entries, since the missing ones may have matched. The
/// failure message and what the log lost (the `VERIFICATION_FAILED` entry's argument). Upstream also counts log events
/// its ring buffer dropped (ring full, in-flight byte budget); our log records synchronously and drops none.
fn unprovable_after_eviction(state: &State, times: &Times, subject: &str) -> Option<(String, Value)> {
    if times.at_most == -1 || !state.config.bool_property("failVerificationOnEvictedLog", true) {
        return None;
    }
    let evicted = state.log.evicted();
    if evicted == 0 {
        return None;
    }
    let byte_evicted = state.log.byte_evicted().min(evicted);
    let count_evicted = evicted - byte_evicted;
    let entries = |n: u64| if n == 1 { " recorded entry was" } else { " recorded entries were" };
    let mut message = format!("{subject} could not be verified {} because the event log is not a complete record: ", times.describe());
    let mut remedy = String::from("To fix: ");
    let mut loss = serde_json::Map::new();
    if count_evicted > 0 {
        let max_log_entries = crate::config::max_log_entries(&state.config);
        loss.insert("evictedAtMaxLogEntries".into(), count_evicted.into());
        loss.insert("maxLogEntries".into(), (max_log_entries as u64).into());
        message.push_str(&format!(
            "{count_evicted}{} EVICTED after the log reached its maximum number of entries (maxLogEntries={max_log_entries}). ",
            entries(count_evicted)
        ));
        remedy.push_str("for the evictions at maxLogEntries, raise it, or lower the log level so fewer entries are recorded per request, or keep the log level and set maxLoggedMatchFailures (e.g. to 10) to cap the did-not-match entries logged per request; ");
    }
    if byte_evicted > 0 {
        let max_bytes = crate::config::max_event_log_size_in_bytes(&state.config);
        loss.insert("evictedAtMaxEventLogSizeInBytes".into(), byte_evicted.into());
        loss.insert("maxEventLogSizeInBytes".into(), max_bytes.into());
        message.push_str(&format!(
            "{byte_evicted}{} EVICTED after the log reached its maximum size in bytes (maxEventLogSizeInBytes={max_bytes}). ",
            entries(byte_evicted)
        ));
        remedy.push_str("for the evictions at maxEventLogSizeInBytes, raise it, or set maxLoggedBodyBytes to truncate large bodies so each recorded entry is smaller; ");
    }
    message.push_str("Absence cannot be proven \u{2014} the matching requests may have been discarded rather than never made. ");
    message.push_str(&remedy);
    message.push_str("or reset the event log between tests, or set failVerificationOnEvictedLog=false to restore the previous (unsound) behaviour.");
    Some((message, Value::Object(loss)))
}

/// `detailedVerificationFailures`: a failed verification carries the closest match diff and the summary block.
fn detailed(state: &State) -> bool {
    state.config.bool_property("detailedVerificationFailures", true)
}

/// A verification with a `timeout` waited for its requests (`verification.getTimeout() > 0`).
fn waited(v: &Value) -> bool {
    v.get("timeout").and_then(Value::as_i64).is_some_and(|t| t > 0)
}

/// The recorded exchanges logged after the verification started (`RecordedExchange.arrivedAtMillis`).
fn exchange_arrivals(v: &Value, pairs: &[std::sync::Arc<recorded::Exchange>], started: i64) -> crate::verify_summary::Arrivals {
    let count = pairs.iter().filter(|x| x.timestamp.timestamp_millis() > started).count();
    crate::verify_summary::Arrivals { count, waited: waited(v) }
}

/// `eventuallyVerify`: without a `timeout` (or one of 0 or less) one evaluation, logged. With one (clamped to
/// `MAX_VERIFY_TIMEOUT_MILLIS`) the verification is evaluated without logging, again on every change of the event log,
/// until it passes or the deadline comes; then one final evaluation logs the single outcome and gives the answer.
fn eventually(state: &State, v: &Value, evaluate: impl Fn() -> Outcome) -> Outcome {
    let timeout = v.get("timeout").and_then(Value::as_i64).unwrap_or(0).min(MAX_VERIFY_TIMEOUT_MILLIS);
    // a shut-down scheduler would never fire the deadline: one evaluation, answered at once (fe354ebd5)
    if timeout <= 0 || state.scheduler_is_shut_down() {
        return evaluate();
    }
    // subscribed before the first evaluation, so a change between it and the wait is not missed
    let mut changes = state.log.changes.subscribe();
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout as u64);
    while !passes_quietly(&evaluate) && wait_for_change(&mut changes, deadline) {}
    evaluate()
}

/// One evaluation with logging suppressed; what its matchers met (regex timeouts, traced differences) is dropped, as it
/// would otherwise be logged once per retry, and each such entry would be a log change that triggers another.
fn passes_quietly(evaluate: &impl Fn() -> Outcome) -> bool {
    let was = QUIET.with(|q| q.replace(true));
    let outcome = evaluate();
    QUIET.with(|q| q.set(was));
    if !was {
        crate::matcher::take_regex_timeouts();
        crate::matcher::take_received_trace();
    }
    matches!(outcome, Outcome::Passed)
}

/// Blocks until the event log changes and then for `MockServerEventLogNotifier.COALESCE_WINDOW_MILLIS` more, as
/// upstream's listener is notified once per window after the first change in it (true), or until `deadline` passes
/// first (false). On a server's multi-threaded runtime the worker hands its queued tasks on first, so the requests the
/// verification waits for are still served.
fn wait_for_change(changes: &mut tokio::sync::watch::Receiver<u64>, deadline: std::time::Instant) -> bool {
    let multi_thread = tokio::runtime::Handle::try_current().is_ok_and(|h| h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread);
    let changed = if multi_thread {
        let handle = tokio::runtime::Handle::current();
        tokio::task::block_in_place(|| handle.block_on(async { matches!(tokio::time::timeout_at(deadline.into(), changes.changed()).await, Ok(Ok(()))) }))
    } else {
        loop {
            if changes.has_changed().unwrap_or(false) {
                changes.mark_unchanged();
                break true;
            }
            let now = std::time::Instant::now();
            if now >= deadline {
                break false;
            }
            std::thread::sleep((deadline - now).min(std::time::Duration::from_millis(10)));
        }
    };
    if !changed {
        return false;
    }
    let now = std::time::Instant::now();
    let window = (now + std::time::Duration::from_millis(COALESCE_WINDOW_MILLIS)).min(deadline);
    crate::blocking::off_worker(|| std::thread::sleep(window.saturating_duration_since(now)));
    changes.mark_unchanged();
    window < deadline
}

/// `verification.getHttpRequest() instanceof HttpRequest`: no OpenAPI, conditional, binary or DNS definition.
fn is_http_request(filter: &Value) -> bool {
    filter.get("specUrlOrPayload").is_none() && !canonical::is_conditional_request(filter) && !canonical::is_binary_request(filter) && !canonical::is_dns_request(filter)
}

impl Times {
    fn counts(self, matched: i64) -> crate::verify_summary::Counts {
        crate::verify_summary::Counts { times: self.describe(), matched, found_too_often: self.found_too_often(matched) }
    }
}

fn max_in_failure(v: &Value) -> usize {
    v.get("maximumNumberOfRequestToReturnInVerificationFailure").and_then(Value::as_u64).map(|n| n as usize).unwrap_or(MAX_REQUESTS_IN_FAILURE)
}

/// `verifyResponse`: counts the recorded request-response pairs (of the requests `httpRequest` selects) whose
/// response matches.
fn verify_response(state: &State, v: &Value, filter_json: Option<&Value>, response: &Value, times: Times, correlation: &str, started: i64) -> Outcome {
    // SECURITY: carries the server's remote-`$ref` policy into the compile.
    let filter = crate::matcher::string::with_remote_refs_policy(state.json_schema_allow_remote_refs(), || filter_json.map(RequestMatcher::compile));
    let pairs = recorded_pairs(state, filter.as_ref());
    let matcher = crate::matcher::with_exact_case(state.config.match_exact_case(), || ResponseMatcher::compile(response));
    let matched = pairs.iter().filter(|x| matcher.matches(&x.response)).count() as i64;
    let expected_json = verification_response(response);
    let expected = json::pretty(&expected_json);
    if times.matches(matched) {
        if let Some((failure, loss)) = unprovable_after_eviction(state, &times, "Response") {
            let format = format!("response:{{}}could not be verified {} because the event log has evicted entries:{{}}", times.describe());
            log(state, entry(Kind::VerificationFailed, format, correlation, filter_json, true).args([&expected_json, &loss]), filter_json);
            return Outcome::Failed(failure);
        }
        let format = format!("response:{{}}found {}", times.describe());
        log(state, entry(Kind::VerificationPassed, format, correlation, filter_json, true).args([&expected_json]), filter_json);
        return Outcome::Passed;
    }
    if quiet() {
        return Outcome::Failed(String::new());
    }
    let summary = if detailed(state) { crate::verify_summary::responses(&matcher, &times.counts(matched), &pairs, exchange_arrivals(v, &pairs, started)) } else { String::new() };
    let exchanges: Vec<Value> = pairs.iter().map(|x| recorded::exchange_json(x)).collect();
    let format = times.mismatch_format("response", matched);
    let shown = recorded::Arg::with_text(Value::Array(exchanges.clone()), java_list(exchanges.iter().map(json::pretty)));
    log(state, entry(Kind::VerificationFailed, format, correlation, filter_json, true).args([recorded::Arg::from(&expected_json), shown]), filter_json);
    let max = max_in_failure(v);
    let responses: Vec<&Value> = pairs.iter().map(|x| &x.response).collect();
    let mut message = if pairs.len() < max {
        format!("{}, expected:<{expected}> but was:<{}>", times.count_mismatch("Response", matched), responses_text(&responses))
    } else {
        format!(
            "{}, expected:<{expected}> but was found {matched} time{} among {} recorded responses",
            times.count_mismatch("Response", matched),
            if matched == 1 { "" } else { "s" },
            pairs.len()
        )
    };
    if detailed(state) && !responses.is_empty() {
        message.push_str(&closest_response_diff(&matcher, &responses, max));
    }
    message.push_str(&summary);
    Outcome::Failed(message)
}

/// The response-aware branch of `verify(VerificationSequence)`: the i-th request (when given) and the i-th
/// response must be found together, in order, among the recorded pairs.
fn verify_response_sequence(state: &State, v: &Value, responses: &[Value], correlation: &str, started: i64) -> Outcome {
    let requests = v.get("httpRequests").and_then(Value::as_array).cloned().unwrap_or_default();
    if !requests.is_empty() && requests.len() != responses.len() {
        return Outcome::Failed(format!(
            "Request and response sequences must be the same length for a response-aware verification sequence, found {} request(s) and {} response(s)",
            requests.len(),
            responses.len()
        ));
    }
    let pairs = recorded_pairs(state, None);
    let mut next = 0;
    for (i, response) in responses.iter().enumerate() {
        // SECURITY: carries the server's remote-`$ref` policy into the compile.
        let request = crate::matcher::string::with_remote_refs_policy(state.json_schema_allow_remote_refs(), || {
            requests.get(i).map(|r| RequestMatcher::compile(&canonical::request_definition(r)))
        });
        let matcher = crate::matcher::with_exact_case(state.config.match_exact_case(), || ResponseMatcher::compile(response));
        let found = pairs[next..].iter().position(|x| {
            request.as_ref().is_none_or(|r| r.matches(&x.request, crate::matcher::Mode::ControlPlane)) && matcher.matches(&x.response)
        });
        match found {
            Some(p) => next += p + 1,
            None => {
                if quiet() {
                    return Outcome::Failed(String::new());
                }
                let summary = if detailed(state) {
                    let step = crate::verify_summary::Step { number: i + 1, count: responses.len(), previous: i, searched_from: next };
                    let rankable = requests.get(i).is_none_or(|r| is_http_request(&canonical::request_definition(r)));
                    let request_matcher = request.as_ref().filter(|_| rankable);
                    crate::verify_summary::response_sequence(&step, rankable, request_matcher, Some(&matcher), &pairs, exchange_arrivals(v, &pairs, started))
                } else {
                    String::new()
                };
                let expected: Vec<Value> = responses.iter().map(verification_response).collect();
                let recorded_responses: Vec<Value> = pairs.iter().map(|x| x.response.clone()).collect();
                let entry = recorded::LogEntry::new(Kind::VerificationFailed, "response sequence not found, expected:{}but was:{}").correlation(correlation).without_port().args([
                    recorded::Arg::with_text(Value::Array(expected.clone()), java_list(expected.iter().map(json::pretty))),
                    recorded::Arg::with_text(Value::Array(recorded_responses.clone()), java_list(recorded_responses.iter().map(json::pretty))),
                ]);
                state.log.message(entry);
                let max = max_in_failure(v);
                let expected: Vec<Value> = responses.iter().map(verification_response).collect();
                let expected: Vec<&Value> = expected.iter().collect();
                let recorded: Vec<&Value> = pairs.iter().map(|x| &x.response).collect();
                let mut message = if recorded.len() < max {
                    format!("Response sequence not found, expected:<{}> but was:<{}>", responses_text(&expected), responses_text(&recorded))
                } else {
                    format!("Response sequence not found, expected:<{}> but was not found, found {} other responses", responses_text(&expected), recorded.len())
                };
                if detailed(state) && !recorded.is_empty() {
                    message.push_str(&closest_response_diff(&matcher, &recorded, max));
                }
                message.push_str(&summary);
                return Outcome::Failed(message);
            }
        }
    }
    Outcome::Passed
}
