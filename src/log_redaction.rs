//! `redactSecretsInLog` on everything a log entry renders, not only its top-level `httpRequest`/`httpResponse`
//! (upstream fixes cc7d7d185 and c76143e4a, adopted after 8.0.0; `docs/divergences.md`).
//!
//! Upstream's `LogEntry` redacts, at render time and under the settings in force then: its arguments (requests,
//! responses, expectations and request/response pairs field by field, as `FixtureRedactor` masks them; free text
//! scrubbed), its message (re-formatted from the scrubbed format and the redacted arguments), its compact message,
//! `because` and throwable. Free text is scrubbed of the credential values the entry's own requests and responses
//! carry (`FixtureRedactor.sensitiveValues`), every stretch an occurrence covers replaced by the placeholder,
//! overlapping occurrences merged into one (`SensitiveValueMatcher.scrub`), in one pass of an Aho-Corasick automaton
//! once a text is long enough to pay for building it.

use serde_json::Value;

use crate::recorded::{LOG_REDACTED, LOG_REDACT_HEADERS, LOG_REDACT_QUERY};

/// `FixtureRedactor.MIN_SCRUBBED_VALUE_LENGTH`.
const MIN_SCRUBBED_VALUE_LENGTH: usize = 4;
/// `FixtureRedactor.MIN_SCRUBBED_COOKIE_VALUE_LENGTH`.
const MIN_SCRUBBED_COOKIE_VALUE_LENGTH: usize = 8;
/// `SensitiveValueMatcher.MAX_VALUE_LENGTH`.
const MAX_VALUE_LENGTH: usize = 4 * 1024;
/// `SensitiveValueMatcher.MAX_VALUES`.
const MAX_VALUES: usize = 10_000;
/// `SensitiveValueMatcher.MAX_TOTAL_LENGTH`.
const MAX_TOTAL_LENGTH: usize = 256 * 1024;
/// `SensitiveValueMatcher.TRUNCATION_WARNED`: the WARN about dropped values is logged once per process.
static TRUNCATION_WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// `LogEntry.Redaction.MAX_ARGUMENT_DEPTH`.
const MAX_ARGUMENT_DEPTH: usize = 4;

/// What a JSON log argument is upstream, told apart by its fields.
enum Shape {
    Request,
    Response,
    /// An `Expectation`, a `LogEventRequestAndResponse` or an `HttpRequestAndHttpResponse`: its `httpRequest` and
    /// `httpResponse` are redacted, the rest left as it is.
    Pair,
    Other,
}

fn shape(v: &Value) -> Shape {
    let Value::Object(o) = v else { return Shape::Other };
    if o.get("httpRequest").is_some_and(Value::is_object) || o.get("httpResponse").is_some_and(Value::is_object) {
        return Shape::Pair;
    }
    if o.contains_key("statusCode") || o.contains_key("reasonPhrase") {
        return Shape::Response;
    }
    if o.contains_key("method") || o.contains_key("path") {
        return Shape::Request;
    }
    if !o.is_empty() && o.keys().all(|k| crate::log_entry::MESSAGE_FIELDS.contains(&k.as_str())) {
        return Shape::Request;
    }
    Shape::Other
}

/// One render's redaction: the configured body fields and the entry's credential values (`LogEntry.Redaction`).
pub struct Redaction {
    fields: Vec<String>,
    values: SensitiveValues,
}

/// `SensitiveValueMatcher`: masks every occurrence of a set of credential values in free text.
///
/// Short texts are checked value by value; a text for which that would cost more than the values' total length (what
/// building the automaton costs) goes through an Aho-Corasick automaton, built once and kept, which finds every
/// occurrence, overlapping ones included, in one pass. Both give the same result.
pub struct SensitiveValues {
    /// Longest first, each at most [`MAX_VALUE_LENGTH`], bounded by [`MAX_VALUES`] and [`MAX_TOTAL_LENGTH`].
    values: Vec<String>,
    total_length: usize,
    automaton: std::sync::OnceLock<Option<aho_corasick::AhoCorasick>>,
}

impl SensitiveValues {
    /// `SensitiveValueMatcher.of`: `values` most important first; empty, duplicate or over-long ones are ignored and
    /// those past [`MAX_VALUES`] or [`MAX_TOTAL_LENGTH`] dropped.
    /// The first time any render drops values, one WARN goes to the console (`TRUNCATION_WARNED`).
    pub fn of(values: Vec<String>) -> SensitiveValues {
        let (values, dropped) = bounded(values);
        if dropped && TRUNCATION_WARNED.compare_exchange(false, true, std::sync::atomic::Ordering::SeqCst, std::sync::atomic::Ordering::SeqCst).is_ok() {
            crate::log::java_logger_warn(&format!(
                "redactSecretsInLog: a log entry carries more credential values than are searched for in its free text (at most {MAX_VALUES} values and {MAX_TOTAL_LENGTH} characters); the values beyond that are still masked in the headers, cookies, query parameters and body fields they came from, but not where the entry's message text quotes them"
            ));
        }
        let total_length = values.iter().map(String::len).sum();
        SensitiveValues { values, total_length, automaton: std::sync::OnceLock::new() }
    }

    /// `SensitiveValueMatcher.TRUNCATION_WARNED`: whether a render of this process has dropped values (and warned).
    pub fn truncation_warned() -> bool {
        TRUNCATION_WARNED.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// `SensitiveValueMatcher.valueCount`.
    pub fn value_count(&self) -> usize {
        self.values.len()
    }

    /// `SensitiveValueMatcher.totalLength`: the values' length summed, in UTF-16 units as Java counts them.
    pub fn total_length(&self) -> usize {
        self.values.iter().map(|v| v.encode_utf16().count()).sum()
    }

    fn automaton(&self, text: &str) -> Option<&aho_corasick::AhoCorasick> {
        if let Some(built) = self.automaton.get() {
            return built.as_ref();
        }
        if self.values.len().saturating_mul(text.len()) <= self.total_length {
            return None;
        }
        // a build that fails (none should, for at most 256K characters) leaves the value-by-value path
        self.automaton.get_or_init(|| aho_corasick::AhoCorasick::new(&self.values).ok()).as_ref()
    }

    /// Whether `text` contains any of the values.
    pub fn contains_any(&self, text: &str) -> bool {
        if self.values.is_empty() || text.is_empty() {
            return false;
        }
        match self.automaton(text) {
            Some(automaton) => automaton.is_match(text),
            None => self.values.iter().any(|v| text.contains(v.as_str())),
        }
    }

    /// `text` with every stretch an occurrence of a value covers replaced by the placeholder, overlapping occurrences
    /// merged.
    pub fn scrub(&self, text: &str) -> String {
        if self.values.is_empty() || text.is_empty() {
            return text.to_string();
        }
        let spans: Vec<(usize, usize)> = match self.automaton(text) {
            // every value is valid UTF-8, so each occurrence starts and ends on a character boundary
            Some(automaton) => automaton.find_overlapping_iter(text).map(|m| (m.start(), m.end())).collect(),
            None => occurrences(text, &self.values),
        };
        mask(text, spans)
    }
}

impl std::fmt::Debug for Redaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Redaction")
    }
}

impl Redaction {
    /// The redaction of an entry whose requests, responses and arguments are these (`collectFromArguments`):
    /// requests and responses nested in arguments count as if attached.
    pub fn new(fields: &[String], requests: &[&Value], responses: &[&Value], arguments: &[&Value]) -> Redaction {
        Redaction::with_texts(fields, requests, responses, arguments, &[])
    }

    /// [`Redaction::new`] also scrubbing `texts`, the entry's sensitive arguments (`SensitiveLogValue`), after the
    /// credentials of its requests and responses.
    pub fn with_texts(fields: &[String], requests: &[&Value], responses: &[&Value], arguments: &[&Value], texts: &[&str]) -> Redaction {
        let mut requests: Vec<&Value> = requests.to_vec();
        let mut responses: Vec<&Value> = responses.to_vec();
        for argument in arguments {
            collect(argument, &mut requests, &mut responses, 0);
        }
        let mut values = sensitive_values(&requests, &responses, fields, &log_header, &log_query);
        for text in texts {
            if text.encode_utf16().count() >= MIN_SCRUBBED_VALUE_LENGTH {
                push(&mut values, text.to_string());
            }
        }
        Redaction { fields: fields.to_vec(), values: SensitiveValues::of(values) }
    }

    /// The redaction of text quoting `requests` with a redactor's own header and query sets
    /// (`FixtureRedactor(headers, fields, queryParams).sensitiveValues(requests, [])`), e.g. `LlmPromptRedactor`'s.
    pub fn with_sets(fields: &[String], requests: &[&Value], header: &dyn Fn(&str) -> bool, query: &dyn Fn(&str) -> bool) -> Redaction {
        let values = sensitive_values(requests, &[], fields, header, query);
        Redaction { fields: fields.to_vec(), values: SensitiveValues::of(values) }
    }

    /// `SensitiveValueMatcher.scrub`.
    pub fn scrub(&self, text: &str) -> String {
        self.values.scrub(text)
    }

    /// Whether `text` quotes any of the values.
    pub fn quotes_any(&self, text: &str) -> bool {
        self.values.contains_any(text)
    }

    /// `LogEntry.redactArgument`.
    pub fn argument(&self, v: &Value) -> Value {
        // `EventLogRedactor.redactRequestDefinition`: a binary message's bytes, alone or in a list, are masked whole
        if let Some(masked) = crate::recorded::masked_binary_definition(v) {
            return masked;
        }
        if let Value::Array(items) = v
            && items.iter().any(|i| crate::recorded::masked_binary_definition(i).is_some())
        {
            return Value::Array(items.iter().map(|i| crate::recorded::masked_binary_definition(i).unwrap_or_else(|| self.argument_at(i, 1))).collect());
        }
        self.argument_at(v, 0)
    }

    fn argument_at(&self, v: &Value, depth: usize) -> Value {
        if depth > MAX_ARGUMENT_DEPTH {
            return Value::String(LOG_REDACTED.to_string());
        }
        match v {
            Value::String(s) => Value::String(self.scrub(s)),
            Value::Array(items) => Value::Array(items.iter().map(|i| self.argument_at(i, depth + 1)).collect()),
            Value::Object(o) => match shape(v) {
                Shape::Request => self.request(v),
                Shape::Response => self.response(v),
                Shape::Pair => {
                    let mut out = o.clone();
                    if let Some(r) = o.get("httpRequest").filter(|r| r.is_object()) {
                        // `redactRequestDefinition`: an expectation's binary definition is masked whole
                        out.insert("httpRequest".into(), crate::recorded::masked_binary_definition(r).unwrap_or_else(|| self.request(r)));
                    }
                    if let Some(r) = o.get("httpResponse").filter(|r| r.is_object()) {
                        out.insert("httpResponse".into(), self.response(r));
                    }
                    Value::Object(out)
                }
                Shape::Other => {
                    // a map: keys scrubbed (keys that scrub alike kept apart), values redacted in turn
                    let mut out = serde_json::Map::new();
                    for (k, value) in o {
                        let mut key = self.scrub(k);
                        if out.contains_key(&key) {
                            let mut suffix = 1;
                            loop {
                                suffix += 1;
                                let distinct = format!("{key} ({suffix})");
                                if !out.contains_key(&distinct) {
                                    key = distinct;
                                    break;
                                }
                            }
                        }
                        out.insert(key, self.argument_at(value, depth + 1));
                    }
                    Value::Object(out)
                }
            },
            other => other.clone(),
        }
    }

    /// `FixtureRedactor.redactRequestDefinition` on a request's JSON.
    pub fn request(&self, v: &Value) -> Value {
        redact_message(v, &self.fields, true)
    }

    /// `FixtureRedactor.redactResponseObject` on a response's JSON.
    pub fn response(&self, v: &Value) -> Value {
        redact_message(v, &self.fields, false)
    }
}

/// A request's or response's JSON with its sensitive headers, cookies, (a request's) query-string values and configured
/// body fields masked.
pub fn redact_message(v: &Value, fields: &[String], request: bool) -> Value {
    crate::recorded::redact_value(v, fields, request)
}

fn collect<'a>(v: &'a Value, requests: &mut Vec<&'a Value>, responses: &mut Vec<&'a Value>, depth: usize) {
    if depth > MAX_ARGUMENT_DEPTH {
        return;
    }
    match v {
        Value::Array(items) => items.iter().for_each(|i| collect(i, requests, responses, depth + 1)),
        Value::Object(o) => match shape(v) {
            Shape::Request => requests.push(v),
            Shape::Response => responses.push(v),
            Shape::Pair => {
                if let Some(r) = o.get("httpRequest").filter(|r| r.is_object()) {
                    requests.push(r);
                }
                if let Some(r) = o.get("httpResponse").filter(|r| r.is_object()) {
                    responses.push(r);
                }
            }
            Shape::Other => o.values().for_each(|i| collect(i, requests, responses, depth + 1)),
        },
        _ => {}
    }
}

/// The text of a header, query-string or cookie value: a plain string, or a nottable one's `value`.
fn text_of(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Object(o) => o.get("value").and_then(Value::as_str).map(str::to_string),
        _ => None,
    }
}

/// `(name, values)` of a multi-map in either JSON form: `{"Name": [v, …]}` or `[{"name": …, "values": […]}]`.
fn entries(map: &Value) -> Vec<(String, Vec<String>)> {
    let values = |v: &Value| match v {
        Value::Array(items) => items.iter().filter_map(text_of).collect(),
        other => text_of(other).into_iter().collect(),
    };
    match map {
        Value::Object(o) => o.iter().map(|(k, v)| (k.clone(), values(v))).collect(),
        Value::Array(items) => items
            .iter()
            .filter_map(|i| Some((text_of(i.get("name")?)?, i.get("values").map(values).unwrap_or_default())))
            .collect(),
        _ => Vec::new(),
    }
}

fn push(set: &mut Vec<String>, value: String) {
    if !set.contains(&value) {
        set.push(value);
    }
}

fn after_equals(cookie_values: &mut Vec<String>, pair: &str) {
    if let Some((_, value)) = pair.split_once('=') {
        push(cookie_values, value.trim().to_string());
    }
}

fn log_header(name: &str) -> bool {
    LOG_REDACT_HEADERS.iter().any(|h| h.eq_ignore_ascii_case(name))
}

fn log_query(name: &str) -> bool {
    LOG_REDACT_QUERY.iter().any(|q| q.eq_ignore_ascii_case(name))
}

fn header_values(message: &Value, sensitive: &dyn Fn(&str) -> bool, values: &mut Vec<String>, cookie_values: &mut Vec<String>) {
    let Some(headers) = message.get("headers") else { return };
    for (name, list) in entries(headers) {
        if !sensitive(&name) {
            continue;
        }
        for value in list {
            push(values, value.clone());
            if name.eq_ignore_ascii_case("Cookie") {
                for pair in value.split(';') {
                    push(values, pair.trim().to_string());
                    after_equals(cookie_values, pair);
                }
            } else if name.eq_ignore_ascii_case("Set-Cookie") {
                let pair = value.split(';').next().unwrap_or_default();
                push(values, pair.trim().to_string());
                after_equals(cookie_values, pair);
            } else if let Some(space) = value.trim().find(' ').filter(|&s| s > 0) {
                // "Bearer <token>", "Basic <credentials>": the credential alone can be quoted too
                push(values, value.trim()[space + 1..].trim().to_string());
            }
        }
    }
}

fn cookie_values_of(message: &Value, cookie_values: &mut Vec<String>) {
    match message.get("cookies") {
        Some(Value::Object(o)) => o.values().filter_map(text_of).for_each(|v| push(cookie_values, v)),
        Some(Value::Array(items)) => items.iter().filter_map(|i| i.get("value").and_then(text_of)).for_each(|v| push(cookie_values, v)),
        _ => {}
    }
}

/// `FixtureRedactor.addBodyFieldValues`.
fn body_field_values(message: &Value, fields: &[String], body_values: &mut Vec<String>) {
    if fields.is_empty() {
        return;
    }
    let Some(text) = message.get("body").and_then(crate::recorded::response_body_text) else { return };
    if text.is_empty() || !crate::recorded::mentions_field(&text, fields) {
        return;
    }
    let documents: Vec<String> = if crate::recorded::is_sse_body(&text) {
        text.split('\n').map(str::trim).filter_map(|l| l.strip_prefix("data:")).map(|d| d.trim().to_string()).collect()
    } else {
        vec![text]
    };
    for document in documents {
        if let Ok(node) = serde_json::from_str::<Value>(&document) {
            collect_field_values(&node, false, fields, body_values);
        }
    }
}

fn collect_field_values(node: &Value, inside: bool, fields: &[String], out: &mut Vec<String>) {
    match node {
        Value::Object(o) => {
            for (k, v) in o {
                let sensitive = inside || fields.iter().any(|f| f.eq_ignore_ascii_case(k));
                if sensitive && !inside && (v.is_object() || v.is_array()) {
                    // the whole sensitive object or array as compact text, once
                    if let Ok(text) = serde_json::to_string(v) && text.chars().count() <= MAX_VALUE_LENGTH {
                        push(out, text);
                    }
                }
                collect_field_values(v, sensitive, fields, out);
            }
        }
        Value::Array(items) => items.iter().for_each(|i| collect_field_values(i, inside, fields, out)),
        Value::Null => {}
        Value::String(s) if inside => push(out, s.clone()),
        other if inside => push(out, other.to_string()),
        _ => {}
    }
}

/// `FixtureRedactor.sensitiveValues(requests, responses)`.
fn sensitive_values(requests: &[&Value], responses: &[&Value], fields: &[String], header: &dyn Fn(&str) -> bool, query: &dyn Fn(&str) -> bool) -> Vec<String> {
    let (mut values, mut cookie_values, mut body_values) = (Vec::new(), Vec::new(), Vec::new());
    for request in requests {
        header_values(request, header, &mut values, &mut cookie_values);
        cookie_values_of(request, &mut cookie_values);
        if let Some(parameters) = request.get("queryStringParameters") {
            for (name, list) in entries(parameters) {
                if query(&name) {
                    list.into_iter().for_each(|v| push(&mut values, v));
                }
            }
        }
        body_field_values(request, fields, &mut body_values);
    }
    for response in responses {
        header_values(response, header, &mut values, &mut cookie_values);
        cookie_values_of(response, &mut cookie_values);
        body_field_values(response, fields, &mut body_values);
    }
    let len = |v: &String| v.encode_utf16().count();
    values.retain(|v| len(v) >= MIN_SCRUBBED_VALUE_LENGTH);
    cookie_values.retain(|v| len(v) >= MIN_SCRUBBED_COOKIE_VALUE_LENGTH);
    body_values.retain(|v| len(v) >= MIN_SCRUBBED_VALUE_LENGTH);
    for v in cookie_values.into_iter().chain(body_values) {
        push(&mut values, v);
    }
    let mut ordered = Vec::with_capacity(values.len());
    for value in values {
        let common = ["true", "false", "null"].iter().any(|w| w.eq_ignore_ascii_case(&value));
        if len(&value) > MAX_VALUE_LENGTH || value == LOG_REDACTED || common {
            continue;
        }
        // a value quoted inside JSON text (e.g. a serialized header map) appears in its escaped form
        let escaped = json_escaped(&value);
        let differs = escaped != value;
        ordered.push(value);
        if differs {
            ordered.push(escaped);
        }
    }
    ordered
}

/// `JsonStringEncoder.quoteAsString`.
fn json_escaped(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04X}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// `SensitiveValueMatcher.of`: values deduplicated, empty or over-long ones dropped, at most [`MAX_VALUES`] and
/// [`MAX_TOTAL_LENGTH`] characters kept in the order given, then longest first; and whether any was dropped past
/// those two bounds.
fn bounded(values: Vec<String>) -> (Vec<String>, bool) {
    let mut kept: Vec<String> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut total = 0;
    let mut dropped = false;
    for value in values {
        let len = value.encode_utf16().count();
        if value.is_empty() || len > MAX_VALUE_LENGTH || seen.contains(&value) {
            continue;
        }
        if kept.len() == MAX_VALUES || total + len > MAX_TOTAL_LENGTH {
            dropped = true;
            continue;
        }
        total += len;
        seen.insert(value.clone());
        kept.push(value);
    }
    kept.sort_by_key(|v| std::cmp::Reverse(v.encode_utf16().count()));
    (kept, dropped)
}

/// Every occurrence of every value in `text`, overlapping ones included, value by value.
fn occurrences(text: &str, values: &[String]) -> Vec<(usize, usize)> {
    let mut spans: Vec<(usize, usize)> = Vec::new();
    for value in values {
        let mut from = 0;
        while let Some(at) = text[from..].find(value.as_str()) {
            let start = from + at;
            spans.push((start, start + value.len()));
            // the next occurrence may overlap this one
            from = start + text[start..].chars().next().map_or(1, char::len_utf8);
            if from >= text.len() {
                break;
            }
        }
    }
    spans
}

/// `text` with every stretch the spans cover replaced by the placeholder, overlapping spans merged.
fn mask(text: &str, mut spans: Vec<(usize, usize)>) -> String {
    if spans.is_empty() {
        return text.to_string();
    }
    spans.sort_unstable();
    let mut out = String::with_capacity(text.len());
    let mut at = 0;
    let mut i = 0;
    while i < spans.len() {
        let (start, mut end) = spans[i];
        i += 1;
        while i < spans.len() && spans[i].0 < end {
            end = end.max(spans[i].1);
            i += 1;
        }
        out.push_str(&text[at..start]);
        out.push_str(LOG_REDACTED);
        at = end;
    }
    out.push_str(&text[at..]);
    out
}
