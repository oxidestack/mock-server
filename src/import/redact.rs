//! `ImportRedaction` over `FixtureRedactor`: sensitive header and query values, and sensitive JSON body fields
//! at any depth, become `***REDACTED***` before imported expectations are stored. A body is read as its
//! `toString()` and, when that is a JSON document (or an SSE stream), written back as a plain string body — so an
//! imported JSON, regex or JSON-path body matcher becomes a string matcher, as it does upstream.

use jackson::JsonNode;
use serde_json::{Map, Value, json};

pub const REDACTED: &str = "***REDACTED***";
const UNPARSEABLE: &str = "<redacted: body could not be parsed for field redaction>";

const SENSITIVE_HEADERS: &[&str] = &["Authorization", "x-api-key", "api-key", "Cookie", "Set-Cookie", "Proxy-Authorization"];
const SENSITIVE_QUERY: &[&str] = &["key", "api_key", "apikey", "access_token", "token", "signature", "x-amz-signature", "x-amz-security-token", "sig"];
const SENSITIVE_BODY_FIELDS: &[&str] = &[
    "api_key", "apiKey", "apikey", "access_token", "accessToken", "refresh_token", "refreshToken", "client_secret", "clientSecret", "password",
    "passwd", "pwd", "secret", "token", "authorization",
];

/// `ImportRedaction.Options`.
#[derive(Clone)]
pub struct Options {
    pub enabled: bool,
    pub additional_headers: Vec<String>,
    pub additional_body_fields: Vec<String>,
}

impl Options {
    pub fn enabled() -> Options {
        Options { enabled: true, additional_headers: Vec::new(), additional_body_fields: Vec::new() }
    }

    pub fn disabled() -> Options {
        Options { enabled: false, ..Options::enabled() }
    }
}

/// A `FixtureRedactor` with case-insensitive name sets.
struct Redactor {
    headers: Vec<String>,
    body_fields: Vec<String>,
}

impl Redactor {
    fn new(options: &Options) -> Redactor {
        let headers = SENSITIVE_HEADERS.iter().map(|s| s.to_string()).chain(options.additional_headers.iter().cloned()).collect();
        let body_fields = SENSITIVE_BODY_FIELDS.iter().map(|s| s.to_string()).chain(options.additional_body_fields.iter().cloned()).collect();
        Redactor { headers, body_fields }
    }

    fn sensitive_header(&self, name: &str) -> bool {
        self.headers.iter().any(|h| h.eq_ignore_ascii_case(name))
    }

    fn sensitive_field(&self, name: &str) -> bool {
        self.body_fields.iter().any(|f| f.eq_ignore_ascii_case(name))
    }

    /// `redactRequest` (only `HttpRequest`s; OpenAPI definitions pass through).
    fn request(&self, request: &Value) -> Value {
        let Some(o) = request.as_object().filter(|o| !o.contains_key("specUrlOrPayload")) else { return request.clone() };
        let mut o = o.clone();
        self.entries(&mut o, "headers", |name| self.sensitive_header(name));
        // `redactCookies`: the parsed cookies too, while `Cookie` is a sensitive header.
        if let Some(c) = o.get_mut("cookies").filter(|_| self.sensitive_header("Cookie")) {
            crate::recorded::redact_cookies_json(c);
        }
        self.entries(&mut o, "queryStringParameters", |name| SENSITIVE_QUERY.iter().any(|q| q.eq_ignore_ascii_case(name)));
        self.body(&mut o);
        Value::Object(o)
    }

    /// `redactResponse`.
    fn response(&self, response: &Value) -> Value {
        let Some(o) = response.as_object() else { return response.clone() };
        let mut o = o.clone();
        self.entries(&mut o, "headers", |name| self.sensitive_header(name));
        if let Some(c) = o.get_mut("cookies").filter(|_| self.sensitive_header("Set-Cookie")) {
            crate::recorded::redact_cookies_json(c);
        }
        self.body(&mut o);
        Value::Object(o)
    }

    /// Rebuilds a multimap, a sensitive entry keeping one placeholder value.
    fn entries(&self, o: &mut Map<String, Value>, key: &str, sensitive: impl Fn(&str) -> bool) {
        let Some(list) = o.get(key).map(entry_list) else { return };
        let mut rebuilt: Vec<(String, Vec<String>)> = Vec::new();
        let mut changed = false;
        for (name, values) in list {
            let plain = name.trim_start_matches('!');
            if sensitive(plain) {
                changed = true;
                super::add(&mut rebuilt, plain, vec![REDACTED.to_string()]);
            } else {
                super::add(&mut rebuilt, &name, values);
            }
        }
        if changed {
            o.insert(key.into(), super::entries_json(&rebuilt));
        }
    }

    /// `redactBodyIfNeeded(bodyText(body, Content-Type), withBody)`.
    fn body(&self, o: &mut Map<String, Value>) {
        let content_type = first_header(o, "Content-Type");
        let Some(text) = o.get("body").and_then(|b| redaction_text(b, content_type.as_deref())) else { return };
        if self.body_fields.is_empty() || text.is_empty() {
            return;
        }
        if let Ok(mut root) = crate::jnode::read_tree(&text) {
            if root.is_object() || root.is_array() {
                self.fields(&mut root);
                o.insert("body".into(), Value::String(root.to_java_string()));
            }
            return;
        }
        if is_sse(&text) {
            o.insert("body".into(), Value::String(self.sse(&text)));
            return;
        }
        if self.mentions_field(&text) {
            o.insert("body".into(), UNPARSEABLE.into());
        }
    }

    fn mentions_field(&self, text: &str) -> bool {
        let lower = text.to_lowercase();
        self.body_fields.iter().any(|f| lower.contains(&f.to_lowercase()))
    }

    fn sse(&self, body: &str) -> String {
        let segments: Vec<String> = body
            .split('\n')
            .map(|segment| {
                let (line, cr) = match segment.strip_suffix('\r') {
                    Some(l) => (l, "\r"),
                    None => (segment, ""),
                };
                let line = match line.strip_prefix("data:") {
                    Some(after) => {
                        let space = if after.starts_with(' ') { " " } else { "" };
                        format!("data:{space}{}", self.sse_payload(&after[space.len()..]))
                    }
                    None => line.to_string(),
                };
                format!("{line}{cr}")
            })
            .collect();
        segments.join("\n")
    }

    fn sse_payload(&self, payload: &str) -> String {
        let trimmed = payload.trim();
        if trimmed.is_empty() {
            return payload.to_string();
        }
        if let Ok(mut node) = crate::jnode::read_tree(trimmed) && (node.is_object() || node.is_array()) {
            self.fields(&mut node);
            return node.to_java_string();
        }
        if self.mentions_field(payload) { UNPARSEABLE.to_string() } else { payload.to_string() }
    }

    /// `redactJsonNode`.
    fn fields(&self, node: &mut JsonNode) {
        match node {
            JsonNode::Object(o) => {
                for (name, child) in std::sync::Arc::make_mut(o).iter_mut() {
                    if self.sensitive_field(name) {
                        *child = JsonNode::text(REDACTED);
                    } else {
                        self.fields(child);
                    }
                }
            }
            JsonNode::Array(items) => std::sync::Arc::make_mut(items).iter_mut().for_each(|c| self.fields(c)),
            _ => {}
        }
    }
}

fn is_sse(body: &str) -> bool {
    body.split('\n').any(|segment| segment.strip_suffix('\r').unwrap_or(segment).starts_with("data:"))
}

/// A multimap in either input form as `(name, values)` entries.
pub fn entry_list(v: &Value) -> Vec<(String, Vec<String>)> {
    let strings = |v: Option<&Value>| -> Vec<String> {
        match v {
            Some(Value::Array(items)) => items.iter().map(value_string).collect(),
            Some(other) => vec![value_string(other)],
            None => Vec::new(),
        }
    };
    match v {
        Value::Array(items) => items
            .iter()
            .filter_map(|item| {
                let name = item.get("name").map(value_string)?;
                Some((name, strings(item.get("values").or_else(|| item.get("value")))))
            })
            .collect(),
        Value::Object(o) => o.iter().filter(|(k, _)| *k != "keyMatchStyle").map(|(k, v)| (k.clone(), strings(Some(v)))).collect(),
        _ => Vec::new(),
    }
}

/// A `NottableString` in input form (`"!x"` or `{"not": true, "value": "x"}`) as its string form.
fn value_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Object(o) => {
            let value = o.get("value").map(text).unwrap_or_default();
            if o.get("not").and_then(Value::as_bool).unwrap_or(false) { format!("!{value}") } else { value }
        }
        other => text(other),
    }
}

/// A scalar of an expectation in input form as its text.
pub fn text(v: &Value) -> String {
    v.as_str().map_or_else(|| v.to_string(), str::to_string)
}

/// `FixtureRedactor.bodyText`: a binary body of no content type, sent with no `Content-Type` header, as lenient
/// UTF-8 (`BinaryBody.matchableString`); any other body as [`body_as_string`].
fn redaction_text(body: &Value, content_type_header: Option<&str>) -> Option<String> {
    if let Value::Object(o) = body && o.get("type").and_then(Value::as_str) == Some("BINARY") && o.get("contentType").is_none() && content_type_header.is_none_or(|c| c.trim().is_empty()) && let Some(bytes) = o.get("base64Bytes").and_then(Value::as_str).and_then(super::base64_decode) {
        return Some(String::from_utf8_lossy(&bytes).into_owned());
    }
    body_as_string(body)
}

/// `getFirstHeader(name)` of a request or response in input form.
pub fn first_header(o: &Map<String, Value>, name: &str) -> Option<String> {
    let headers = o.get("headers").map(entry_list)?;
    headers.into_iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).and_then(|(_, v)| v.into_iter().next())
}

/// `Body.toString()`: the text of string, JSON and XML bodies, base64 of binary ones, else the body's JSON.
pub fn body_as_string(body: &Value) -> Option<String> {
    match body {
        Value::String(s) => Some(s.clone()),
        Value::Object(o) => {
            let kind = o.get("type").and_then(Value::as_str).unwrap_or_default();
            match kind {
                "STRING" => o.get("string").map(text),
                "JSON" => o.get("json").map(text),
                "XML" => o.get("xml").map(text),
                "BINARY" => o.get("base64Bytes").map(text),
                _ => {
                    let mut shown = o.clone();
                    shown.remove("rawBytes");
                    Some(Value::Object(shown).to_string())
                }
            }
        }
        Value::Null => None,
        other => Some(other.to_string()),
    }
}

/// `ImportRedaction.redact` (HAR, Postman, Pact, recorded traffic): `FixtureRedactor.redact` rebuilds each
/// expectation with unlimited times, keeping priority, scenario state and the response (or response list); the
/// importer's id is restored.
pub fn redact(expectations: Vec<Value>, options: &Options) -> Vec<Value> {
    if !options.enabled || expectations.is_empty() {
        return expectations;
    }
    let redactor = Redactor::new(options);
    expectations
        .iter()
        .map(|source| {
            let s = source.as_object().cloned().unwrap_or_default();
            let mut e = Map::new();
            if let Some(id) = s.get("id") {
                e.insert("id".into(), id.clone());
            }
            e.insert("priority".into(), s.get("priority").cloned().unwrap_or_else(|| 0.into()));
            if let Some(r) = s.get("httpRequest") {
                e.insert("httpRequest".into(), redactor.request(r));
            }
            e.insert("times".into(), json!({"unlimited": true}));
            e.insert("timeToLive".into(), json!({"unlimited": true}));
            for key in ["scenarioName", "scenarioState", "newScenarioState"] {
                if let Some(v) = s.get(key) {
                    e.insert(key.into(), v.clone());
                }
            }
            if let Some(r) = s.get("httpSseResponse") {
                e.insert("httpSseResponse".into(), r.clone());
            } else if let Some(r) = s.get("httpResponse") {
                e.insert("httpResponse".into(), redactor.response(r));
            }
            if let Some(Value::Array(list)) = s.get("httpResponses").filter(|l| l.as_array().is_some_and(|l| !l.is_empty())) {
                e.insert("httpResponses".into(), Value::Array(list.iter().map(|r| redactor.response(r)).collect()));
                for key in ["responseMode", "responseWeights", "switchAfter"] {
                    if let Some(v) = s.get(key) {
                        e.insert(key.into(), v.clone());
                    }
                }
            }
            Value::Object(e)
        })
        .collect()
}

/// `ImportRedaction.redactPreservingActions` (Mountebank, Mockoon): request, responses and after-action requests
/// redacted, body matchers kept typed, the action, times, time to live, priority, id, scenario state and response
/// mode kept.
pub fn redact_preserving_actions(expectations: Vec<Value>, options: &Options) -> Vec<Value> {
    redact_preserving_actions_warning(expectations, options, &[], &mut Vec::new())
}

/// `ImportRedaction.redactPreservingActions(expectations, options, locators, warnings)` (WireMock): also a
/// `bodyPatterns` warning, item `locators[i]`, for each request body matcher redaction masked or cannot mask.
pub fn redact_preserving_actions_warning(expectations: Vec<Value>, options: &Options, locators: &[String], warnings: &mut Vec<super::Warning>) -> Vec<Value> {
    if !options.enabled || expectations.is_empty() {
        return expectations;
    }
    let redactor = Redactor::new(options);
    expectations
        .iter()
        .enumerate()
        .map(|(i, source)| {
            let mut e = source.as_object().cloned().unwrap_or_default();
            if let Some(r) = e.get("httpRequest") {
                let redacted = preserve_body_matcher(r, redactor.request(r));
                if let Some(locator) = locators.get(i) && let Some(warning) = body_matcher_warning(r, &redacted, &redactor) {
                    warnings.push(super::Warning::new(locator.clone(), "bodyPatterns", warning));
                }
                e.insert("httpRequest".into(), redacted);
            }
            if let Some(Value::Array(list)) = e.get("httpResponses").cloned() {
                e.insert("httpResponses".into(), Value::Array(list.iter().map(|r| preserve_file_body(r, redactor.response(r))).collect()));
            } else if let Some(r) = e.get("httpResponse").map(|r| preserve_file_body(r, redactor.response(r))) {
                e.insert("httpResponse".into(), r);
            }
            if let Some(Value::Array(actions)) = e.get_mut("afterActions") {
                for action in actions.iter_mut() {
                    if let Some(r) = action.get("httpRequest").map(|r| redactor.request(r)) {
                        action["httpRequest"] = r;
                    }
                }
            }
            Value::Object(e)
        })
        .collect()
}

/// `preserveBodyMatcher`: the redactor writes a JSON-looking body back as a plain string, so a JSON, substring,
/// XML or binary matcher is rebuilt around the redacted value; JsonPath, XPath and regex matchers are kept as
/// written.
fn preserve_body_matcher(source: &Value, mut redacted: Value) -> Value {
    if source.get("specUrlOrPayload").is_some() {
        return redacted;
    }
    let Some(source_body) = source.get("body") else { return redacted };
    let kind = source_body.get("type").and_then(Value::as_str).unwrap_or_default();
    if matches!(kind, "XPATH" | "JSON_PATH" | "REGEX") {
        redacted["body"] = source_body.clone();
        return redacted;
    }
    let Some(Value::String(value)) = redacted.get("body").filter(|b| *b != source_body).cloned() else { return redacted };
    let o = match source_body {
        Value::Object(o) => o,
        _ => return redacted,
    };
    let sub_string = o.get("subString").and_then(Value::as_bool).unwrap_or(false);
    let mut rebuilt = Map::new();
    match kind {
        "JSON" => {
            rebuilt.insert("type".into(), "JSON".into());
            rebuilt.insert("json".into(), value.into());
            for key in ["contentType", "matchType", "matchNumbersAsStrings"] {
                if let Some(v) = o.get(key) {
                    rebuilt.insert(key.into(), v.clone());
                }
            }
        }
        "STRING" if sub_string => {
            rebuilt.insert("type".into(), "STRING".into());
            rebuilt.insert("string".into(), value.into());
            rebuilt.insert("subString".into(), true.into());
        }
        "XML" => {
            rebuilt.insert("type".into(), "XML".into());
            rebuilt.insert("xml".into(), value.into());
        }
        "BINARY" => {
            use base64::Engine;
            rebuilt.insert("type".into(), "BINARY".into());
            rebuilt.insert("base64Bytes".into(), base64::engine::general_purpose::STANDARD.encode(value.as_bytes()).into());
        }
        _ => return redacted,
    }
    if !matches!(kind, "JSON") && let Some(v) = o.get("contentType") {
        rebuilt.insert("contentType".into(), v.clone());
    }
    for key in ["optional", "not"] {
        if let Some(v) = o.get(key) {
            rebuilt.insert(key.into(), v.clone());
        }
    }
    redacted["body"] = Value::Object(rebuilt);
    redacted
}

/// `preserveFileBody`: a file body names a file on the MockServer host, so it is kept.
fn preserve_file_body(source: &Value, mut redacted: Value) -> Value {
    if let Some(body) = source.get("body").filter(|b| b.get("type").and_then(Value::as_str) == Some("FILE")) {
        redacted["body"] = body.clone();
    }
    redacted
}

/// `bodyMatcherWarning`.
fn body_matcher_warning(source: &Value, redacted: &Value, redactor: &Redactor) -> Option<String> {
    if source.get("specUrlOrPayload").is_some() {
        return None;
    }
    let text = redacted.get("body").and_then(body_value_text);
    if text.as_deref().is_some_and(|t| t.contains(REDACTED) || t.contains(UNPARSEABLE)) {
        return Some(
            "secret values in the body matcher were replaced by the redaction placeholder, so it now matches only a request carrying the placeholder; import with redactSensitiveData=false, or adjust additionalRedactedBodyFields, to keep them"
                .into(),
        );
    }
    let kind = source.get("body").map(|b| match b {
        Value::String(_) => "STRING",
        other => other.get("type").and_then(Value::as_str).unwrap_or_default(),
    });
    if !matches!(kind, Some("XPATH" | "JSON_PATH" | "REGEX" | "STRING")) {
        return None;
    }
    let field = sensitive_field_in(text.as_deref()?, &redactor.body_fields)?;
    Some(format!(
        "the body matcher mentions the sensitive field '{field}' but is kept as written, because redaction cannot mask a value inside an expression or fragment without breaking it; check it does not hold a real secret"
    ))
}

/// `String.valueOf(body.getValue())` (a binary body's bytes as UTF-8).
fn body_value_text(body: &Value) -> Option<String> {
    match body {
        Value::String(s) => Some(s.clone()),
        Value::Object(o) => {
            let key = match o.get("type").and_then(Value::as_str).unwrap_or_default() {
                "STRING" => "string",
                "JSON" => "json",
                "XML" => "xml",
                "REGEX" => "regex",
                "JSON_PATH" => "jsonPath",
                "XPATH" => "xpath",
                "JSON_SCHEMA" => "jsonSchema",
                "XML_SCHEMA" => "xmlSchema",
                "PARAMETERS" => "parameters",
                "FILE" => "filePath",
                "BINARY" => {
                    let bytes = o.get("base64Bytes").and_then(Value::as_str).and_then(super::base64_decode)?;
                    return Some(String::from_utf8_lossy(&bytes).into_owned());
                }
                _ => return None,
            };
            o.get(key).map(text)
        }
        _ => None,
    }
}

/// `sensitiveFieldIn`: the first sensitive field name, in `TreeSet` order, the text mentions (case-insensitive).
fn sensitive_field_in(text: &str, fields: &[String]) -> Option<String> {
    let lower = text.to_lowercase();
    let mut sorted: Vec<&String> = fields.iter().collect();
    sorted.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
    sorted.dedup();
    sorted.into_iter().find(|f| lower.contains(&f.to_lowercase())).cloned()
}

/// `ImportRedaction.mentionsSensitiveBodyField`: redaction is on and the text mentions a sensitive body field.
pub fn mentions_sensitive_body_field(text: &str, options: &Options) -> bool {
    options.enabled && sensitive_field_in(text, &Redactor::new(options).body_fields).is_some()
}

/// `ImportRedaction.redactResponse`: a response about to become template text, which later redaction cannot reach.
pub fn redact_response(response: &Value, options: &Options) -> Value {
    if !options.enabled {
        return response.clone();
    }
    Redactor::new(options).response(response)
}
/// `ImportRedaction.redactRecordedTraffic`: each request and response of a re-imported pair.
pub fn redact_pair(request: &Value, response: Option<&Value>, options: &Options) -> (Value, Option<Value>) {
    if !options.enabled {
        return (request.clone(), response.cloned());
    }
    let redactor = Redactor::new(options);
    (redactor.request(request), response.map(|r| redactor.response(r)))
}
