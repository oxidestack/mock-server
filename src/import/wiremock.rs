//! `WireMockImporter`: stub mappings (one stub, a `mappings` wrapper or an array) become expectations; what has
//! no MockServer equivalent is reported as a warning.

use std::path::{Component, Path, PathBuf};
use std::sync::LazyLock;

use jackson::JsonNode;
use serde_json::{Map, Value, json};

use super::wiremock_template::{self as template, PathContext};
use super::{Affix, Ctx, Imported, Options, Req, affix_regex, expectation, parse, path_and_query, set, url_parts};
use super::{TextOrNull, field_names};
use crate::java_text::quote;

/// WireMock's lognormal is parameterised by sigma, MockServer's by its 99th percentile.
const Z_SCORE_P99: f64 = 2.326347874;
/// The bytes WireMock writes for `MALFORMED_RESPONSE_CHUNK` and `RANDOM_DATA_THEN_CLOSE`.
const WIREMOCK_GARBAGE: &[u8] = b"lskdu018973t09sylgasjkfg1][]'./.sdlv";
static PATH_TEMPLATE_NAME: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"\{([^/{}]+)\}").unwrap());
static URL_PARTS: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"(?is)^(https?)://([^/?#]+)([^?#]*)(?:\?([^#]*))?.*$").unwrap());

pub fn import(document: &str, options: &Options, files_directory: Option<&str>) -> Result<Imported, String> {
    let files_root = files_directory.filter(|d| !d.trim().is_empty()).map(|d| normalize(&std::path::absolute(d).unwrap_or_else(|_| PathBuf::from(d))));
    if document.trim().is_empty() {
        return Err("WireMock stub JSON body is required".into());
    }
    let root = parse(document).map_err(|e| format!("failed to parse WireMock stub JSON: {e}"))?;
    let stubs: Vec<JsonNode> = match &root {
        JsonNode::Array(items) => items.to_vec(),
        JsonNode::Object(_) if root.path("mappings").is_array() => root.path("mappings").as_array().cloned().unwrap_or_default(),
        JsonNode::Object(o) if o.contains_key("request") || o.contains_key("response") => vec![root.clone()],
        _ => {
            return Err("not a valid WireMock stub document — expected a stub object with 'request'/'response', a 'mappings' array, or a JSON array of stubs".into());
        }
    };
    let mut expectations = Vec::new();
    let mut locators = Vec::new();
    let mut warnings = Vec::new();
    for (index, stub) in stubs.iter().enumerate() {
        let locator = format!("stub[{index}]");
        if let Some(e) = build(stub, index, files_root.as_deref(), options, &mut Ctx::new(locator.clone(), &mut warnings)) {
            expectations.push(e);
            locators.push(locator);
        }
    }
    let expectations = super::redact::redact_preserving_actions_warning(expectations, options, &locators, &mut warnings);
    Ok(Imported { expectations, warnings: Some(warnings) })
}

fn build(stub: &JsonNode, index: usize, files_root: Option<&Path>, options: &Options, ctx: &mut Ctx) -> Option<Value> {
    let request = stub.get("request");
    let response = stub.get("response");
    if request.is_none() && response.is_none() {
        ctx.warn("stub", "skipped — neither 'request' nor 'response' present");
        return None;
    }
    let req = build_request(request, options, ctx);
    let mut e = expectation(Some(&format!("wiremock-{index}{}", id_suffix(stub))), &req);
    if let Some(name) = stub.value_text("scenarioName") {
        e.insert("scenarioName".into(), name.into());
        super::set_scenario(&mut e, "scenarioState", stub.value_text("requiredScenarioState"));
        super::set_scenario(&mut e, "newScenarioState", stub.value_text("newScenarioState"));
    }
    // WireMock 1 is the highest priority and 5 its default; MockServer matches higher first, default 0.
    if let JsonNode::Int(p) = stub.path("priority") {
        e.insert("priority".into(), (5 - p as i64).into());
    }
    if stub.get("metadata").is_some() {
        ctx.warn("metadata", "stub metadata is not mapped; MockServer expectations carry no metadata");
    }
    if stub.path("persistent").as_boolean_or(false) {
        ctx.warn("persistent", "the per-stub persistent flag is not mapped; enable the persistExpectations configuration property to persist all expectations");
    }
    let request = request.cloned().unwrap_or(JsonNode::Missing);
    apply_response(&mut e, response, &path_context(&request), files_root, options, ctx);
    apply_webhooks(&mut e, stub, ctx);
    Some(Value::Object(e))
}

fn path_context(request: &JsonNode) -> PathContext {
    let mut exact_path = request.value_text("urlPath");
    let url = request.value_text("url");
    let other = ["urlPathTemplate", "urlPathPattern", "urlPattern"].iter().any(|k| request.get(k).is_some());
    if exact_path.is_none() && !other {
        exact_path = url.map(|u| u.split('?').next().unwrap_or_default().to_string());
    }
    PathContext { exact_path, path_template: request.value_text("urlPathTemplate").is_some() }
}

fn build_request(request: Option<&JsonNode>, options: &Options, ctx: &mut Ctx) -> Req {
    let mut req = Req::default();
    let Some(request) = request else { return req };
    if let Some(method) = request.value_text("method").filter(|m| !m.eq_ignore_ascii_case("ANY")) {
        req.method = Some(method.to_uppercase());
    }
    let mut query = Vec::new();
    if let Some(p) = request.value_text("urlPath") {
        req.path = Some(p);
    } else if let Some(template) = request.value_text("urlPathTemplate") {
        // MockServer path templates use the same {name} syntax, but only a declared name matches a segment, so a
        // name WireMock leaves unconstrained is declared as any one segment.
        req.path = Some(template.clone());
        let mut declared: Vec<String> = Vec::new();
        for (name, predicate) in request.path("pathParameters").as_object().into_iter().flatten() {
            if let Some(value) = match_predicate(predicate, &format!("pathParameters.{name}"), ctx) {
                req.path_params.push((name.clone(), vec![value]));
                declared.push(name.clone());
            }
        }
        for c in PATH_TEMPLATE_NAME.captures_iter(&template) {
            if !declared.iter().any(|d| d == &c[1]) {
                declared.push(c[1].to_string());
                super::add(&mut req.path_params, &c[1], vec!["[^/]+".into()]);
            }
        }
    } else if let Some(p) = request.value_text("urlPathPattern") {
        req.path = Some(p);
    } else if let Some(pattern) = request.value_text("urlPattern") {
        match pattern.find("\\?").or_else(|| pattern.find('?')) {
            Some(q) => {
                ctx.warn("request.urlPattern", "regex covered the query string; MockServer matches the path regex only — query portion dropped");
                req.path = Some(pattern[..q].to_string());
            }
            None => req.path = Some(pattern),
        }
    } else if let Some(url) = request.value_text("url") {
        let (path, url_query) = path_and_query(&url);
        req.path = Some(path);
        query = url_query;
    }
    for (name, predicate) in request.path("queryParameters").as_object().into_iter().flatten() {
        if let Some(value) = match_predicate(predicate, &format!("queryParameters.{name}"), ctx) {
            query.push((name.clone(), vec![value]));
        }
    }
    if !query.is_empty() {
        set(&mut req.query, query);
    }
    let mut headers = Vec::new();
    for (name, predicate) in request.path("headers").as_object().into_iter().flatten() {
        if let Some(value) = match_predicate(predicate, &format!("headers.{name}"), ctx) {
            headers.push((name.clone(), vec![value]));
        }
    }
    if !headers.is_empty() {
        set(&mut req.headers, headers);
    }
    if request.path("cookies").as_object().is_some_and(|c| !c.is_empty()) {
        ctx.warn("request.cookies", "cookie predicates are not mapped; add explicit cookie matchers if needed");
    }
    if let Some(patterns) = request.path("bodyPatterns").as_array().filter(|a| !a.is_empty()) {
        apply_body_patterns(&mut req, patterns, options, ctx);
    }
    if request.get("basicAuthCredentials").is_some() {
        ctx.warn("request.basicAuthCredentials", "basic-auth credential matching is not mapped; add an Authorization header matcher if needed");
    }
    if request.get("multipartPatterns").is_some() {
        ctx.warn("request.multipartPatterns", "multipart body-part matching is not mapped");
    }
    req
}

/// A header, query or path-parameter predicate as a matcher value (`"!x"` for `doesNotMatch`); `None` omits the key.
fn match_predicate(predicate: &JsonNode, field: &str, ctx: &mut Ctx) -> Option<String> {
    if !predicate.is_object() {
        return Some(predicate.as_text());
    }
    if let Some(v) = predicate.get("equalTo") {
        let value = v.as_text();
        return Some(if predicate.path("caseInsensitive").as_boolean_or(false) { format!("(?i){}", quote(&value)) } else { value });
    }
    if let Some(v) = predicate.get("matches") {
        return Some(v.as_text());
    }
    if let Some(v) = predicate.get("contains") {
        return Some(affix_regex(Affix::Contains, "", &v.as_text()));
    }
    if let Some(v) = predicate.get("doesNotMatch") {
        return Some(format!("!{}", v.as_text()));
    }
    if let Some(operator) = date_time_operator(predicate) {
        let date_time = date_time_predicate(operator, predicate, field, ctx)?;
        return Some(format!("{}{}", super::DATE_TIME_VALUE, crate::json::compact(&date_time)));
    }
    if predicate.path("absent").as_boolean_or(false) {
        ctx.warn(field, "'absent' predicate has no direct MockServer analogue on a named key — omitted (a request lacking the key already matches)");
        return None;
    }
    ctx.warn(field, format!("unsupported match predicate {} — omitted", field_names(predicate)));
    None
}

const DATE_TIME_PREDICATES: [&str; 3] = ["before", "after", "equalToDateTime"];

fn date_time_operator(predicate: &JsonNode) -> Option<&'static str> {
    DATE_TIME_PREDICATES.into_iter().find(|op| predicate.get(op).is_some())
}

/// `dateTimePredicate`: WireMock's `before` / `after` / `equalToDateTime` as a date-time matcher value (input
/// form); `expectedOffset` with `expectedOffsetUnit` folds into a `now` offset. `None`, with a warning, when the
/// matcher does not compile.
fn date_time_predicate(operator: &'static str, predicate: &JsonNode, field: &str, ctx: &mut Ctx) -> Option<Value> {
    let mut expected = predicate.path(operator).as_text().trim_matches(|c: char| c <= ' ').to_string();
    if predicate.get("expectedOffset").is_some() {
        let offset = format!("{} {}", predicate.path("expectedOffset").as_text(), predicate.path("expectedOffsetUnit").as_text_or("days").to_lowercase());
        if expected.len() >= 3 && expected.is_char_boundary(3) && expected[..3].eq_ignore_ascii_case("now") {
            expected = format!("{expected} {}", if offset.starts_with('-') { offset } else { format!("+{offset}") });
        } else {
            ctx.warn(field, "expectedOffset on a literal date-time is not mapped — the literal is used as given");
        }
    }
    let text = |key: &str| predicate.get(key).filter(|v| !v.is_null()).map(JsonNode::as_text);
    let date_time = crate::model::DateTimeValue {
        operator,
        expected: Some(expected),
        actual_format: text("actualFormat"),
        truncate_expected: text("truncateExpected"),
        truncate_actual: text("truncateActual"),
        apply_truncation_last: predicate.get("applyTruncationLast").map(|v| v.as_boolean_or(false)),
        zone: None,
    };
    if let Err(message) = date_time.comparison() {
        ctx.warn(field, format!("'{operator}' predicate could not be mapped ({message}) — omitted"));
        return None;
    }
    let mut o = Map::new();
    date_time.write(&mut o);
    Some(Value::Object(o))
}

/// MockServer matches one body per request: the first mappable pattern applies, the rest are warned about.
fn apply_body_patterns(req: &mut Req, patterns: &[JsonNode], options: &Options, ctx: &mut Ctx) {
    let mut body_set = false;
    for (i, pattern) in patterns.iter().enumerate() {
        let locator = format!("{} bodyPatterns[{i}]", ctx.locator);
        let mut ctx = ctx.at(locator);
        let Some(body) = body_matcher(pattern, options, &mut ctx) else { continue };
        if body_set {
            ctx.warn("bodyPatterns", "multiple body patterns; only the first mappable one is applied");
            continue;
        }
        req.body = Some(body);
        body_set = true;
    }
}

/// One WireMock body pattern as a MockServer body matcher, or `None` (with a warning) when it has no equivalent.
fn body_matcher(pattern: &JsonNode, options: &Options, ctx: &mut Ctx) -> Option<Value> {
    let has = |k: &str| pattern.get(k).is_some();
    if let Some(json) = pattern.get("equalToJson") {
        let ignore_extra = pattern.path("ignoreExtraElements").as_boolean_or(false);
        if pattern.path("ignoreArrayOrder").as_boolean_or(false) && !ignore_extra {
            ctx.warn("bodyPatterns.ignoreArrayOrder", "ignoreArrayOrder is approximated by MockServer's JSON matching and not separately configurable");
        }
        let text = json.text_value().map_or_else(|| json.to_java_string(), str::to_string);
        return Some(super::json_body(&text, if ignore_extra { "ONLY_MATCHING_FIELDS" } else { "STRICT" }));
    }
    if let Some(json_path) = pattern.get("matchesJsonPath") {
        let expression = json_path.text_value().map(str::to_string).or_else(|| json_path.value_text("expression"));
        let Some(expression) = expression else {
            ctx.warn("bodyPatterns.matchesJsonPath", "matchesJsonPath object form has no 'expression' field — body matcher omitted");
            return None;
        };
        if let Some(operator) = json_path.is_object().then(|| date_time_operator(json_path)).flatten() {
            let date_time = date_time_predicate(operator, json_path, "bodyPatterns.matchesJsonPath", ctx)?;
            let mut body = super::json_path_body(&expression);
            body["dateTime"] = date_time;
            return Some(body);
        }
        if json_path.is_object() && json_path.size() > 1 {
            ctx.warn("bodyPatterns.matchesJsonPath", "the sub-matcher on the JSONPath result is not applied; the body matches when the expression selects anything");
        }
        return Some(super::json_path_body(&expression));
    }
    if has("equalToXml") {
        for unsupported in ["enablePlaceholders", "placeholderOpeningDelimiterRegex", "placeholderClosingDelimiterRegex", "exemptedComparisons"] {
            if has(unsupported) {
                ctx.warn(
                    format!("bodyPatterns.equalToXml.{unsupported}"),
                    format!("{unsupported} is not mapped; MockServer compares XML for similarity, ignoring whitespace, comments and element order"),
                );
            }
        }
        return Some(json!({"type": "XML", "xml": pattern.path("equalToXml").as_text()}));
    }
    if has("matchesXPath") {
        return xpath_matcher(pattern, options, ctx);
    }
    if has("binaryEqualTo") {
        return match super::base64_decode(&pattern.path("binaryEqualTo").as_text()) {
            Some(bytes) => Some(binary_body(&bytes)),
            None => {
                ctx.warn("bodyPatterns.binaryEqualTo", "invalid Base64 — body matcher omitted");
                None
            }
        };
    }
    if let Some(v) = pattern.get("equalTo") {
        return Some(Value::String(v.as_text()));
    }
    if let Some(v) = pattern.get("contains") {
        return Some(super::substring_body(&v.as_text()));
    }
    if let Some(v) = pattern.get("matches") {
        return Some(super::regex_body(&v.as_text()));
    }
    ctx.warn("bodyPatterns", format!("unsupported body pattern {} — omitted", field_names(pattern)));
    None
}

/// `matchesXPath`: an expression, or an object holding one and a matcher for its result; an `equalTo` or `contains`
/// result matcher folds into the expression.
fn xpath_matcher(pattern: &JsonNode, options: &Options, ctx: &mut Ctx) -> Option<Value> {
    let xpath = pattern.path("matchesXPath");
    let mut date_time = None;
    let operator = (xpath.is_object() && xpath.value_text("expression").is_some()).then(|| date_time_operator(&xpath)).flatten();
    let expression = if let Some(operator) = operator {
        date_time = Some(date_time_predicate(operator, &xpath, "bodyPatterns.matchesXPath", ctx)?);
        xpath.path("expression").as_text()
    } else if xpath.is_textual() {
        xpath.as_text()
    } else if let Some(expression) = xpath.value_text("expression") {
        let selector = format!("({expression})");
        // A value compared with a sensitive field is masked, as redaction masks that field in a JSON body.
        let masked = super::redact::mentions_sensitive_body_field(&selector, options);
        let literal = |key: &str| xpath_literal(&if masked { super::redact::REDACTED.to_string() } else { xpath.path(key).as_text() });
        if xpath.get("equalTo").is_some() {
            format!("{selector} = {}", literal("equalTo"))
        } else if xpath.get("contains").is_some() {
            format!("{selector}[contains(., {})]", literal("contains"))
        } else {
            if xpath.size() > 1 {
                ctx.warn(
                    "bodyPatterns.matchesXPath",
                    format!("the result matcher {} is not applied; the body matches when the expression selects anything", field_names(&xpath)),
                );
            }
            expression
        }
    } else {
        ctx.warn("bodyPatterns.matchesXPath", "matchesXPath has no expression — body matcher omitted");
        return None;
    };
    let mut body = json!({"type": "XPATH", "xpath": expression});
    let namespaces: Map<String, Value> =
        pattern.path("xPathNamespaces").as_object().into_iter().flatten().map(|(k, v)| (k.clone(), Value::String(v.as_text()))).collect();
    if !namespaces.is_empty() {
        body["namespacePrefixes"] = Value::Object(namespaces);
    }
    if let Some(date_time) = date_time {
        body["dateTime"] = date_time;
    }
    Some(body)
}

fn xpath_literal(value: &str) -> String {
    if !value.contains('\'') {
        format!("'{value}'")
    } else if !value.contains('"') {
        format!("\"{value}\"")
    } else {
        format!("concat('{}')", value.replace('\'', "', \"'\", '"))
    }
}

fn binary_body(bytes: &[u8]) -> Value {
    use base64::Engine;
    json!({"type": "BINARY", "base64Bytes": base64::engine::general_purpose::STANDARD.encode(bytes)})
}

fn apply_response(e: &mut Map<String, Value>, response: Option<&JsonNode>, path: &PathContext, files_root: Option<&Path>, options: &Options, ctx: &mut Ctx) {
    let Some(response) = response else {
        e.insert("httpResponse".into(), json!({"statusCode": 200}));
        return;
    };
    // A fault is a connection-level failure, and wins over a body.
    if let Some(fault) = response.value_text("fault") {
        e.insert("httpError".into(), map_fault(&fault, ctx));
        return;
    }
    let delay = map_delay(&response.path("fixedDelayMilliseconds"), &response.path("delayDistribution"), "response", ctx);
    if let Some(proxy) = response.value_text("proxyBaseUrl") {
        let url = url_parts(&proxy);
        match &url {
            Some(u) => {
                if let Some(p) = u.path.as_deref().filter(|p| !p.is_empty() && *p != "/") {
                    ctx.warn("response.proxyBaseUrl", format!("proxyBaseUrl path prefix '{p}' is not applied; MockServer forwards to host/port only"));
                }
            }
            None => ctx.warn("response.proxyBaseUrl", format!("could not parse proxyBaseUrl '{proxy}' — forward target may be incomplete")),
        }
        super::forward(e, url.as_ref());
        if let (Some(d), Some(Value::Object(f))) = (delay, e.get_mut("httpForward")) {
            f.insert("delay".into(), d);
        }
        return;
    }
    let mut resp = Map::new();
    resp.insert("statusCode".into(), (response.path("status").as_int_or(200) as i64).into());
    let headers = super::header_object(&response.path("headers"));
    if !headers.is_empty() {
        resp.insert("headers".into(), super::entries_json(&headers));
    }
    let templated = templating_enabled(response, ctx);
    let json_body = response.path("jsonBody");
    let body = response.value_text("body");
    let base64_body = response.value_text("base64Body");
    let body_file_name = response.value_text("bodyFileName");
    let mut template_body: Option<String> = None;
    let mut body_length: i64 = -1;
    if !json_body.is_missing() && !json_body.is_null() {
        let text = json_body.to_java_string();
        resp.insert("body".into(), super::string_body_with_type(&text, "application/json"));
        template_body = Some(text);
    } else if let Some(body) = body.filter(|b| !b.is_empty()) {
        resp.insert("body".into(), Value::String(body.clone()));
        template_body = Some(body);
    } else if let Some(encoded) = base64_body.filter(|b| !b.is_empty()) {
        match super::base64_decode(&encoded) {
            Some(bytes) => {
                resp.insert("body".into(), Value::String(String::from_utf8_lossy(&bytes).into_owned()));
            }
            None => ctx.warn("response.base64Body", "invalid Base64 — response body omitted"),
        }
    } else if let Some(name) = body_file_name && let Some(file) = resolve_body_file(&name, files_root, ctx) {
        template_body = if templated { read_templated_file(&file) } else { None };
        match &template_body {
            Some(text) => {
                resp.insert("body".into(), Value::String(text.clone()));
            }
            None => {
                let mut f = Map::new();
                f.insert("type".into(), "FILE".into());
                f.insert("filePath".into(), file.to_string_lossy().into_owned().into());
                if let Some(ct) = super::redact::first_header(&resp, "Content-Type").filter(|c| !c.is_empty()) {
                    f.insert("contentType".into(), ct.into());
                }
                resp.insert("body".into(), Value::Object(f));
                body_length = std::fs::metadata(&file).map_or(-1, |m| m.len() as i64);
            }
        }
    }
    if body_length < 0 && let Some(b) = resp.get("body") {
        body_length = super::redact::body_as_string(b).map_or(0, |s| s.len() as i64);
    }
    let template_has_tags = templated && template::has_tags(template_body.as_deref());
    if let Some(options) = map_chunked_dribble(&response.path("chunkedDribbleDelay"), body_length, template_has_tags, ctx) {
        resp.insert("connectionOptions".into(), options);
    }
    let mut resp = Value::Object(resp);
    if templated && let Some(mut t) = response_template(&mut resp, template_body.as_deref(), path, options, ctx) {
        if let Some(d) = delay {
            t.insert("delay".into(), d);
        }
        e.insert("httpResponseTemplate".into(), Value::Object(t));
        return;
    }
    if let Some(d) = delay {
        resp["delay"] = d;
    }
    e.insert("httpResponse".into(), resp);
}

/// True when the stub asks for the `response-template` transformer; any other one is a WireMock extension.
fn templating_enabled(response: &JsonNode, ctx: &mut Ctx) -> bool {
    let mut templated = false;
    for transformer in response.path("transformers").as_array().into_iter().flatten() {
        let name = transformer.as_text();
        if name == "response-template" {
            templated = true;
        } else {
            ctx.warn(format!("response.transformers.{name}"), format!("custom response transformer '{name}' has no MockServer equivalent and is not applied"));
        }
    }
    let parameters = response.path("transformerParameters");
    if parameters.as_object().is_some_and(|p| !p.is_empty()) {
        ctx.warn("response.transformerParameters", format!("transformer parameters {} are not mapped", field_names(&parameters)));
    }
    templated
}

/// A Mustache response template when the WireMock template uses only references MockServer can express; `None`
/// when there is nothing to template, or (with a warning) when a reference cannot be translated.
/// The translated headers replace the response's own too, served verbatim or not: upstream's shallow clone shares
/// its `Headers` with the response, and `withHeaders` refills that shared object.
fn response_template(response: &mut Value, template_body: Option<&str>, path: &PathContext, options: &Options, ctx: &mut Ctx) -> Option<Map<String, Value>> {
    let mut untranslatable = Vec::new();
    let mut has_tags = false;
    let mut templated = response.as_object().cloned().unwrap_or_default();
    let mut translated_body = None;
    if let Some(text) = template_body {
        let t = template::to_mustache(text, path);
        has_tags = t.has_tags;
        untranslatable.extend(t.untranslatable);
        let content_type = response.get("body").and_then(|b| b.get("contentType")).cloned();
        templated.insert(
            "body".into(),
            match content_type {
                Some(ct) => json!({"type": "STRING", "string": t.text, "contentType": ct}),
                None => Value::String(t.text.clone()),
            },
        );
        translated_body = Some(t.text);
    }
    let mut headers = Vec::new();
    for (name, values) in super::redact::entry_list(response.get("headers").unwrap_or(&Value::Null)) {
        let mut out = Vec::new();
        for value in values {
            let t = template::to_mustache(&value, path);
            has_tags |= t.has_tags;
            untranslatable.extend(t.untranslatable);
            out.push(t.text);
        }
        headers.push((name, out));
    }
    if headers.is_empty() {
        templated.remove("headers");
    } else {
        templated.insert("headers".into(), super::entries_json(&headers));
        response["headers"] = super::entries_json(&headers);
    }
    if !untranslatable.is_empty() {
        ctx.warn(
            "response.transformers.response-template",
            format!("the template uses [{}], which has no MockServer Mustache equivalent; the response is served verbatim", untranslatable.join(", ")),
        );
        return None;
    }
    if !has_tags {
        return None;
    }
    if template::references_request_values(translated_body.as_deref()) || headers.iter().flat_map(|(_, v)| v).any(|v| template::references_request_values(Some(v))) {
        ctx.warn(
            "response.transformers.response-template",
            "request values are rendered inside MockServer's JSON response template, so a backslash in one is read as a JSON escape (and a trailing backslash stops the response rendering)",
        );
    }
    // The template text is out of reach of the import redaction that runs later, so it is redacted here.
    let redacted = super::redact::redact_response(&Value::Object(templated), options);
    let text = crate::json::pretty(&crate::canonical::response(&redacted));
    let mut t = Map::new();
    t.insert("templateType".into(), "MUSTACHE".into());
    t.insert("template".into(), text.into());
    Some(t)
}

/// WireMock adds `fixedDelayMilliseconds` to a sampled `delayDistribution`; MockServer has one delay, fixed or
/// sampled, so the fixed part is folded into the distribution.
fn map_delay(fixed_node: &JsonNode, distribution: &JsonNode, field: &str, ctx: &mut Ctx) -> Option<Value> {
    let fixed = if fixed_node.is_number() { as_long(fixed_node, 0).max(0) } else { 0 };
    let fixed_delay = || fixed_node.is_number().then(|| millis(fixed));
    if !distribution.is_object() {
        return fixed_delay();
    }
    let kind = distribution.path("type").as_text_or("").to_lowercase();
    let construct = format!("{field}.delayDistribution");
    let sampled = |d: Value| Some(json!({"timeUnit": "MILLISECONDS", "value": 0, "distribution": d}));
    let invalid = |ctx: &mut Ctx, message: String| ctx.warn(construct.clone(), format!("invalid {kind} delay distribution ({message}); only fixedDelayMilliseconds is applied"));
    match kind.as_str() {
        "uniform" => {
            let (min, max) = (as_long(&distribution.path("lower"), 0) + fixed, as_long(&distribution.path("upper"), 0) + fixed);
            if min < 0 {
                invalid(ctx, format!("min must be >= 0, got {min}"));
            } else if max < min {
                invalid(ctx, format!("max must be >= min, got min={min} max={max}"));
            } else {
                return sampled(json!({"type": "UNIFORM", "min": min, "max": max}));
            }
        }
        "lognormal" => {
            let median = as_double(&distribution.path("median"));
            let sigma = as_double(&distribution.path("sigma"));
            let p99 = java_round(median * (sigma * Z_SCORE_P99).exp());
            if fixed > 0 {
                ctx.warn(construct.clone(), "fixedDelayMilliseconds plus a lognormal distribution is approximated by a lognormal with the same median and 99th percentile");
            }
            if distribution.get("maxValue").is_some() {
                ctx.warn(format!("{construct}.maxValue"), "the lognormal maxValue cap is not applied");
            }
            let (median, p99) = (java_round(median).max(1) + fixed, p99.max(1) + fixed);
            if median <= 0 {
                invalid(ctx, format!("median must be > 0, got {median}"));
            } else if p99 < median {
                invalid(ctx, format!("p99 must be >= median, got median={median} p99={p99}"));
            } else {
                return sampled(json!({"type": "LOG_NORMAL", "median": median, "p99": p99}));
            }
        }
        "fixed" => return Some(millis(fixed + as_long(&distribution.path("milliseconds"), 0).max(0))),
        _ => ctx.warn(construct.clone(), format!("unknown delay distribution type '{kind}'; only fixedDelayMilliseconds is applied")),
    }
    fixed_delay()
}

fn millis(value: i64) -> Value {
    json!({"timeUnit": "MILLISECONDS", "value": value})
}

/// `chunkedDribbleDelay` spreads `numberOfChunks` chunks over `totalDuration`; MockServer's chunked connection
/// options take a chunk size and a per-chunk delay.
fn map_chunked_dribble(dribble: &JsonNode, body_length: i64, templated: bool, ctx: &mut Ctx) -> Option<Value> {
    if !dribble.is_object() {
        return None;
    }
    let chunks = dribble.path("numberOfChunks").as_int_or(0) as i64;
    let total = as_long(&dribble.path("totalDuration"), -1);
    if chunks < 1 || total < 0 {
        ctx.warn("response.chunkedDribbleDelay", "numberOfChunks must be at least 1 and totalDuration at least 0 — not applied");
        return None;
    }
    if body_length <= 0 {
        ctx.warn("response.chunkedDribbleDelay", "the response has no body to dribble — not applied");
        return None;
    }
    if templated {
        ctx.warn("response.chunkedDribbleDelay", "the chunk size is computed from the unrendered template, so the rendered body may arrive in a different number of chunks");
    }
    let chunk_size = ((body_length + chunks - 1) / chunks).max(1).min(i32::MAX as i64);
    Some(json!({"chunkSize": chunk_size, "chunkDelay": millis(total / chunks)}))
}

/// `bodyFileName` inside the `__files` directory; a name that escapes it is refused.
fn resolve_body_file(name: &str, root: Option<&Path>, ctx: &mut Ctx) -> Option<PathBuf> {
    let Some(root) = root else {
        ctx.warn(
            "response.bodyFileName",
            format!("bodyFileName '{name}' is not resolved because no files directory was given; pass the WireMock __files directory as filesDirectory, or inline the body"),
        );
        return None;
    };
    let outside = |ctx: &mut Ctx| ctx.warn("response.bodyFileName", format!("bodyFileName '{name}' resolves outside the files directory — response body omitted"));
    let file = normalize(&root.join(name));
    if !file.starts_with(root) {
        outside(ctx);
        return None;
    }
    let Some(canonical) = file.is_file().then(|| file.canonicalize().ok()).flatten() else {
        ctx.warn("response.bodyFileName", format!("bodyFileName '{name}' was not found in {} — response body omitted", root.display()));
        return None;
    };
    // A symbolic link inside the directory must not lead outside it.
    if !canonical.starts_with(root.canonicalize().unwrap_or_else(|_| root.to_path_buf())) {
        outside(ctx);
        return None;
    }
    Some(canonical)
}

/// A templated body file is inlined so its references can be translated; `None` when it has no tags.
fn read_templated_file(file: &Path) -> Option<String> {
    let bytes = std::fs::read(file).ok()?;
    let content = String::from_utf8_lossy(&bytes).into_owned();
    template::has_tags(Some(&content)).then_some(content)
}

/// `Path.normalize()`: `.` dropped, `..` folded into its parent, lexically.
fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    out.push("..");
                }
            }
            other => out.push(other),
        }
    }
    out
}

/// `EMPTY_RESPONSE`, `MALFORMED_RESPONSE_CHUNK` and `RANDOM_DATA_THEN_CLOSE` byte for byte on HTTP/1.1;
/// `CONNECTION_RESET_BY_PEER` a TCP reset, as WireMock does.
fn map_fault(fault: &str, ctx: &mut Ctx) -> Value {
    use base64::Engine;
    let bytes = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
    match fault.to_uppercase().as_str() {
        "EMPTY_RESPONSE" => json!({"dropConnection": true}),
        "MALFORMED_RESPONSE_CHUNK" => {
            let mut b = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
            b.extend_from_slice(WIREMOCK_GARBAGE);
            json!({"dropConnection": true, "responseBytes": bytes(&b)})
        }
        "RANDOM_DATA_THEN_CLOSE" => json!({"dropConnection": true, "responseBytes": bytes(WIREMOCK_GARBAGE)}),
        "CONNECTION_RESET_BY_PEER" => json!({"resetConnection": true}),
        _ => {
            ctx.warn(format!("response.fault.{fault}"), "unknown fault type — approximated as a dropped connection");
            json!({"dropConnection": true})
        }
    }
}

/// WireMock webhooks (`postServeActions` in WireMock 2, `serveEventListeners` in 3) as after-actions.
fn apply_webhooks(e: &mut Map<String, Value>, stub: &JsonNode, ctx: &mut Ctx) {
    let mut actions = Vec::new();
    for field in ["postServeActions", "serveEventListeners"] {
        let listeners = stub.path(field);
        if let Some(items) = listeners.as_array() {
            for (i, listener) in items.iter().enumerate() {
                let locator = format!("{} {field}[{i}]", ctx.locator);
                add_webhook(&mut actions, &listener.path("name").as_text_or(""), &listener.path("parameters"), field, &mut ctx.at(locator));
            }
        } else if let Some(o) = listeners.as_object() {
            for (name, parameters) in o {
                let locator = format!("{} {field}.{name}", ctx.locator);
                add_webhook(&mut actions, name, parameters, field, &mut ctx.at(locator));
            }
        }
    }
    if !actions.is_empty() {
        e.insert("afterActions".into(), Value::Array(actions));
    }
}

fn add_webhook(actions: &mut Vec<Value>, name: &str, parameters: &JsonNode, field: &str, ctx: &mut Ctx) {
    if name != "webhook" {
        ctx.warn(format!("{field}.{name}"), format!("serve event listener '{name}' has no MockServer equivalent and is not applied"));
        return;
    }
    let mut untranslatable = Vec::new();
    let url = parameters.value_text("url").map(|u| runtime_expressions(&u, &mut untranslatable));
    let parts = url.as_deref().and_then(|u| URL_PARTS.captures(u));
    let Some(parts) = parts else {
        let what = match &url {
            None => "is missing".to_string(),
            Some(u) => format!("'{u}' is not an absolute http(s) URL"),
        };
        ctx.warn(format!("{field}.webhook"), format!("webhook url {what} — webhook not applied"));
        return;
    };
    let path = parts.get(3).map_or("", |m| m.as_str());
    let mut request = Map::new();
    request.insert("method".into(), parameters.path("method").as_text_or("GET").to_uppercase().into());
    request.insert("secure".into(), parts[1].eq_ignore_ascii_case("https").into());
    request.insert("path".into(), (if path.is_empty() { "/" } else { path }).into());
    let mut headers: super::MultiMap = vec![("Host".into(), vec![parts[2].to_string()])];
    let query = super::parse_query_string(parts.get(4).map(|m| m.as_str()));
    if !query.is_empty() {
        request.insert("queryStringParameters".into(), super::entries_json(&query));
    }
    for (name, value) in parameters.path("headers").as_object().into_iter().flatten() {
        let values: Vec<String> = match value.as_array() {
            Some(items) => items.iter().map(|v| runtime_expressions(&v.as_text(), &mut untranslatable)).collect(),
            None => vec![runtime_expressions(&value.as_text(), &mut untranslatable)],
        };
        super::add(&mut headers, name, values);
    }
    request.insert("headers".into(), super::entries_json(&headers));
    if let Some(body) = parameters.value_text("body") {
        request.insert("body".into(), Value::String(runtime_expressions(&body, &mut untranslatable)));
    } else if let Some(encoded) = parameters.value_text("base64Body") {
        match super::base64_decode(&encoded) {
            Some(bytes) => {
                request.insert("body".into(), binary_body(&bytes));
            }
            None => ctx.warn(format!("{field}.webhook.base64Body"), "invalid Base64 — webhook body omitted"),
        }
    }
    if !untranslatable.is_empty() {
        ctx.warn(format!("{field}.webhook"), format!("webhook template references [{}] have no MockServer equivalent and are sent verbatim", untranslatable.join(", ")));
    }
    let mut action = Map::new();
    action.insert("httpRequest".into(), Value::Object(request));
    if let Some(delay) = map_delay(&JsonNode::Missing, &parameters.path("delay"), &format!("{field}.webhook"), ctx) {
        action.insert("delay".into(), delay);
    }
    actions.push(Value::Object(action));
}

fn runtime_expressions(text: &str, untranslatable: &mut Vec<String>) -> String {
    let t = template::to_runtime_expressions(text);
    untranslatable.extend(t.untranslatable);
    t.text
}

/// `asLong(default)`: numbers truncated, booleans 1/0, text parsed as a long, anything else the default.
fn as_long(node: &JsonNode, default: i64) -> i64 {
    match node {
        JsonNode::Boolean(b) => *b as i64,
        JsonNode::Text(s) => s.trim().parse().unwrap_or(default),
        n if n.is_number() => n.long_value(),
        _ => default,
    }
}

/// `asDouble()`.
fn as_double(node: &JsonNode) -> f64 {
    match node {
        JsonNode::Boolean(b) => *b as i64 as f64,
        JsonNode::Text(s) => s.trim().parse().unwrap_or(0.0),
        n if n.is_number() => n.double_value(),
        _ => 0.0,
    }
}

/// `Math.round(double)`: half up, NaN as 0, saturated.
fn java_round(v: f64) -> i64 {
    if v.is_nan() { 0 } else { (v + 0.5).floor() as i64 }
}

fn id_suffix(stub: &JsonNode) -> String {
    let id = stub.value_text("id").or_else(|| stub.value_text("uuid")).or_else(|| stub.value_text("name").map(|n| super::slug(&n)));
    id.filter(|i| !i.is_empty()).map(|i| format!("-{i}")).unwrap_or_default()
}
