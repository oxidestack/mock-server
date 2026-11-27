//! Body matchers (§2.4), compiled from the canonical body form.

use base64::Engine;
use serde_json::{Map, Value};

use super::multimap::MultiMapMatcher;
use super::string::StringMatcher;
use crate::canonical;
use crate::request::{self, HttpRequest};

#[derive(Debug)]
enum Kind {
    String(String),
    SubString(String),
    Regex(StringMatcher),
    /// `written`: the expectation's JSON as a string, which `JsonStringMatcher` quotes as written; a
    /// JSON value is quoted pretty-printed.
    /// `numeric`: `matchNumbersAsStrings`, which `JsonStringMatcher` turns into JSONUnit's `withTolerance(ZERO)`.
    Json { expected: Value, strict: bool, written: Option<String>, numeric: bool },
    /// With its `parameterStyles`, applied to a form body before it is validated, and the schema as differences
    /// quote it.
    JsonSchema(Option<Box<jsonschema::Validator>>, Vec<(String, String)>, Value),
    /// SECURITY: a `JSON_SCHEMA` body whose schema names a remote/file `$ref` that
    /// `jsonSchemaAllowRemoteRefs` (default deny) blocks — the schema as written, its `parameterStyles`, and the
    /// blocked `$ref` URI. `JsonSchemaValidator.isValid` never fetches it; the expectation still registers, and
    /// every request against it fails to match with `InvalidSchemaException`'s text, exactly as upstream defers
    /// the failure to match time rather than rejecting the expectation.
    JsonSchemaBlocked(Value, Vec<(String, String)>, String),
    /// A `JSON_SCHEMA` body whose `jsonSchema` is a string that is neither a JSON document (ends with `}`) nor a
    /// `*.json` file path: `JsonSchemaValidator`'s constructor throws, so the expectation is rejected.
    JsonSchemaIllegal,
    /// A `JSON_SCHEMA` body whose schema networknt cannot build: the exception's message.
    JsonSchemaUnbuilt(String),
    /// The compiled path and the path as written.
    JsonPath(JaywayPath, String),
    /// The parsed document and the document as written.
    Xml(Option<XmlNode>, String),
    /// The expression, `xpathMatchingTimeoutMillis` as the matcher was built ([`with_xpath_timeout`]) and its
    /// `namespacePrefixes`, which make `XPathEvaluator` parse namespace-aware ([`XPathNamespaces`]).
    XPath(String, i64, XPathNamespaces),
    /// A `JSON_PATH` body with a `dateTime` (`JsonPathMatcher` with a `NottableDateTimeString`): a value the path
    /// selects must be a matching date-time.
    JsonPathDateTime(JaywayPath, String, Box<StringMatcher>),
    /// An `XPATH` body with a `dateTime`: the text of a node the expression selects must be a matching date-time.
    XPathDateTime(String, XPathNamespaces, Box<StringMatcher>),
    /// The schema as written, and the compiled schema or why it could not be read.
    XmlSchema(String, Result<std::sync::Arc<crate::xsd::Schema>, crate::xsd::SchemaError>),
    Parameters(MultiMapMatcher),
    Binary(Vec<u8>),
    /// `WASM`: the named module decides (`crate::wasm`).
    Wasm(String),
    /// `JSON_RPC`: a 2.0 request (or one in a batch) whose `method` equals or matches `method`, with `params`
    /// valid against `paramsSchema` when one is given.
    JsonRpc(Box<JsonRpc>),
    GraphQl(Box<super::graphql::GraphQl>),
    /// `FUZZY`: Jaro-Winkler similarity at least `threshold`.
    Fuzzy { expected: String, threshold: f64, ignore_case: bool },
    /// `ALL_OF`: every component matches the same body.
    AllOf(Vec<BodyMatcher>),
    /// `MULTIPART`: the decoded form-data fields, file names and part content types (`MultipartMatcher`).
    Multipart { fields: MultiMapMatcher, filenames: MultiMapMatcher, part_content_types: MultiMapMatcher, blank: bool },
    /// `FILE` whose file cannot be read: `FileBodyMaterialiser` throws, so the expectation is rejected.
    UnreadableFile(String),
    /// A body type this server does not evaluate yet; never matches.
    Unsupported,
}

#[derive(Debug)]
pub struct BodyMatcher {
    kind: Kind,
    not: bool,
    /// `optional`: an absent body matches.
    optional: bool,
    /// `matchExactCase` (see [`super::with_exact_case`]): a `REGEX` body matches case-sensitively on the data plane.
    exact_case: bool,
}

impl BodyMatcher {
    /// From a canonical body value.
    /// A form body's parameters put back in the order the input body lists them (see `MultiMapMatcher::in_order_of`).
    pub fn in_order_of(mut self, input: Option<&Value>) -> BodyMatcher {
        if let Kind::Parameters(m) = self.kind {
            let parameters = input.and_then(Value::as_object).and_then(|o| canonical::field(o, "parameters"));
            self.kind = Kind::Parameters(m.in_order_of(parameters));
        } else if let Kind::Json { written, .. } = &mut self.kind {
            // The canonical form holds the JSON parsed; the input still has it as written.
            let json = input.and_then(Value::as_object).filter(|o| canonical::body_type(o).as_deref() == Some("JSON")).and_then(|o| canonical::field(o, "json"));
            *written = json.and_then(Value::as_str).map(str::to_string);
        }
        self
    }

    pub fn compile(v: &Value) -> BodyMatcher {
        let exact_case = super::exact_case();
        let positive = |kind| BodyMatcher { kind, not: false, optional: false, exact_case };
        let o = match v {
            Value::String(s) => return positive(Kind::String(s.clone())),
            Value::Array(_) => return positive(Kind::Json { expected: v.clone(), strict: false, written: None, numeric: false }),
            Value::Object(o) => o,
            // A bare scalar JSON body; one given as a string is a number holding its text (`canonical::body`).
            Value::Number(_) | Value::Bool(_) => return positive(Kind::Json { expected: json_scalar(v), strict: false, written: None, numeric: false }),
            _ => return positive(Kind::Unsupported),
        };
        let Some(kind) = canonical::body_type(o) else {
            return positive(Kind::Json { expected: v.clone(), strict: false, written: None, numeric: false });
        };
        let not = o.get("not").and_then(Value::as_bool).unwrap_or(false);
        let text = |key: &str| canonical::field(o, key).and_then(Value::as_str).unwrap_or_default().to_string();
        let kind = match kind.as_str() {
            "STRING" if o.get("subString").and_then(Value::as_bool).unwrap_or(false) => Kind::SubString(text("string")),
            "STRING" => Kind::String(text("string")),
            "REGEX" => Kind::Regex(StringMatcher::fixed_value(&text("regex"))),
            "JSON" => Kind::Json {
                expected: json_scalar(&canonical::json_payload(canonical::field(o, "json").unwrap_or(&Value::Null))),
                strict: o.get("matchType").and_then(Value::as_str) == Some("STRICT"),
                written: None,
                numeric: o.get("matchNumbersAsStrings").and_then(Value::as_bool).unwrap_or(false),
            },
            "JSON_SCHEMA" => {
                let schema = canonical::json_payload(canonical::field(o, "jsonSchema").unwrap_or(&Value::Null));
                let styles = || {
                    o.get("parameterStyles")
                        .and_then(Value::as_object)
                        .map(|styles| styles.iter().filter_map(|(k, v)| v.as_str().map(|v| (k.clone(), v.to_string()))).collect())
                        .unwrap_or_default()
                };
                // SECURITY: a blocked remote/file `$ref` is reported at match time, never fetched —
                // see `Kind::JsonSchemaBlocked` and `super::string::validator`.
                let blocked = (!super::string::remote_refs_allowed()).then(|| super::string::blocked_remote_ref(&schema)).flatten();
                let illegal = schema.as_str().is_some_and(|s| !s.trim().ends_with(".json") && !s.trim().ends_with('}'));
                // No schema read is `""` (a `bodyAllOf` component whose null schema was dropped).
                let illegal = illegal || schema.is_boolean() || schema.is_null();
                let unbuilt = schema.is_object().then(|| {
                    crate::networknt::construction_error(&schema, crate::networknt::default_dialect(&schema), super::string::remote_refs_allowed())
                });
                match blocked {
                    _ if illegal => Kind::JsonSchemaIllegal,
                    _ if unbuilt.as_ref().is_some_and(Option::is_some) => Kind::JsonSchemaUnbuilt(unbuilt.flatten().unwrap_or_default()),
                    Some(uri) => Kind::JsonSchemaBlocked(schema, styles(), uri),
                    // A schema the `jsonschema` crate cannot build is still evaluated (networknt accepts more).
                    None => Kind::JsonSchema(super::string::validator(&schema).ok().map(Box::new), styles(), schema),
                }
            },
            "JSON_PATH" => match canonical::field(o, "dateTime").filter(|d| d.is_object()) {
                Some(date_time) => Kind::JsonPathDateTime(JaywayPath::compile(&text("jsonPath")), text("jsonPath"), Box::new(StringMatcher::compile(date_time))),
                None => Kind::JsonPath(JaywayPath::compile(&text("jsonPath")), text("jsonPath")),
            },
            "XML" => Kind::Xml(XmlNode::parse(&text("xml")), text("xml")),
            "XPATH" => {
                let namespaces = canonical::field(o, "namespacePrefixes").and_then(Value::as_object).map(|m| {
                    m.iter().map(|(k, v)| (k.clone(), v.as_str().map_or_else(|| v.to_string(), str::to_string))).collect()
                });
                match canonical::field(o, "dateTime").filter(|d| d.is_object()) {
                    Some(date_time) => Kind::XPathDateTime(text("xpath"), namespaces, Box::new(StringMatcher::compile(date_time))),
                    None => Kind::XPath(text("xpath"), XPATH_TIMEOUT_MILLIS.with(std::cell::Cell::get), namespaces),
                }
            }
            "XML_SCHEMA" => {
                let schema = text("xmlSchema");
                // One `SchemaFactory` per JVM upstream: the namespaces it reported are the server's, kept across
                // resets (outside a request, as at startup, a compile starts from none).
                let reported = crate::wasm::current_server().map(|state| state.xsd_reported.clone()).unwrap_or_default();
                let compiled = crate::xsd::Schema::compile(&schema, &reported).map(std::sync::Arc::new);
                Kind::XmlSchema(schema, compiled)
            }
            "PARAMETERS" => Kind::Parameters(MultiMapMatcher::compile(canonical::field(o, "parameters").unwrap_or(&Value::Null))),
            "BINARY" => Kind::Binary(base64::engine::general_purpose::STANDARD.decode(text("base64Bytes")).unwrap_or_default()),
            "WASM" => Kind::Wasm(text("moduleName")),
            "MULTIPART" => {
                let map = |k: &str| canonical::field(o, k).filter(|m| m.as_object().is_some_and(|m| !m.is_empty()));
                Kind::Multipart {
                    fields: MultiMapMatcher::compile(map("fields").unwrap_or(&Value::Null)),
                    filenames: MultiMapMatcher::compile(map("filenames").unwrap_or(&Value::Null)),
                    part_content_types: MultiMapMatcher::compile(map("partContentTypes").unwrap_or(&Value::Null)),
                    blank: map("fields").is_none() && map("filenames").is_none() && map("partContentTypes").is_none(),
                }
            }
            "FUZZY" => Kind::Fuzzy {
                expected: text("fuzzy"),
                threshold: canonical::field(o, "threshold").and_then(Value::as_f64).unwrap_or(0.8),
                ignore_case: o.get("ignoreCase").and_then(Value::as_bool).unwrap_or(false),
            },
            "ALL_OF" => Kind::AllOf(canonical::field(o, "bodyAllOf").and_then(Value::as_array).map(|b| b.iter().map(BodyMatcher::compile).collect()).unwrap_or_default()),
            // `FileBodyMaterialiser`: the file as it is now, as text for a text content type, else as bytes.
            "FILE" => {
                let path = text("filePath");
                let content_type = canonical::field(o, "contentType").and_then(Value::as_str).filter(|c| !c.trim().is_empty());
                match crate::templates::read_file(&path) {
                    Ok(bytes) if content_type.is_some() && crate::media_type::MediaType::parse(content_type).is_string() => {
                        Kind::String(String::from_utf8_lossy(&bytes).into_owned())
                    }
                    Ok(bytes) => Kind::Binary(bytes),
                    Err(_) => Kind::UnreadableFile(path),
                }
            }
            "GRAPHQL" => Kind::GraphQl(Box::new(super::graphql::GraphQl::compile(o))),
            "JSON_RPC" => Kind::JsonRpc(Box::new(JsonRpc::compile(&text("method"), canonical::field(o, "paramsSchema").and_then(Value::as_str)))),
            _ => Kind::Unsupported,
        };
        let optional = o.get("optional").and_then(Value::as_bool).unwrap_or(false);
        BodyMatcher { kind, not, optional, exact_case }
    }

    /// How a non-matching body is described in closest-match diagnostics.
    /// `None` for a negated body, which upstream reports without any difference.
    pub fn difference(&self, request: &HttpRequest) -> Option<super::Difference> {
        self.difference_as(request, self.not)
    }

    /// [`Self::difference`] as if the body were negated when `not`, else as its positive matcher.
    fn difference_as(&self, request: &HttpRequest, not: bool) -> Option<super::Difference> {
        if not {
            // `ParameterStringMatcher` matches its parameters with the recording context before applying `not`, so
            // a negated form body that fails still records the comparisons its subset match made.
            if let Kind::Parameters(m) = &self.kind {
                let actual = m.split_values(&request::parse_query(&request.body_str()));
                return m.recorded(&actual, true, super::multimap::MapKind::Parameters).into_iter().next().map(super::Difference::Text);
            }
            return None;
        }
        Some(match &self.kind {
            // `JsonSchemaMatcher` records nothing for an absent body.
            Kind::JsonSchema(..) | Kind::JsonSchemaBlocked(..) if request.body.is_empty() => super::Difference::None,
            // `WasmBodyMatcher` records no difference.
            Kind::Wasm(_) => super::Difference::None,
            Kind::JsonRpc(m) => super::Difference::Text(m.matches(&request.body_str()).1.unwrap_or_default()),
            Kind::GraphQl(m) => super::Difference::Text(m.matches(&request.body_str()).1.unwrap_or_default()),
            Kind::Fuzzy { .. } if request.body.is_empty() => super::Difference::None,
            Kind::Fuzzy { expected, threshold, ignore_case } => {
                let found = request.body_str();
                let normalise = |v: &str| if *ignore_case { v.trim().to_lowercase() } else { v.to_string() };
                let similarity = jaro_winkler(&normalise(expected), &normalise(&found));
                super::Difference::Text(super::format_log_message(
                    1,
                    "fuzzy string match failed similarity:{}below threshold:{}expected:{}found:{}",
                    &[&java_compat::double_to_string(similarity), &java_compat::double_to_string(*threshold), expected, &found],
                ))
            }
            // Only a decoded body's field maps record differences.
            Kind::Multipart { fields, filenames, part_content_types, .. } => match decode_multipart(request.first_header("content-type"), &request.body) {
                None => super::Difference::None,
                Some((f, n, t)) => match self.recorded_maps(request, false).and_then(|texts| texts.into_iter().next()) {
                    Some(first) => super::Difference::Text(first),
                    None if !fields.matches(&f, false) => fields.difference(&f),
                    None if !filenames.matches(&n, false) => filenames.difference(&n),
                    None => part_content_types.difference(&t),
                },
            },
            Kind::AllOf(parts) => match parts.iter().find(|p| !p.matches(request, false)).and_then(|p| p.difference(request)) {
                Some(d) => d,
                None => super::Difference::None,
            },
            Kind::String(expected) => {
                super::Difference::ExactString { expected: expected.clone(), found: request.body_str().into_owned() }
            }
            // `ParameterStringMatcher` always hands `MultiValueMapMatcher` a parameters object, `{ }` when the body is empty.
            Kind::Parameters(m) => m.field_difference(
                &m.split_values(&request::parse_query(&request.body_str())),
                super::multimap::MapKind::PathParameters,
            ),
            Kind::XmlSchema(schema, compiled) => {
                let found = request.body_str();
                super::Difference::Text(if found.trim().is_empty() {
                    let found = if request.body.is_empty() && !request.empty_body_given { "null" } else { &found };
                    super::format_log_message(1, "xml schema match failed expected:{}found:{}failed because xml is null or empty", &[schema, found])
                } else {
                    let because = match compiled {
                        Ok(s) => s.validate(&found).err().unwrap_or_default(),
                        Err(e) => e.message.clone(),
                    };
                    super::format_log_message(1, "xml schema match failed expected:{}found:{}failed because:{}", &[schema, &found, &because])
                })
            }
            // `JsonStringMatcher` given no body fails on the body itself (`matched.equals`) before comparing.
            Kind::Json { expected, written, .. } if request.body.is_empty() => super::Difference::Text(json_exception(&json_text(expected, written), None)),
            // `BodyMatching.bodyMatches` hands it the body `convertToJson` makes (an XML or form body as JSON).
            Kind::Json { expected, strict, written, numeric } => {
                let found = json_matched(request, &[]).unwrap_or_else(|| request.body_str().into_owned());
                let expected_text = json_text(expected, written);
                // The body as received, read (leniently, as `JsonStringMatcher` reads it) when it was matched; an XML or
                // form body as the JSON `convertToJson` printed.
                let parsed = json_body_once(request);
                let read;
                let actual = match (&parsed.value, parsed.as_received) {
                    (Some(actual), true) => actual,
                    (None, true) => return Some(super::Difference::Text(json_exception(&expected_text, Some(&found)))),
                    (_, false) => match serde_json::from_str::<Value>(&found) {
                        Ok(actual) => {
                            read = actual;
                            &read
                        }
                        Err(_) => return Some(super::Difference::Text(json_exception(&expected_text, Some(&found)))),
                    },
                };
                let differences = with_numeric_tolerance(*numeric, || json_unit_differences(expected, actual, *strict));
                super::Difference::Text(if differences.is_empty() {
                    super::format_log_message(1, "json match failed expected:{}found:{}", &[&expected_text, &found])
                } else {
                    let because = differences.join(",\n");
                    super::format_log_message(1, "json match failed expected:{}found:{}failed because:{}", &[&expected_text, &found, &because])
                })
            }
            Kind::SubString(expected) => {
                super::Difference::Text(super::format_log_message(1, "substring match failed expected:{}found:{}", &[expected, &request.body_str()]))
            }
            Kind::Regex(m) => super::Difference::String { expected: m.printed(), found: request.body_str().into_owned() },
            // `JsonPathMatcher` with a path Jayway did not compile.
            Kind::JsonPath(JaywayPath::Uncompiled, _) => {
                let found = json_matched(request, &[]);
                super::Difference::Text(super::format_log_message(
                    1,
                    "json path match failed expected:{}found:{}failed because:{}",
                    &["null", found.as_deref().unwrap_or("null"), "json path matcher was null"],
                ))
            }
            Kind::JsonPath(_, path) => {
                let found = json_matched(request, &[]);
                super::Difference::Text(super::format_log_message(
                    1,
                    "json path match failed expected:{}found:{}failed because:{}",
                    &[path, found.as_deref().unwrap_or("null"), &json_path_failure(path, found.as_deref())],
                ))
            }
            // `JsonPathMatcher` with a date-time: an exception reading the path, else no selected value matched.
            Kind::JsonPathDateTime(path, text, date_time) => {
                let found = json_matched(request, &[]);
                let because = match (path, found.as_deref()) {
                    (JaywayPath::Uncompiled, _) => {
                        return Some(super::Difference::Text(super::format_log_message(
                            1,
                            "json path match failed expected:{}found:{}failed because:{}",
                            &["null", found.as_deref().unwrap_or("null"), "json path matcher was null"],
                        )));
                    }
                    (_, Some(f)) if !f.is_empty() => match crate::json::parse_lenient(f.as_bytes()).map(|d| path.evaluate(&d)) {
                        Ok(Err(because)) => because,
                        _ => format!("no value the json path selected is a date-time {}", date_time.value),
                    },
                    (_, Some(_)) => "json can not be null or empty".to_string(),
                    (_, None) => "json path did not evaluate to truthy".to_string(),
                };
                super::Difference::Text(super::format_log_message(
                    1,
                    "json path match failed expected:{}found:{}failed because:{}",
                    &[text, found.as_deref().unwrap_or("null"), &because],
                ))
            }
            Kind::XPathDateTime(expr, _, date_time) => {
                let found = request.body_str();
                let found = if request.body.is_empty() && !request.empty_body_given { "null" } else { &found };
                super::Difference::Text(super::format_log_message(
                    1,
                    "xpath match failed expected:{}found:{}failed because:{}",
                    &[expr, found, &format!("no node the xpath selected has a date-time {}", date_time.value)],
                ))
            }
            // `JsonSchemaMatcher` records nothing for a blank body.
            Kind::JsonSchema(validator, styles, schema) => match json_matched(request, styles).filter(|f| !f.trim().is_empty()) {
                None => super::Difference::None,
                Some(found) => {
                    // `JsonSchemaValidator.isValid`: read leniently, or the parse failure as `<Exception> - <message>`.
                    let because = match crate::json::parse_lenient(found.as_bytes()) {
                        Ok(instance) => crate::schema::value_report(validator.as_deref(), schema, &instance),
                        Err(_) => super::string::jackson_parse_error(&found),
                    };
                    super::Difference::Text(super::format_log_message(
                        1,
                        "json schema match failed expected:{}found:{}failed because:{}",
                        &[&crate::json::pretty(schema), &found, &because],
                    ))
                }
            },
            // SECURITY: the schema names a blocked remote/file `$ref` — never resolved, so this is
            // upstream's `InvalidSchemaException` text (`JsonSchemaValidator.isValid`), not an instance-level report.
            Kind::JsonSchemaBlocked(schema, styles, uri) => match json_matched(request, styles).filter(|f| !f.trim().is_empty()) {
                None => super::Difference::None,
                Some(found) => super::Difference::Text(super::format_log_message(
                    1,
                    "json schema match failed expected:{}found:{}failed because:{}",
                    &[&crate::json::pretty(schema), &found, &format!("InvalidSchemaException - Schema from '{uri}' is not allowed to be loaded.")],
                )),
            },
            // `XPathMatcher`: an absent body is not evaluated, so it is reported as not truthy.
            // `XPathMatcher` builds no evaluator for a blank expression, nor for one whose prefix its namespaces lack.
            Kind::XPath(expr, _, namespaces) if !xpath_compiles(expr, namespaces) => {
                let found = request.body_str();
                let found = if request.body.is_empty() && !request.empty_body_given { "null" } else { &found };
                super::Difference::Text(super::format_log_message(
                    1,
                    "xpath match failed expected:{}found:{}failed because:{}",
                    &["null", found, "xpath matcher was null"],
                ))
            }
            Kind::XPath(expr, millis, namespaces) => {
                let absent = request.body.is_empty() && !request.empty_body_given;
                let found = request.body_str();
                let found = if absent { "null" } else { &found };
                // `StringToXmlDocumentParser`: the error handler records a fatal error, then the parser throws it.
                if let Some(because) = (!absent).then(|| xpath_parse_error(found, namespaces.is_some())).flatten() {
                    return Some(super::Difference::Text(super::format_log_message(
                        1,
                        "xpath match failed expected:{}found:{}failed because fatal error:{}",
                        &[expr, found, &because],
                    )));
                }
                let falsy = super::format_log_message(1, "xpath match failed expected:{}found:{}failed because:{}", &[expr, found, "xpath did not evaluate to truthy"]);
                // `XPathEvaluator`: a timeout is reported through the error logger at WARNING, then the `false` it
                // returns is not truthy.
                if !absent && xpath_evaluate(expr, found, *millis, namespaces).is_none() {
                    let timed_out = format!("xpath evaluation timed out after {millis}ms for expression: {expr}");
                    let warning = super::format_log_message(1, "xpath match failed expected:{}found:{}failed because warning:{}", &[expr, found, &timed_out]);
                    return Some(super::Difference::Text(format!("{warning}\n{falsy}")));
                }
                super::Difference::Text(falsy)
            }
            // `XmlStringMatcher`: a document that does not parse fails with the parser's message, the expected one
            // first (whatever the body); then an absent body fails XMLUnit's input with an exception whose message
            // is null.
            Kind::Xml(expected, text) => {
                let found = request.body_str();
                let because = match expected {
                    None => xml_parse_error(text),
                    Some(_) if request.body.is_empty() && !request.empty_body_given => Some("null".to_string()),
                    Some(expected) => match XmlNode::parse(&found) {
                        Some(actual) => {
                            xml_difference(expected, &actual, &format!("/{}[1]", expected.name.1), &format!("/{}[1]", actual.name.1))
                        }
                        None => xml_parse_error(&found),
                    },
                };
                match because {
                    Some(because) => super::Difference::Text(super::format_log_message(
                        1,
                        "xml match failed expected:{}found:{}failed because:{}",
                        &[text, if request.body.is_empty() && !request.empty_body_given { "null" } else { &found }, &because],
                    )),
                    None => super::Difference::Other("xml match failed"),
                }
            }
            Kind::Binary(bytes) => super::Difference::Text(super::format_log_message(
                1,
                "binary match failed expected:{}found:{}",
                &[&byte_array_to_string(bytes), &byte_array_to_string(&request.body)],
            )),
            _ => super::Difference::Other("body match failed"),
        })
    }

    /// The differences a non-lenient `MatchDifference` records for a failing body, each as one entry; a JSON matcher
    /// given a body that is not JSON records Jackson's parse failure first.
    pub fn recorded_differences(&self, request: &HttpRequest) -> Vec<String> {
        self.recorded_differences_as(request, self.not)
    }

    /// What a negated body records while it matches: its inner matcher failed, and recorded why before the negation
    /// was applied (`ExactStringMatcher` and its siblings add the difference, then apply `not`). Empty for any other
    /// body, and for a negated body whose inner matcher matched (the body fails without a difference).
    pub fn negated_inner_differences(&self, request: &HttpRequest) -> Vec<String> {
        if !self.not || (self.optional && request.body.is_empty()) || self.matches_positive(request, false) {
            return Vec::new();
        }
        self.recorded_differences_as(request, false)
    }

    fn recorded_differences_as(&self, request: &HttpRequest, not: bool) -> Vec<String> {
        // A body as received is JSON when it was read as JSON when it was matched; an XML or form body is read here.
        let unread = |request: &HttpRequest| {
            let parsed = json_body_once(request);
            if parsed.as_received { parsed.value.is_none() } else { serde_json::from_str::<Value>(&json_matched(request, &[]).unwrap_or_default()).is_err() }
        };
        if let Kind::Json { expected, written, .. } = &self.kind
            && !not
            && (request.body.is_empty() || unread(request))
        {
            // The body `convertToJson` makes: an XML or form body as JSON, an XML one that does not parse as received.
            let found = json_matched(request, &[]).unwrap_or_else(|| request.body_str().into_owned());
            let found = (!request.body.is_empty()).then_some(&*found);
            let expected = json_text(expected, written);
            return vec![
                json_exception(&expected, found),
                super::format_log_message(1, "json match failed expected:{}found:{}", &[&expected, found.unwrap_or("null")]),
            ];
        }
        // `XPathMatcher`: a body the parser rejects records the error handler's fatal error, then the exception.
        if let (Kind::XPath(expr, _, namespaces), false) = (&self.kind, not) {
            let found = request.body_str();
            let present = !request.body.is_empty() || request.empty_body_given;
            let compiled = xpath_compiles(expr, namespaces) && *expr != *found;
            if let Some(because) = (present && compiled).then(|| xpath_parse_error(&found, namespaces.is_some())).flatten() {
                return ["failed because fatal error:{}", "failed because:{}"]
                    .iter()
                    .map(|reason| super::format_log_message(1, &format!("xpath match failed expected:{{}}found:{{}}{reason}"), &[expr, &found, &because]))
                    .collect();
            }
        }
        if let Some(texts) = self.recorded_maps(request, not) {
            return texts;
        }
        self.difference_as(request, not).map(|d| d.log_text()).filter(|t| !t.is_empty()).into_iter().collect()
    }

    /// Whether an XPath body records two differences for `request`: the body does not parse ([`Self::recorded_differences`]).
    pub fn records_parse_failure(&self, request: &HttpRequest) -> bool {
        matches!(self.kind, Kind::XPath(..)) && self.recorded_differences(request).len() > 1
    }

    /// Whether the body is matched by `MultiValueMapMatcher`s ([`Self::recorded_maps`]), whose every comparison a
    /// verification's closest match diff prints.
    pub fn records_maps(&self) -> bool {
        !self.not && matches!(self.kind, Kind::Parameters(_) | Kind::Multipart { .. })
    }

    /// What the `MultiValueMapMatcher`s of a form or multipart body record while they are matched: every comparison
    /// and map failure, a multipart body's maps in turn (fields, filenames, part content types) up to the first that
    /// fails. `None` for a negated body, any other body, or a multipart body that does not decode.
    fn recorded_maps(&self, request: &HttpRequest, not: bool) -> Option<Vec<String>> {
        use super::multimap::MapKind;
        if not {
            return None;
        }
        match &self.kind {
            // `ParameterStringMatcher` always hands `MultiValueMapMatcher` a parameters object, `{ }` when the body is empty.
            Kind::Parameters(m) => Some(m.recorded(&m.split_values(&request::parse_query(&request.body_str())), false, MapKind::PathParameters)),
            Kind::Multipart { fields, filenames, part_content_types, .. } => {
                let (f, n, t) = decode_multipart(request.first_header("content-type"), &request.body)?;
                let mut texts = Vec::new();
                for (matcher, actual) in [(fields, &f), (filenames, &n), (part_content_types, &t)] {
                    let matched = matcher.matches(actual, false);
                    texts.extend(matcher.recorded(actual, matched, MapKind::Parameters));
                    if !matched {
                        break;
                    }
                }
                Some(texts)
            }
            _ => None,
        }
    }

    /// Why the matcher cannot be used (`XmlSchemaMatcher` rejects a schema it cannot read when it is created, and
    /// `FileBodyMaterialiser` a file it cannot read, with `FileBodyException`).
    pub fn load_error(&self) -> Option<String> {
        if let Kind::UnreadableFile(path) = &self.kind {
            return Some(format!("Exception while loading file body \"{path}\""));
        }
        if let Kind::JsonSchemaUnbuilt(message) = &self.kind {
            return Some(message.clone());
        }
        self.unreadable_schema().map(|schema| super::format_log_message(0, "exception parsing schema{}", &[schema]))
    }

    /// Whether [`BodyMatcher::load_error`] is a `JSON_SCHEMA` schema networknt cannot build.
    pub fn schema_unbuilt(&self) -> bool {
        matches!(self.kind, Kind::JsonSchemaUnbuilt(_))
    }

    /// An `IllegalArgumentException` of the body matcher's constructor, answered as a plain 400 (`JSON_SCHEMA` with a
    /// `jsonSchema` string that is neither a JSON document nor a `*.json` path).
    pub fn argument_error(&self) -> Option<&'static str> {
        match &self.kind {
            Kind::JsonSchemaIllegal => Some("Schema must either be a path reference to a *.json file or a json string"),
            Kind::AllOf(parts) => parts.iter().find_map(BodyMatcher::argument_error),
            _ => None,
        }
    }

    /// The XML schema [`BodyMatcher::load_error`] is about.
    pub fn unreadable_schema(&self) -> Option<&str> {
        self.schema_error().map(|(schema, _)| schema)
    }

    /// The XML schema [`BodyMatcher::load_error`] is about, and why it cannot be built.
    pub fn schema_error(&self) -> Option<(&str, &crate::xsd::SchemaError)> {
        match &self.kind {
            Kind::XmlSchema(schema, Err(e)) => Some((schema, e)),
            _ => None,
        }
    }

    /// A `REGEX` body's data-plane `would match` note, as [`BodyMatcher::matches`] evaluates it.
    pub(super) fn note_would_match(&self, request: &HttpRequest) {
        if let Kind::Regex(m) = &self.kind
            && !(self.optional && request.body.is_empty())
        {
            super::string::note_would_match(m, &request.body_str(), self.exact_case);
        }
    }

    pub fn matches(&self, request: &HttpRequest, case_insensitive: bool) -> bool {
        if self.optional && request.body.is_empty() {
            return true;
        }
        self.matches_positive(request, case_insensitive) != self.not
    }

    fn matches_positive(&self, request: &HttpRequest, ci: bool) -> bool {
        // Read as text only by the matchers that compare text: a JSON matcher reads the body parsed once
        // ([`json_body_once`]), and decoding 4 KiB for each of 1,000 of them was a tenth of their cost.
        let body = std::cell::LazyCell::new(|| request.body_str());
        match &self.kind {
            // `ExactStringMatcher.matches`: a blank expected string matches any body.
            Kind::String(expected) => {
                expected.trim().is_empty() || **body == **expected || (ci && body.eq_ignore_ascii_case(expected))
            }
            Kind::SubString(expected) => {
                body.contains(expected.as_str()) || (ci && body.to_lowercase().contains(&expected.to_lowercase()))
            }
            // `BodyMatcherBuilder`: a regex body is case-sensitive only under `matchExactCase` on the data plane
            // (`ci` is the control plane's flag); it is case-insensitive everywhere else.
            Kind::Regex(m) => m.matches(&body, ci || !self.exact_case),
            Kind::Json { expected, strict, numeric, .. } => match &json_body_once(request).value {
                Some(actual) => with_numeric_tolerance(*numeric, || json_matches(expected, actual, *strict)),
                None => false,
            },
            Kind::JsonSchema(validator, styles, schema) if styles.is_empty() => {
                json_body_once(request).value.as_ref().is_some_and(|actual| crate::schema::value_matches(validator.as_deref(), schema, actual))
            }
            Kind::JsonSchema(validator, styles, schema) => {
                json_body(request, styles).is_some_and(|actual| crate::schema::value_matches(validator.as_deref(), schema, &actual))
            }
            // `JsonPathMatcher`: a body equal to a compiled path's text matches unevaluated.
            Kind::JsonPath(path, text) if !matches!(path, JaywayPath::Uncompiled) && !request.body.is_empty() && **text == **body => true,
            Kind::JsonPath(path, _) => json_body_once(request).value.as_ref().is_some_and(|actual| path.matches(actual)),
            Kind::JsonPathDateTime(path, _, date_time) => json_body_once(request).value.as_ref().is_some_and(|actual| json_path_date_time(path, actual, date_time)),
            Kind::XPathDateTime(expr, namespaces, date_time) => {
                !request.body.is_empty() && xpath_node_texts(expr, &body, namespaces).is_some_and(|texts| texts.iter().any(|t| date_time.matches(t, true)))
            }
            // XMLUnit's similarity, as `xml_difference` describes its first difference.
            Kind::Xml(expected, _) => match (expected, XmlNode::parse(&body)) {
                (Some(e), Some(a)) => xml_difference(e, &a, "", "").is_none(),
                _ => false,
            },
            // `XPathMatcher`: no evaluator for a blank expression; a body equal to the expression matches unevaluated.
            Kind::XPath(expr, _, namespaces) if !xpath_compiles(expr, namespaces) => false,
            Kind::XPath(expr, ..) if !request.body.is_empty() && *expr == *body => true,
            Kind::XPath(expr, millis, namespaces) => xpath_evaluate(expr, &body, *millis, namespaces) == Some(true),
            Kind::XmlSchema(_, schema) => !body.trim().is_empty() && schema.as_ref().is_ok_and(|s| s.validate(&body).is_ok()),
            // `ParameterStringMatcher`: styled parameters split (`ExpandedParameterDecoder.splitParameters`) first.
            Kind::Parameters(m) => m.matches(&m.split_values(&request::parse_query(&body)), ci),
            // Either the body as received (a compressed one) or as inflated (`BodyMatching`'s original bytes);
            // `BinaryMatcher` matches any body when it has no bytes.
            Kind::Binary(bytes) => {
                bytes.is_empty() || request.body.as_ref() == bytes.as_slice() || request.original_body.as_deref() == Some(bytes.as_slice())
            }
            Kind::Wasm(module) => crate::wasm::body_matches(module, request),
            Kind::JsonRpc(m) => m.matches(&body).0,
            Kind::GraphQl(m) => m.matches(&body).0,
            Kind::Fuzzy { expected, threshold, ignore_case } => {
                // `FuzzyMatcher` is given null for an absent body, which never meets a threshold.
                expected.trim().is_empty() || !request.body.is_empty() && {
                    let normalise = |v: &str| if *ignore_case { v.trim().to_lowercase() } else { v.to_string() };
                    jaro_winkler(&normalise(expected), &normalise(&body)) >= *threshold
                }
            }
            Kind::Multipart { fields, filenames, part_content_types, blank } => {
                *blank
                    || decode_multipart(request.first_header("content-type"), &request.body).is_some_and(|(f, n, t)| {
                        fields.matches(&f, ci) && filenames.matches(&n, ci) && part_content_types.matches(&t, ci)
                    })
            }
            // The composite's own `not` applies to the conjunction; `optional` components still see the body.
            Kind::AllOf(parts) => parts.iter().all(|p| p.matches(request, ci)),
            // SECURITY: a blocked schema never matches — `JsonSchemaValidator.isValid` throws before
            // any instance-level check runs.
            Kind::JsonSchemaBlocked(..) => false,
            Kind::UnreadableFile(_) | Kind::Unsupported | Kind::JsonSchemaIllegal | Kind::JsonSchemaUnbuilt(_) => false,
        }
    }
}

/// What `JsonStringMatcher` records when comparing throws: Jackson's parse failure for a body that is not JSON, or
/// the `NullPointerException` of `matched.equals` for an absent one (`found` `None`).
fn json_exception(expected: &str, found: Option<&str>) -> String {
    let because = match found {
        None => "java.lang.NullPointerException: Cannot invoke \"String.equals(Object)\" because \"matched\" is null".to_string(),
        Some(found) => {
            let token: String = found.trim_start().chars().take_while(|c| c.is_alphanumeric() || matches!(c, '_' | '$')).collect();
            let column = found.len() - found.trim_start().len() + 1;
            let location = format!("\n at [Source: REDACTED (`StreamReadFeature.INCLUDE_SOURCE_IN_LOCATION` disabled); line: 1, column: {column}]");
            let values = "(JSON String, Number (or 'NaN'/'+INF'/'-INF'), Array, Object or token 'null', 'true' or 'false')";
            match found.trim_start().chars().next() {
                // `_handleOddValue`: a character that cannot start a value or a token (an XML body's `<`).
                Some(c) if token.is_empty() => format!(
                    "shaded_package.com.fasterxml.jackson.core.JsonParseException: Unexpected character ('{c}' (code {})): expected a valid value {values}{location}",
                    c as u32
                ),
                _ => format!("shaded_package.com.fasterxml.jackson.core.JsonParseException: Unrecognized token '{token}': was expecting {values}{location}"),
            }
        }
    };
    super::format_log_message(
        1,
        "exception while perform json match failed expected:{}found:{}failed because:{}",
        &[expected, found.unwrap_or("null"), &because],
    )
}

/// A canonical JSON value read again: a scalar the canonical form keeps as the text it was given (a number holding
/// `"\n  42\n"` or ` "a" `, see `canonical::body`) becomes the value that text holds.
fn json_scalar(v: &Value) -> Value {
    match v {
        Value::Number(n) => crate::json::parse_lenient(n.to_string().as_bytes()).unwrap_or_else(|_| v.clone()),
        other => other.clone(),
    }
}

/// `JsonStringMatcher.matcher` as its differences quote it: the expectation's JSON as written when it was a string,
/// pretty-printed when it was a JSON value.
fn json_text(expected: &Value, written: &Option<String>) -> String {
    written.clone().unwrap_or_else(|| crate::json::pretty(expected))
}

/// `JsonSchemaBodyDecoder.convertToJson` as the text JSON matchers quote: an XML body as the pretty JSON of its
/// `xmlToMap` (or as received when it does not parse), a form body as the pretty JSON object of its parameters,
/// anything else as received; `None` for an absent body.
fn json_matched(request: &HttpRequest, styles: &[(String, String)]) -> Option<String> {
    if request.body.is_empty() {
        return request.empty_body_given.then(String::new);
    }
    let content_type = request.first_header("content-type").unwrap_or_default();
    let body = request.body_str().into_owned();
    if content_type.contains("application/xml") || content_type.contains("text/xml") {
        return Some(xml_to_json(&body).map(|v| crate::json::pretty(&v)).unwrap_or(body));
    }
    if content_type.contains("application/x-www-form-urlencoded") {
        return json_body(request, styles).map(|v| crate::json::pretty(&v));
    }
    Some(body)
}

/// `BinaryArrayFormatter.byteArrayToString`: base64 then hex, each wrapped at 64 characters.
fn byte_array_to_string(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "base64:\n\nhex:\n".to_string();
    }
    let wrap = |s: String| s.as_bytes().chunks(64).map(|c| String::from_utf8_lossy(c).into_owned()).collect::<Vec<_>>().join("\n  ");
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("base64:\n  {}\nhex:\n  {}", wrap(base64::engine::general_purpose::STANDARD.encode(bytes)), wrap(hex))
}

/// A step of a definite Jayway path: a property, several properties of one object (last step only), an array
/// index, or a function of the value reached (last step only).
#[derive(Debug, Clone)]
pub enum PathToken {
    Property(String),
    Properties(Vec<String>),
    Index(i64),
    /// A path function (`.min()`, `.index(1)`) and its literal arguments.
    Function(String, Vec<String>),
}

/// The steps of a definite Jayway path (`$`, then `.name`, `['name']`, `['a','b']`, `[n]` and a closing function
/// such as `.min()`); `None` for any other path. A `[` closing the path is dropped, as Jayway's compiler drops it.
fn definite_path(path: &str) -> Option<Vec<PathToken>> {
    let trimmed = path.trim();
    let chars: Vec<char> = trimmed.strip_suffix('[').filter(|p| p.len() > 1).unwrap_or(trimmed).chars().collect();
    if chars.first() != Some(&'$') {
        return None;
    }
    let mut tokens = Vec::new();
    let mut i = 1;
    while i < chars.len() {
        // Only a function may follow a multi-property step, and nothing may follow a function.
        let closing_function = || {
            let name_end = chars[i..].iter().skip(1).position(|c| !(c.is_alphanumeric() || *c == '_')).map(|p| i + 1 + p);
            chars[i] == '.' && name_end.is_some_and(|e| e > i + 1 && function_arguments(&chars[e..]).is_some())
        };
        if matches!(tokens.last(), Some(PathToken::Function(..))) || (matches!(tokens.last(), Some(PathToken::Properties(_))) && !closing_function()) {
            return None;
        }
        match chars[i] {
            '.' => {
                let start = i + 1;
                let mut j = start;
                while j < chars.len() && (chars[j].is_alphanumeric() || matches!(chars[j], '_' | '-' | '$')) {
                    j += 1;
                }
                if j == start {
                    return None;
                }
                let name: String = chars[start..j].iter().collect();
                if let Some(args) = function_arguments(&chars[j..]) {
                    tokens.push(PathToken::Function(name, args));
                    i = chars.len();
                    continue;
                }
                tokens.push(PathToken::Property(name));
                i = j;
            }
            '[' => {
                let close = i + chars[i..].iter().position(|c| *c == ']')?;
                let inner: String = chars[i + 1..close].iter().collect::<String>().trim().to_string();
                let names: Option<Vec<String>> = inner
                    .split(',')
                    .map(|part| {
                        let part = part.trim();
                        let quoted = part.len() >= 2 && ((part.starts_with('\'') && part.ends_with('\'')) || (part.starts_with('"') && part.ends_with('"')));
                        (quoted && !part[1..part.len() - 1].contains(['\'', '"'])).then(|| part[1..part.len() - 1].to_string())
                    })
                    .collect();
                match names {
                    Some(mut names) if names.len() == 1 => tokens.push(PathToken::Property(names.remove(0))),
                    Some(names) => tokens.push(PathToken::Properties(names)),
                    None => tokens.push(PathToken::Index(inner.parse::<i64>().ok()?)),
                }
                i = close + 1;
            }
            _ => return None,
        }
    }
    Some(tokens)
}

/// The literal arguments of a function call closing a path (`(1, 'x')`), `None` when `rest` is not one.
fn function_arguments(rest: &[char]) -> Option<Vec<String>> {
    let inner: String = rest.strip_prefix(&['('])?.strip_suffix(&[')'])?.iter().collect();
    if inner.contains(['(', ')']) {
        return None;
    }
    Some(inner.split(',').map(|a| a.trim().to_string()).filter(|a| !a.is_empty()).collect())
}

/// A definite path as Jayway's `PathToken`s print it: `$['a'][0]`.
fn render_path(tokens: &[PathToken]) -> String {
    format!("${}", render_tokens(tokens))
}

/// Path tokens as Jayway prints a token and those after it: `['a'][0].min()`, `.index(...)` for a call with arguments.
fn render_tokens(tokens: &[PathToken]) -> String {
    let mut out = String::new();
    for t in tokens {
        match t {
            PathToken::Property(p) => out.push_str(&format!("['{p}']")),
            PathToken::Properties(p) => out.push_str(&format!("['{}']", p.join("','"))),
            PathToken::Index(n) => out.push_str(&format!("[{n}]")),
            PathToken::Function(f, args) if args.is_empty() => out.push_str(&format!(".{f}()")),
            PathToken::Function(f, _) => out.push_str(&format!(".{f}(...)")),
        }
    }
    out
}

/// `JsonPath.read` of a definite path: the value it reads (`None` for a function of a value it does not apply to,
/// which reads as null), or the message of the `PathNotFoundException` it throws.
fn read_definite(tokens: &[PathToken], document: &Value) -> Result<Option<Value>, String> {
    let mut current = document;
    for (n, token) in tokens.iter().enumerate() {
        let leaf = n == tokens.len() - 1;
        let not_an_object = |property: String, current: &Value| {
            format!(
                "Expected to find an object with property {property} in path {} but found '{}'. This is not a json object according to the JsonProvider: 'shaded_package.com.jayway.jsonpath.spi.json.JsonSmartJsonProvider'.",
                render_path(&tokens[..n]),
                json_smart_class(current)
            )
        };
        match token {
            PathToken::Property(name) => {
                let Value::Object(o) = current else { return Err(not_an_object(format!("['{name}']"), current)) };
                match o.get(name) {
                    Some(v) => current = v,
                    None if leaf => return Err(format!("No results for path: {}", render_path(tokens))),
                    None => return Err(format!("Missing property in path {}", render_path(&tokens[..=n]))),
                }
            }
            // A missing leaf property is left out of the map read.
            PathToken::Properties(names) => {
                let Value::Object(o) = current else { return Err(not_an_object(format!("['{}']", names.join("','")), current)) };
                let read = Value::Object(names.iter().filter_map(|name| o.get(name).map(|v| (name.clone(), v.clone()))).collect());
                return match tokens.get(n + 1) {
                    Some(PathToken::Function(name, args)) => apply_function(name, args, &read, &[]),
                    _ => Ok(Some(read)),
                };
            }
            PathToken::Index(i) => {
                let items = match current {
                    Value::Array(items) => items,
                    Value::Null => return Err(format!("The path {} is null", render_path(&tokens[..n]))),
                    other => {
                        return Err(format!("Filter: {} can only be applied to arrays. Current context is: {}", render_tokens(&tokens[n..]), java_to_string(other)))
                    }
                };
                let at = if *i < 0 { items.len() as i64 + i } else { *i };
                match usize::try_from(at).ok().and_then(|at| items.get(at)) {
                    Some(v) => current = v,
                    None => return Err(format!("No results for path: {}", render_path(tokens))),
                }
            }
            PathToken::Function(name, args) => return apply_function(name, args, current, &[]),
        }
    }
    Ok(Some(current.clone()))
}

/// The definite steps an indefinite path starts with (`$.a` of `$.a[*].b`).
fn definite_head(prefix: &str) -> Vec<PathToken> {
    let boundaries = prefix.char_indices().filter(|(i, c)| *i > 0 && matches!(c, '.' | '[')).map(|(i, _)| i);
    boundaries.take_while(|i| definite_path(&prefix[..*i]).is_some()).last().and_then(|i| definite_path(&prefix[..i])).unwrap_or_default()
}

/// Reads the definite steps of a longer path: a missing property is not the path's leaf.
fn read_definite_steps(head: &[PathToken], document: &Value) -> Result<(), String> {
    let mut steps = head.to_vec();
    // A placeholder last step, so that every head step reads as a step before the leaf.
    steps.push(PathToken::Function("length".to_string(), Vec::new()));
    read_definite(&steps, document).map(|_| ())
}

const EMPTY_AGGREGATION: &str = "Aggregation function attempted to calculate value using empty array";

/// Jayway's `PathFunction.invoke` of the function `name` on `model`: what it returns (`None` for null) or the message
/// of what it throws. `parameters` are values read by a path given as the parameter (`$..a.sum()`, compiled as
/// `$.sum($..a)`), each an array of what that path read; literal `args` follow them.
fn apply_function(name: &str, args: &[String], model: &Value, parameters: &[Value]) -> Result<Option<Value>, String> {
    let literal = |a: &String| match a.parse::<serde_json::Number>() {
        Ok(n) => Value::Number(n),
        Err(_) => Value::String(a.trim_matches(['\'', '"']).to_string()),
    };
    let parameters: Vec<Value> = parameters.iter().cloned().chain(args.iter().map(literal)).collect();
    // `Parameter.consume`: the items of an array parameter, or a single value.
    let consumed = || parameters.iter().flat_map(|p| match p {
        Value::Array(items) => items.clone(),
        other => vec![other.clone()],
    });
    match name {
        "length" | "size" if !parameters.is_empty() && args.is_empty() => Ok(Some(Value::from(consumed().count()))),
        "length" | "size" => Ok(match model {
            Value::Array(items) => Some(Value::from(items.len())),
            Value::Object(o) => Some(Value::from(o.len())),
            _ => None,
        }),
        "min" | "max" | "avg" | "stddev" | "sum" => {
            let own = match model {
                Value::Array(items) => items.clone(),
                _ => Vec::new(),
            };
            let numbers: Vec<f64> = own.into_iter().chain(consumed()).filter_map(|v| v.as_f64()).collect();
            if numbers.is_empty() {
                return Err(EMPTY_AGGREGATION.to_string());
            }
            let count = numbers.len() as f64;
            let sum: f64 = numbers.iter().sum();
            let value = match name {
                "min" => numbers.iter().cloned().fold(f64::INFINITY, f64::min),
                "max" => numbers.iter().cloned().fold(f64::NEG_INFINITY, f64::max),
                "avg" => sum / count,
                "stddev" => (numbers.iter().map(|x| x * x).sum::<f64>() / count - (sum / count).powi(2)).sqrt(),
                _ => sum,
            };
            Ok(Some(serde_json::Number::from_f64(value).map_or(Value::Null, Value::Number)))
        }
        "keys" => Ok(match model {
            Value::Object(o) => Some(Value::Array(o.keys().cloned().map(Value::String).collect())),
            _ => None,
        }),
        // `AbstractSequenceAggregation`: a negative index counts from the end, but one reaching the first item throws.
        "first" | "last" | "index" => {
            let Value::Array(items) = model else { return Err(EMPTY_AGGREGATION.to_string()) };
            let target = match name {
                "first" => 0,
                "last" => -1,
                _ => match args.first().and_then(|a| a.parse::<i64>().ok()) {
                    Some(i) => i,
                    None => return Err("Index 0 out of bounds for length 0".to_string()),
                },
            };
            let len = items.len() as i64;
            if target >= 0 {
                return items.get(target as usize).cloned().map(Some).ok_or_else(|| format!("Index {target} out of bounds for length {len}"));
            }
            match len + target {
                real if real > 0 => Ok(Some(items[real as usize].clone())),
                _ => Err(format!("Target index:{target} larger than object count:{len}")),
            }
        }
        "concat" => Ok(Some(Value::String(String::new()))),
        "append" => Ok(match model {
            Value::Array(items) => Some(Value::Array(items.iter().cloned().chain(parameters.iter().cloned()).collect())),
            Value::Null => Some(Value::Array(parameters.clone())),
            other => Some(other.clone()),
        }),
        _ => Err(format!("Function with name: {name} does not exist.")),
    }
}

/// `JsonPathMatcher`'s truthiness of what a path read: not null, and not an empty collection.
fn json_path_truthy(read: &Value) -> bool {
    !read.is_null() && !matches!(read, Value::Array(items) if items.is_empty())
}

/// `toString()` of what json-smart reads, in Jayway's mode: objects are `LinkedHashMap`s (`{k=v, …}`), arrays
/// `JSONArray`s (their compact JSON).
fn java_to_string(v: &Value) -> String {
    match v {
        Value::Object(o) => format!("{{{}}}", o.iter().map(|(k, v)| format!("{k}={}", java_to_string(v))).collect::<Vec<_>>().join(", ")),
        Value::Array(_) => serde_json::to_string(v).unwrap_or_default(),
        Value::String(s) => s.clone(),
        Value::Number(n) if n.is_f64() => java_compat::double_to_string(n.as_f64().unwrap_or_default()),
        other => other.to_string(),
    }
}

/// Why `JsonPathMatcher` failed for `found` (the body as the JSON matchers see it, `None` when absent): the
/// `PathNotFoundException` Jayway throws while reading a definite path, otherwise that the path did not evaluate
/// to a truthy value.
fn json_path_failure(path: &str, found: Option<&str>) -> String {
    const NOT_TRUTHY: &str = "json path did not evaluate to truthy";
    let Some(found) = found else { return NOT_TRUTHY.to_string() };
    // `JsonPath.parse` refuses an empty document before json-smart reads it.
    if found.is_empty() {
        return "json can not be null or empty".to_string();
    }
    // json-smart, in Jayway's permissive mode, reads a bare word as a string.
    let document = crate::json::parse_lenient(found.as_bytes()).unwrap_or_else(|_| Value::String(found.trim().to_string()));
    match JaywayPath::compile(path).evaluate(&document) {
        Err(because) => because,
        Ok(_) => NOT_TRUTHY.to_string(),
    }
}

/// The class json-smart reads a JSON value as.
fn json_smart_class(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "java.lang.Boolean",
        Value::String(_) => "java.lang.String",
        Value::Array(_) => "shaded_package.net.minidev.json.JSONArray",
        Value::Object(_) => "shaded_package.net.minidev.json.JSONObject",
        Value::Number(n) if n.as_i64().is_some_and(|i| i32::try_from(i).is_ok()) => "java.lang.Integer",
        Value::Number(n) if n.as_i64().is_some() => "java.lang.Long",
        Value::Number(n) if n.is_u64() => "java.math.BigInteger",
        Value::Number(_) => "java.lang.Double",
    }
}

/// Why XMLUnit's document builder rejects `xml` (namespace-aware, DOCTYPE declarations disallowed), in Xerces'
/// words; `None` when the reason is not known.
fn xml_parse_error(xml: &str) -> Option<String> {
    if xml.strip_prefix('\u{feff}').unwrap_or(xml).trim_matches([' ', '\t', '\n', '\r']).is_empty() {
        return Some("Premature end of file.".to_string());
    }
    if xml.contains("<!DOCTYPE") {
        return Some("DOCTYPE is disallowed when the feature \"http://apache.org/xml/features/disallow-doctype-decl\" set to true.".to_string());
    }
    crate::xsd::well_formedness_error(xml)
}

/// An element's name as XMLUnit quotes a missing child: `QName.toString()`, `{namespace}local`.
fn xml_qname(n: &XmlNode) -> String {
    match &n.name.0 {
        Some(ns) => format!("{{{ns}}}{}", n.name.1),
        None => n.name.1.clone(),
    }
}

/// The first difference XMLUnit's `Diff.toString()` describes for two documents compared as `XmlStringMatcher`
/// configures it (comments stripped, whitespace normalised, child nodes paired by `DefaultNodeMatcher` with
/// `ElementSelectors.byName`, similar differences such as child order, namespace prefixes and CDATA accepted), with
/// `DefaultComparisonFormatter`'s wording. `None` when the documents are similar, which is when the matcher matches.
fn xml_difference(expected: &XmlNode, actual: &XmlNode, expected_path: &str, actual_path: &str) -> Option<String> {
    // Nodes are paired by name (the document element too), so a differently named element is a missing child.
    if expected.name != actual.name {
        return Some(format!("Expected child '{}' but was 'null' - comparing {} at {expected_path} to <NULL>", xml_qname(expected), xml_short(expected)));
    }
    xml_element_difference(expected, actual, expected_path, actual_path)
}

mod simple_date_format;

/// What XMLUnit's `PlaceholderDifferenceEvaluator` (xmlunit-placeholders 2.14) makes of a difference whose expected
/// value is `control` and actual value `test` (`None`: no such text or attribute): `None` when `control` holds no
/// known placeholder (the difference stands), else whether the placeholder accepts `test`, or the reason a thrown
/// exception gives (XMLUnit wraps whatever a `DifferenceEvaluator` throws).
fn xml_placeholder(control: &str, test: Option<&str>) -> Option<Result<bool, String>> {
    const S: &str = r"[ \t\n\x0B\x0C\r]";
    const THROWN: &str = "Caught exception during comparison";
    static PLACEHOLDER: std::sync::LazyLock<regex::Regex> =
        std::sync::LazyLock::new(|| regex::Regex::new(&format!(r"({S}*\$\{{{S}*xmlunit\.(.+){S}*\}}{S}*)")).expect("valid"));
    static ARGS: std::sync::LazyLock<regex::Regex> =
        std::sync::LazyLock::new(|| regex::Regex::new(&format!(r"((.*){S}*\((.+){S}*\){S}*)")).expect("valid"));
    let java_trim = |s: &str| s.trim_matches(|c: char| c <= ' ').to_string();
    let found = PLACEHOLDER.captures(control)?;
    let content = java_trim(&found[2]);
    let (keyword, args) = match ARGS.captures(&content) {
        // `String.split(",")`, which drops trailing empty strings.
        Some(a) => {
            let mut args = a[3].split(',').map(str::to_string).collect::<Vec<_>>();
            while args.last().is_some_and(String::is_empty) {
                args.pop();
            }
            (java_trim(&a[2]), args)
        }
        None => (content.clone(), Vec::new()),
    };
    if !matches!(keyword.as_str(), "ignore" | "isNumber" | "matchesRegex" | "isDateTime") {
        return None;
    }
    if java_trim(&found[1]) != java_trim(control) {
        // "The placeholder must exclusively occupy the text node."
        return Some(Err(THROWN.to_string()));
    }
    Some(match keyword.as_str() {
        "ignore" => Ok(true),
        "isDateTime" => simple_date_format::is_date_time(test, &args).map_err(|()| THROWN.to_string()),
        "isNumber" => {
            static NUMBER: std::sync::LazyLock<regex::Regex> =
                std::sync::LazyLock::new(|| regex::Regex::new(r"^[-+]?[0-9]*\.?[0-9]+([eE][-+]?[0-9]+)?$").expect("valid"));
            Ok(test.is_some_and(|t| NUMBER.is_match(&java_trim(t))))
        }
        _ => match args.first().filter(|a| !a.is_empty()) {
            None => Ok(false),
            Some(pattern) => match super::java_pattern::compile(&java_trim(pattern)) {
                Ok(pattern) => Ok(test.is_some_and(|t| pattern.find(&java_trim(t)))),
                Err(_) => Err(THROWN.to_string()),
            },
        },
    })
}

fn xml_short(n: &XmlNode) -> String {
    format!("<{}...>", n.name.1)
}

/// `DOMDifferenceEngine.compareNodes` of two elements of the same name: child node count, attributes, then the
/// paired children in the expected document's order, then the expected children left unpaired.
fn xml_element_difference(expected: &XmlNode, actual: &XmlNode, expected_path: &str, actual_path: &str) -> Option<String> {
    let describe = |what: &str, e: &str, a: &str, en: String, ep: &str, an: String, ap: &str| {
        format!("Expected {what} '{e}' but was '{a}' - comparing {en} at {ep} to {an} at {ap}")
    };
    // A placeholder that accepts a missing value (`${xmlunit.ignore}`) makes a missing text node or attribute equal.
    let accepts_missing = |control: &str| match xml_placeholder(control, None) {
        Some(Ok(accepted)) => Ok(accepted),
        Some(Err(thrown)) => Err(thrown),
        None => Ok(false),
    };
    if expected.items.len() != actual.items.len() {
        let accepted = match (expected.items.as_slice(), actual.items.is_empty()) {
            ([XmlItem::Text(t)], true) => accepts_missing(t),
            _ => Ok(false),
        };
        match accepted {
            Err(thrown) => return Some(thrown),
            Ok(true) => {}
            Ok(false) => {
                let (e, a) = (expected.items.len().to_string(), actual.items.len().to_string());
                return Some(describe("child nodelist length", &e, &a, xml_short(expected), expected_path, xml_short(actual), actual_path));
            }
        }
    }
    if expected.attributes.len() != actual.attributes.len() {
        // `evaluateAttributeListLengthConsideringPlaceholders`: every expected attribute the actual element lacks
        // accepts a missing value, and every actual attribute is an expected one.
        let mut matched = 0;
        let mut accepted = Ok(true);
        for attribute in &expected.attributes {
            if actual.attributes.iter().any(|a| a.name == attribute.name) {
                matched += 1;
            } else {
                accepted = accepts_missing(&attribute.value);
                if accepted != Ok(true) {
                    break;
                }
            }
        }
        match accepted {
            Err(thrown) => return Some(thrown),
            Ok(true) if matched == actual.attributes.len() => {}
            _ => {
                let (e, a) = (expected.attributes.len().to_string(), actual.attributes.len().to_string());
                return Some(describe("number of attributes", &e, &a, xml_short(expected), expected_path, xml_short(actual), actual_path));
            }
        }
    }
    for attribute in &expected.attributes {
        let attribute_path = format!("{expected_path}/@{}", attribute.name.1);
        match actual.attributes.iter().find(|a| a.name == attribute.name) {
            None => match accepts_missing(&attribute.value) {
                Ok(true) => {}
                Err(thrown) => return Some(thrown),
                Ok(false) => {
                    return Some(format!(
                        "Expected attribute name '{attribute_path}' - comparing {} at {attribute_path} to {} at {actual_path}",
                        xml_short(expected),
                        xml_short(actual)
                    ))
                }
            },
            Some(found) if found.value != attribute.value => {
                match xml_placeholder(&attribute.value, Some(&found.value)) {
                    Some(Ok(true)) => continue,
                    Some(Err(thrown)) => return Some(thrown),
                    _ => {}
                }
                let node = |a: &XmlAttribute| format!("<{} {}=\"{}\"...>", expected.name.1, a.qualified, a.value);
                let found_path = format!("{actual_path}/@{}", found.name.1);
                return Some(describe("attribute value", &attribute.value, &found.value, node(attribute), &attribute_path, node(found), &found_path));
            }
            Some(_) => {}
        }
    }
    // An actual attribute the expected element lacks (reachable once a placeholder accepted a missing one).
    if let Some(extra) = actual.attributes.iter().find(|a| !expected.attributes.iter().any(|e| e.name == a.name)) {
        return Some(format!(
            "Expected attribute name '{expected_path}' - comparing {} at {expected_path} to {} at {actual_path}/@{}",
            xml_short(expected),
            xml_short(actual),
            extra.name.1
        ));
    }
    // The XPath of each child: elements by name and position among same-named siblings, text nodes and processing
    // instructions by position among their kind.
    let child_path = |n: &XmlNode, path: &str, i: usize| {
        let same = |a: &XmlItem, b: &XmlItem| match (a, b) {
            (XmlItem::Element(x), XmlItem::Element(y)) => x.name.1 == y.name.1,
            (XmlItem::Text(_), XmlItem::Text(_)) | (XmlItem::Instruction(..), XmlItem::Instruction(..)) => true,
            _ => false,
        };
        let position = n.items[..=i].iter().filter(|c| same(c, &n.items[i])).count();
        match &n.items[i] {
            XmlItem::Element(e) => format!("{path}/{}[{position}]", e.name.1),
            XmlItem::Text(_) => format!("{path}/text()[{position}]"),
            XmlItem::Instruction(..) => format!("{path}/processing-instruction()[{position}]"),
        }
    };
    // `DefaultNodeMatcher.match`: each expected child takes the first free compatible node after the last one paired,
    // wrapping around.
    let compatible = |a: &XmlItem, b: &XmlItem| match (a, b) {
        (XmlItem::Element(x), XmlItem::Element(y)) => x.name == y.name,
        (XmlItem::Text(_), XmlItem::Text(_)) | (XmlItem::Instruction(..), XmlItem::Instruction(..)) => true,
        _ => false,
    };
    let mut used = vec![false; actual.items.len()];
    let mut last: Option<usize> = None;
    let mut pairs = Vec::new();
    let mut unpaired = Vec::new();
    for (i, item) in expected.items.iter().enumerate() {
        let start = last.map_or(0, |l| l + 1);
        let found = (start..actual.items.len()).chain(0..last.unwrap_or(0)).find(|j| !used[*j] && compatible(item, &actual.items[*j]));
        match found {
            Some(j) => {
                used[j] = true;
                last = Some(j);
                pairs.push((i, j));
            }
            None => unpaired.push(i),
        }
    }
    for (i, j) in pairs {
        let (ep, ap) = (child_path(expected, expected_path, i), child_path(actual, actual_path, j));
        let difference = match (&expected.items[i], &actual.items[j]) {
            (XmlItem::Element(e), XmlItem::Element(a)) => xml_element_difference(e, a, &ep, &ap),
            (XmlItem::Text(e), XmlItem::Text(a)) if e != a => match xml_placeholder(e, Some(a)) {
                Some(Ok(true)) => None,
                Some(Err(thrown)) => Some(thrown),
                _ => {
                    let node = |t: &str| format!("<{} ...>{t}</{}>", expected.name.1, expected.name.1);
                    Some(describe("text value", e, a, node(e), &ep, node(a), &ap))
                }
            },
            (XmlItem::Instruction(et, ed), XmlItem::Instruction(at, ad)) => {
                let node = |t: &str, d: &str| format!("<?{t} {d}?>");
                if et != at {
                    Some(describe("processing instruction target", et, at, node(et, ed), &ep, node(at, ad), &ap))
                } else if ed != ad {
                    Some(describe("processing instruction data", ed, ad, node(et, ed), &ep, node(at, ad), &ap))
                } else {
                    None
                }
            }
            _ => None,
        };
        if difference.is_some() {
            return difference;
        }
    }
    // `cantFindControlTextChildInTest`: an unpaired text child is evaluated as a placeholder against no text.
    let mut unpaired = unpaired.into_iter();
    let first = loop {
        let Some(i) = unpaired.next() else { break None };
        if let XmlItem::Text(t) = &expected.items[i] {
            match accepts_missing(t) {
                Ok(true) => continue,
                Err(thrown) => return Some(thrown),
                Ok(false) => {}
            }
        }
        break Some(i);
    };
    first.map(|i| {
        let path = child_path(expected, expected_path, i);
        let (name, node) = match &expected.items[i] {
            XmlItem::Element(e) => (xml_qname(e), xml_short(e)),
            XmlItem::Text(t) => ("#text".to_string(), format!("<{} ...>{t}</{}>", expected.name.1, expected.name.1)),
            XmlItem::Instruction(t, d) => (t.clone(), format!("<?{t} {d}?>")),
        };
        format!("Expected child '{name}' but was 'null' - comparing {node} at {path} to <NULL>")
    })
}

/// `MultipartFormDataDecoder.decode`: each part's value by name, then the file names and content types of file
/// parts; `None` when the body is not `multipart/form-data` or cannot be read.
fn decode_multipart(content_type: Option<&str>, body: &[u8]) -> Option<(request::MultiMap, request::MultiMap, request::MultiMap)> {
    let add = |map: &mut request::MultiMap, key: &str, value: String| match map.iter_mut().find(|(k, _)| k == key) {
        Some((_, values)) => values.push(value),
        None => map.push((key.to_string(), vec![value])),
    };
    let (mut fields, mut filenames, mut types) = (Vec::new(), Vec::new(), Vec::new());
    for part in multipart_parts(content_type, body)? {
        add(&mut fields, &part.name, String::from_utf8_lossy(&part.bytes).into_owned());
        if let Some(filename) = part.filename {
            add(&mut filenames, &part.name, filename);
            add(&mut types, &part.name, part.content_type.unwrap_or_default());
        }
    }
    Some((fields, filenames, types))
}

/// One part of a `multipart/form-data` body (`MultipartFormDataDecoder.DecodedPart`).
pub struct MultipartPart {
    pub name: String,
    /// Set for a file part.
    pub filename: Option<String>,
    /// A file part's `Content-Type` without its parameters (Netty's default binary type when it declared none);
    /// `None` for a plain field.
    pub content_type: Option<String>,
    /// The `charset` its `Content-Type` named.
    pub charset: Option<String>,
    pub bytes: Vec<u8>,
}

/// The parts of a `multipart/form-data` body in body order; `None` when it is not one or cannot be read.
pub fn multipart_parts(content_type: Option<&str>, body: &[u8]) -> Option<Vec<MultipartPart>> {
    let content_type = content_type.filter(|c| c.to_lowercase().contains("multipart/form-data"))?;
    let boundary = content_type
        .split(';')
        .map(str::trim)
        .find_map(|p| p.split_once('=').filter(|(k, _)| k.trim().eq_ignore_ascii_case("boundary")).map(|(_, v)| v.trim().trim_matches('"').to_string()))?;
    let delimiter = format!("--{boundary}").into_bytes();
    let find = |haystack: &[u8], from: usize| haystack[from..].windows(delimiter.len()).position(|w| w == delimiter.as_slice()).map(|p| p + from);
    let mut parts = Vec::new();
    let mut at = find(body, 0)? + delimiter.len();
    loop {
        if body[at..].starts_with(b"--") {
            break;
        }
        let start = at + body[at..].iter().position(|b| *b == b'\n')? + 1;
        let end = find(body, start)?;
        let part = &body[start..end];
        let part = part.strip_suffix(b"\r\n").or_else(|| part.strip_suffix(b"\n")).unwrap_or(part);
        let split = part.windows(4).position(|w| w == b"\r\n\r\n").map(|p| (p, 4)).or_else(|| part.windows(2).position(|w| w == b"\n\n").map(|p| (p, 2)))?;
        let head = String::from_utf8_lossy(&part[..split.0]).into_owned();
        let content = &part[split.0 + split.1..];
        let (mut name, mut filename, mut part_type, mut charset) = (None, None, None, None);
        for line in head.lines() {
            let Some((header, value)) = line.split_once(':') else { continue };
            if header.trim().eq_ignore_ascii_case("content-disposition") {
                for param in value.split(';').map(str::trim) {
                    if let Some((k, v)) = param.split_once('=') {
                        let v = v.trim().trim_matches('"').to_string();
                        match k.trim().to_ascii_lowercase().as_str() {
                            "name" => name = Some(v),
                            "filename" => filename = Some(v),
                            _ => {}
                        }
                    }
                }
            } else if header.trim().eq_ignore_ascii_case("content-type") {
                let mut params = value.split(';');
                part_type = Some(params.next().unwrap_or_default().trim().to_string());
                charset = params.filter_map(|p| p.split_once('=')).find(|(k, _)| k.trim().eq_ignore_ascii_case("charset")).map(|(_, v)| v.trim().trim_matches('"').to_string());
            }
        }
        let name = name?;
        // Netty gives a file part without a `Content-Type` the default binary type.
        let content_type = filename.as_ref().map(|_| part_type.unwrap_or_else(|| "application/octet-stream".into()));
        parts.push(MultipartPart { name, filename, content_type, charset, bytes: content.to_vec() });
        at = end + delimiter.len();
    }
    Some(parts)
}

/// `StringSimilarity.jaroWinkler`: Jaro similarity plus the common-prefix bonus (scale 0.1, at most 4 characters).
fn jaro_winkler(a: &str, b: &str) -> f64 {
    let (a, b): (Vec<char>, Vec<char>) = (a.chars().collect(), b.chars().collect());
    if a == b {
        return 1.0;
    }
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let distance = (a.len().max(b.len()) / 2).saturating_sub(1);
    let (mut a_matches, mut b_matches) = (vec![false; a.len()], vec![false; b.len()]);
    let mut matches = 0usize;
    for i in 0..a.len() {
        let (start, end) = (i.saturating_sub(distance), (i + distance + 1).min(b.len()));
        for j in start..end {
            if b_matches[j] || a[i] != b[j] {
                continue;
            }
            a_matches[i] = true;
            b_matches[j] = true;
            matches += 1;
            break;
        }
    }
    if matches == 0 {
        return 0.0;
    }
    let (mut transpositions, mut k) = (0usize, 0usize);
    for i in 0..a.len() {
        if !a_matches[i] {
            continue;
        }
        while !b_matches[k] {
            k += 1;
        }
        if a[i] != b[k] {
            transpositions += 1;
        }
        k += 1;
    }
    let m = matches as f64;
    let jaro = (m / a.len() as f64 + m / b.len() as f64 + (m - transpositions as f64 / 2.0) / m) / 3.0;
    let prefix = a.iter().zip(&b).take(4).take_while(|(x, y)| x == y).count();
    jaro + prefix as f64 * 0.1 * (1.0 - jaro)
}

/// `JsonRpcMatcher`.
#[derive(Debug)]
struct JsonRpc {
    method: String,
    /// `Pattern.compile(method)`, matched with `matches()`, unless the method is a plain name (`[a-zA-Z0-9_/.-]+`)
    /// or `Pattern` refuses it.
    pattern: Option<std::sync::Arc<super::java_pattern::JavaRegex>>,
    /// The Java replay of `pattern`, under `regexMatchingTimeoutMillis` (`matchesWithRegexTimeout`).
    java: Option<super::string::DescribedRegex>,
    params_schema: Option<String>,
    params: Option<jsonschema::Validator>,
}

impl JsonRpc {
    fn compile(method: &str, params_schema: Option<&str>) -> JsonRpc {
        let literal = method.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '/' | '.' | '-'));
        let pattern = (!method.trim().is_empty() && !literal).then(|| super::java_pattern::compile(method).ok()).flatten();
        let java = pattern.as_ref().map(|_| super::string::DescribedRegex::compile("json-rpc method", method));
        let params_schema = params_schema.filter(|s| !s.trim().is_empty()).map(str::to_string);
        let params = params_schema.as_deref().and_then(|s| serde_json::from_str::<Value>(s).ok()).and_then(|s| super::string::validator(&s).ok());
        JsonRpc { method: method.to_string(), pattern, java, params_schema, params }
    }

    /// Whether the body matches, and the difference recorded when it does not.
    fn matches(&self, body: &str) -> (bool, Option<String>) {
        let failed = |args: &[&str]| Some(super::format_log_message(1, "json-rpc match failed expected method:{}found:{}failed because:{}", args));
        if self.method.trim().is_empty() {
            return (false, failed(&["null", body, "method was null"]));
        }
        if body.trim().is_empty() {
            return (false, failed(&[&self.method, "null", "request body was empty"]));
        }
        // `OBJECT_MAPPER.readTree` (a plain `ObjectMapper`): Jackson's exception text on failure.
        let root = match crate::jnode::read_value_plain(body) {
            Ok(root) => root,
            Err(e) => return (false, failed(&[&self.method, body, &e])),
        };
        let mut schema_failure = None;
        match &root {
            Value::Array(batch) => {
                if batch.iter().any(|r| self.single(r, &mut schema_failure)) {
                    return (true, None);
                }
                let batch_failed = super::format_log_message(1, "json-rpc batch match failed expected method:{}found:{}failed because:{}", &[&self.method, body, "no request in batch matched method"]);
                (false, Some(schema_failure.map_or(batch_failed.clone(), |s| format!("{s}\n{batch_failed}"))))
            }
            single => {
                if self.single(single, &mut schema_failure) {
                    return (true, None);
                }
                let failed = failed(&[&self.method, body, "method did not match or invalid JSON-RPC format"]).unwrap_or_default();
                (false, Some(schema_failure.map_or(failed.clone(), |s| format!("{s}\n{failed}"))))
            }
        }
    }

    fn single(&self, request: &Value, schema_failure: &mut Option<String>) -> bool {
        let text = |v: &Value| v.as_str().map_or_else(|| v.to_string(), str::to_string);
        if request.get("jsonrpc").map(text).as_deref() != Some("2.0") {
            return false;
        }
        let Some(method) = request.get("method").map(text) else { return false };
        let method_matches = method == self.method || {
            let linear = || self.pattern.as_ref().is_some_and(|p| p.matches(&method));
            self.java.as_ref().map_or_else(linear, |j| j.within_budget(&method, linear))
        };
        if !method_matches {
            return false;
        }
        if let Some(validator) = &self.params {
            let Some(params) = request.get("params") else { return false };
            if !validator.is_valid(params) {
                let because = validator.iter_errors(params).map(|e| e.to_string()).collect::<Vec<_>>().join("\n");
                *schema_failure = Some(super::format_log_message(
                    1,
                    "json-rpc params schema validation failed expected:{}found:{}failed because:{}",
                    &[self.params_schema.as_deref().unwrap_or_default(), &params.to_string(), &because],
                ));
                return false;
            }
        }
        true
    }
}

/// The body a JSON matcher sees (`JsonSchemaBodyDecoder.convertToJson`): a form body becomes an object of its
/// parameters (styled ones split first), each value typed as upstream's `toJsonObject` guesses.
fn json_body(request: &HttpRequest, styles: &[(String, String)]) -> Option<Value> {
    let content_type = request.first_header("content-type").unwrap_or_default();
    // `JsonSchemaBodyDecoder.convertToJson`: an XML body is matched as the JSON `xmlToMap` makes of it, or, when it
    // does not parse, as the body itself.
    if content_type.contains("application/xml") || content_type.contains("text/xml") {
        let body = request.body_str();
        return xml_to_json(&body).or_else(|| serde_json::from_str::<Value>(&body).ok());
    }
    let form = content_type.contains("application/x-www-form-urlencoded");
    if !form {
        // Decoded with the request's charset (a UTF-16 JSON body).
        // `JsonSchemaValidator.isValid` reads the instance with the lenient mapper (unquoted field names, single
        // quotes, comments …), the one that reports the parse failure when there is one.
        return crate::json::parse_lenient(request.body_str().as_bytes()).ok();
    }
    Some(form_json(request, styles))
}

/// [`json_body`] without parameter styles, read once for all the matchers one request meets: a request is matched
/// against every expectation in turn, and reading its body again for each JSON matcher among 1,000 cost 47 ms.
/// `as_received`: the body is neither XML nor a form, so `value` is the body itself read as JSON.
struct JsonBody {
    value: Option<Value>,
    as_received: bool,
}

/// The last body [`json_body_once`] read on this thread, with what it was read from: the request's
/// `Content-Type`, its body kind and its body, which [`json_body`] depends on alone. Holding the body keeps its
/// bytes where they are, so another body at the same address and of the same length is the same bytes.
struct ReadBody {
    content_type: Option<String>,
    kind: request::BodyKind,
    body: bytes::Bytes,
    json: std::rc::Rc<JsonBody>,
}

thread_local! {
    static READ_BODY: std::cell::RefCell<Option<ReadBody>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
thread_local! {
    /// How many bodies [`read_json_body`] has read on this thread.
    static BODIES_READ: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// [`json_body`] of `request` without parameter styles, remembered per thread for the next matcher that reads the
/// same body: the request's own body is recognised by its address (comparing 4 KiB of bytes for each of 1,000
/// matchers cost a fifth of a request), an equal body elsewhere (the next request posting the same document) by its
/// bytes. A body of [`crate::blocking::LARGE_BODY`] or more (matched off the workers) is read each time, so a
/// thread holds at most one body below it, which the event log holds too while it keeps the request.
fn json_body_once(request: &HttpRequest) -> std::rc::Rc<JsonBody> {
    if request.body.len() >= crate::blocking::LARGE_BODY {
        return std::rc::Rc::new(read_json_body(request));
    }
    let content_type = request.first_header("content-type");
    let remembered = READ_BODY.with_borrow_mut(|read| {
        let read = read.as_mut().filter(|r| r.kind == request.body_kind && r.content_type.as_deref() == content_type)?;
        let held = read.body.as_ptr() == request.body.as_ptr() && read.body.len() == request.body.len();
        if !held {
            if read.body != request.body {
                return None;
            }
            read.body = request.body.clone();
        }
        Some(read.json.clone())
    });
    if let Some(json) = remembered {
        return json;
    }
    let json = std::rc::Rc::new(read_json_body(request));
    READ_BODY.with_borrow_mut(|read| {
        *read = Some(ReadBody { content_type: content_type.map(str::to_string), kind: request.body_kind, body: request.body.clone(), json: json.clone() });
    });
    json
}

/// [`json_body`] without parameter styles, telling whether it is the body as received.
fn read_json_body(request: &HttpRequest) -> JsonBody {
    #[cfg(test)]
    BODIES_READ.with(|n| n.set(n.get() + 1));
    let content_type = request.first_header("content-type").unwrap_or_default();
    let xml = content_type.contains("application/xml") || content_type.contains("text/xml");
    let form = content_type.contains("application/x-www-form-urlencoded");
    JsonBody { value: json_body(request, &[]), as_received: !xml && !form }
}

/// [`json_body`] of a form body: an object of its parameters.
fn form_json(request: &HttpRequest, styles: &[(String, String)]) -> Value {
    let mut object = serde_json::Map::new();
    for (name, values) in request::parse_query(&request.body_str()) {
        let values = match styles.iter().find(|(k, _)| *k == name).and_then(|(_, style)| super::multimap::style_delimiter(style, &name)) {
            Some(delimiter) => super::multimap::split_on_delimiter(&delimiter, &values),
            None => values,
        };
        let value = match values.as_slice() {
            [] => Value::Null,
            [one] => typed(one),
            many => Value::Array(many.iter().map(|v| typed(v)).collect()),
        };
        object.insert(name, value);
    }
    Value::Object(object)
}

/// `JsonSchemaBodyDecoder.convertXmlToJson`: `xmlToMap` of the document's first child; `None` when the body does not
/// parse (a DTD is refused, as the hardened `DocumentBuilder` refuses it).
fn xml_to_json(body: &str) -> Option<Value> {
    let doc = roxmltree::Document::parse(body).ok()?;
    Some(doc.root().first_child().map(xml_to_map).unwrap_or(Value::Null))
}

/// `JsonSchemaBodyDecoder.xmlToMap`: child nodes that have children of their own become members named by their
/// qualified name (repeated names collect into an array); failing any, the value of the last text child. Empty
/// elements, attributes, comments and CDATA sections are dropped.
fn xml_to_map(node: roxmltree::Node) -> Value {
    let mut members: Vec<(String, Value)> = Vec::new();
    let mut content = Value::Null;
    for item in node.children() {
        if item.has_children() {
            let name = qualified_name(item);
            let value = xml_to_map(item);
            match members.iter_mut().find(|(k, _)| *k == name) {
                Some((_, Value::Array(list))) => list.push(value),
                Some((_, existing)) => *existing = Value::Array(vec![existing.take(), value]),
                None => members.push((name, value)),
            }
        } else if item.is_text() && !is_cdata(item) {
            content = typed(item.text().unwrap_or_default().trim());
        }
    }
    if members.is_empty() { content } else { Value::Object(members.into_iter().collect()) }
}

/// `Node.getNodeName`: the prefix as written, then the local name.
fn qualified_name(node: roxmltree::Node) -> String {
    let tag = node.tag_name();
    match tag.namespace().and_then(|ns| node.lookup_prefix(ns)).filter(|p| !p.is_empty()) {
        Some(prefix) => format!("{prefix}:{}", tag.name()),
        None => tag.name().to_string(),
    }
}

/// A CDATA section is its own DOM node type, not a text node; roxmltree folds it into a text node.
fn is_cdata(node: roxmltree::Node) -> bool {
    node.document().input_text()[node.range()].starts_with("<![CDATA[")
}

/// `JsonSchemaBodyDecoder.toJsonObject(String)`.
fn typed(value: &str) -> Value {
    let trimmed = value.trim();
    if value.eq_ignore_ascii_case("null") {
        return Value::Null;
    }
    if trimmed.eq_ignore_ascii_case("false") || trimmed.eq_ignore_ascii_case("true") {
        return Value::Bool(trimmed.eq_ignore_ascii_case("true"));
    }
    if let Ok(n) = trimmed.parse::<i64>() {
        return Value::from(n);
    }
    if let Some(n) = java_double(trimmed).and_then(serde_json::Number::from_f64) {
        return Value::Number(n);
    }
    Value::String(trimmed.to_string())
}

/// `Double.parseDouble` for finite decimal values (with an optional `d`/`f` suffix).
fn java_double(text: &str) -> Option<f64> {
    let digits = text.strip_suffix(['d', 'D', 'f', 'F']).unwrap_or(text);
    if digits.chars().any(|c| c.is_ascii_alphabetic() && c != 'e' && c != 'E') {
        return None;
    }
    digits.parse::<f64>().ok().filter(|n| n.is_finite())
}

const PLACEHOLDER: &str = "${json-unit.";

/// JSONUnit comparison: `ONLY_MATCHING_FIELDS` ignores extra fields, extra array items and array order; `STRICT`
/// ignores nothing. Numbers compare as Jackson reads them (see [`numbers_match`]).
///
/// The differences JSONUnit 6.2.0's `Diff` reports to `JsonStringMatcher.Difference`, in its order:
/// missing object keys, then extra ones (`STRICT` only), each sorted, then the common keys sorted and compared in
/// turn; arrays element by element (`STRICT`) or through `ComparisonMatrix` (ignoring order). A missing element has
/// no actual path, so it reads `missing element at "null"`.
fn json_unit_differences(expected: &Value, actual: &Value, strict: bool) -> Vec<String> {
    let mut out = Vec::new();
    json_unit_compare(expected, actual, "", strict, &mut out);
    out
}

fn json_unit_field(path: &str, key: &str) -> String {
    if path.is_empty() { key.to_string() } else { format!("{path}.{key}") }
}

fn json_unit_missing(out: &mut Vec<String>) {
    out.push("missing element at \"null\"".to_string());
}

fn json_unit_extra(out: &mut Vec<String>, path: &str, actual: &Value) {
    out.push(format!("additional element at \"{path}\" with value: {}", crate::json::pretty(actual)));
}

fn json_unit_different(out: &mut Vec<String>, path: &str, expected: &Value, actual: &Value) {
    out.push(format!("wrong value at \"{path}\", expected: {} but was: {}", crate::json::pretty(expected), crate::json::pretty(actual)));
}

/// `Diff.compareNodes`, reporting only what the difference listener hears.
fn json_unit_compare(expected: &Value, actual: &Value, path: &str, strict: bool, out: &mut Vec<String>) {
    if let Value::String(s) = expected && let Some(placeholder) = s.strip_prefix(PLACEHOLDER) {
        let ok = if placeholder == "missing-or-null}" { actual.is_null() } else { placeholder_matches(placeholder, actual) };
        if !ok {
            json_unit_different(out, path, expected, actual);
        }
        return;
    }
    if std::mem::discriminant(expected) != std::mem::discriminant(actual) {
        json_unit_different(out, path, expected, actual);
        return;
    }
    match (expected, actual) {
        (Value::Object(e), Value::Object(a)) => {
            let skipped = |v: &Value| matches!(v.as_str(), Some("${json-unit.ignore-element}" | "${json-unit.missing-or-null}"));
            let mut missing: Vec<&String> = e.iter().filter(|(k, v)| !a.contains_key(*k) && !skipped(v)).map(|(k, _)| k).collect();
            missing.sort();
            missing.iter().for_each(|_| json_unit_missing(out));
            if strict {
                let mut extra: Vec<&String> = a.keys().filter(|k| !e.contains_key(*k)).collect();
                extra.sort();
                for k in extra {
                    json_unit_extra(out, &json_unit_field(path, k), &a[k]);
                }
            }
            let mut common: Vec<&String> = e.keys().filter(|k| a.contains_key(*k)).collect();
            common.sort();
            for k in common {
                json_unit_compare(&e[k], &a[k], &json_unit_field(path, k), strict, out);
            }
        }
        (Value::Array(e), Value::Array(a)) if strict => {
            (a.len()..e.len()).for_each(|_| json_unit_missing(out));
            for (i, v) in a.iter().enumerate().skip(e.len()) {
                json_unit_extra(out, &format!("{path}[{i}]"), v);
            }
            for (i, (ev, av)) in e.iter().zip(a).enumerate() {
                json_unit_compare(ev, av, &format!("{path}[{i}]"), strict, out);
            }
        }
        (Value::Array(e), Value::Array(a)) => {
            let matrix = ComparisonMatrix::new(e, a).compare();
            let (missing, extra) = (matrix.missing(), matrix.extra);
            if e.len() == a.len() && missing.len() == 1 && extra.len() == 1 {
                json_unit_compare(&e[missing[0]], &a[extra[0]], &format!("{path}[{}]", extra[0]), strict, out);
            } else {
                missing.iter().for_each(|_| json_unit_missing(out));
            }
        }
        (Value::Number(e), Value::Number(a)) => {
            if !numbers_match(&e.to_string(), &a.to_string()) {
                json_unit_different(out, path, expected, actual);
            }
        }
        _ => {
            if expected != actual {
                json_unit_different(out, path, expected, actual);
            }
        }
    }
}

/// JSONUnit's `ComparisonMatrix`: pairs expected and actual array elements, ignoring order, and leaves the expected
/// elements nothing matched (missing) and the actual elements that matched nothing (extra), by index.
#[derive(Clone)]
struct ComparisonMatrix {
    /// `equal[actual]`: the expected indices that element is similar to.
    equal: Vec<Vec<usize>>,
    compare_from: usize,
    /// `matches[expected]`: the actual index it was paired with.
    matches: Vec<Option<usize>>,
    extra: Vec<usize>,
    matched: Vec<bool>,
}

impl ComparisonMatrix {
    fn new(expected: &[Value], actual: &[Value]) -> ComparisonMatrix {
        let equal = actual.iter().map(|a| (0..expected.len()).filter(|&j| json_matches(&expected[j], a, false)).collect()).collect();
        ComparisonMatrix { equal, compare_from: 0, matches: vec![None; expected.len()], extra: Vec::new(), matched: vec![false; actual.len()] }
    }

    fn compare(mut self) -> ComparisonMatrix {
        self.simple_matching();
        for i in self.compare_from..self.equal.len() {
            if self.matched[i] {
                continue;
            }
            let matches = self.equal[i].clone();
            match matches.len() {
                0 => self.extra.push(i),
                1 => self.record(i, matches[0]),
                _ => {
                    // comparison is not transitive ([1, 2] == [2] == [2, 3]), so every pairing is tried
                    for &m in &matches {
                        let mut copy = self.clone();
                        copy.compare_from = i + 1;
                        copy.record(i, m);
                        let copy = copy.compare();
                        if copy.extra.is_empty() && copy.missing().is_empty() {
                            return copy;
                        }
                    }
                    self.record(i, matches[0]);
                }
            }
        }
        self
    }

    fn simple_matching(&mut self) {
        for i in 0..self.equal.len() {
            if self.matched[i] || self.equal[i].is_empty() {
                continue;
            }
            let equal_to = self.equal[i].clone();
            let equivalent: Vec<usize> = (0..self.equal.len()).filter(|&k| !self.matched[k] && self.equal[k] == equal_to).collect();
            if equal_to.len() == equivalent.len() {
                for (j, &k) in equivalent.iter().enumerate() {
                    self.record(k, equal_to[j]);
                }
            } else if equivalent.len() > 1 && equal_to.len() > 1 {
                let mut only = equal_to.clone();
                for k in 0..self.equal.len() {
                    if !self.matched[k] && !equivalent.contains(&k) {
                        only.retain(|n| !self.equal[k].contains(n));
                    }
                }
                for j in 0..equivalent.len().min(only.len()) {
                    self.record(equivalent[j], equal_to[j]);
                }
            }
        }
    }

    fn record(&mut self, actual: usize, expected: usize) {
        self.matches[expected] = Some(actual);
        for i in 0..self.equal.len() {
            if !self.matched[i] {
                self.equal[i].retain(|&n| n != expected);
            }
        }
        self.matched[actual] = true;
    }

    fn missing(&self) -> Vec<usize> {
        (0..self.matches.len()).filter(|&i| self.matches[i].is_none()).collect()
    }
}

fn json_matches(expected: &Value, actual: &Value, strict: bool) -> bool {
    if let Value::String(s) = expected && let Some(placeholder) = s.strip_prefix(PLACEHOLDER) {
        return placeholder_matches(placeholder, actual);
    }
    match (expected, actual) {
        (Value::Object(e), Value::Object(a)) => object_matches(e, a, strict),
        (Value::Array(e), Value::Array(a)) => {
            if strict {
                e.len() == a.len() && e.iter().zip(a).all(|(e, a)| json_matches(e, a, true))
            } else {
                array_contains_all(e, a)
            }
        }
        (Value::Number(e), Value::Number(a)) => numbers_match(&e.to_string(), &a.to_string()),
        _ => expected == actual,
    }
}

thread_local! {
    static NUMERIC_TOLERANCE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Runs a JSON comparison (synchronous) with `matchNumbersAsStrings` applied to every [`numbers_match`] inside it.
fn with_numeric_tolerance<R>(numeric: bool, f: impl FnOnce() -> R) -> R {
    let previous = NUMERIC_TOLERANCE.with(|c| c.replace(numeric));
    let result = f();
    NUMERIC_TOLERANCE.with(|c| c.set(previous));
    result
}

/// A number as Jackson reads it, as an exact decimal (`DecimalNode`/`BigIntegerNode.decimalValue()`): an integer
/// exactly, one with a fraction or exponent through a double (`BigDecimal.valueOf(double)`). The sign, the
/// significant digits and the power of ten of the last one; zero is `(false, "", 0)`. `None` when it is not finite.
fn jackson_decimal(text: &str) -> Option<(bool, String, i64)> {
    let text = if text.contains(['.', 'e', 'E']) {
        let value: f64 = text.parse().ok()?;
        if !value.is_finite() {
            return None;
        }
        format!("{value:e}")
    } else {
        text.to_string()
    };
    let (mantissa, exponent) = match text.split_once(['e', 'E']) {
        Some((m, e)) => (m, e.parse::<i64>().ok()?),
        None => (text.as_str(), 0),
    };
    let (negative, mantissa) = match mantissa.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, mantissa.strip_prefix('+').unwrap_or(mantissa)),
    };
    let (whole, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    let digits = format!("{whole}{fraction}");
    let mut exponent = exponent - fraction.len() as i64;
    let trimmed = digits.trim_start_matches('0');
    let significant = trimmed.trim_end_matches('0');
    if significant.is_empty() {
        return Some((false, String::new(), 0));
    }
    exponent += (trimmed.len() - significant.len()) as i64;
    Some((negative, significant.to_string(), exponent))
}

/// Jackson reads a number with a fraction or exponent as a double and any other as an integer, and the two kinds
/// never match each other (`1.0` ≠ `1`); doubles compare by value (`12.50` = `12.5`), integers exactly. Under
/// `matchNumbersAsStrings` (JSONUnit's zero tolerance) any two numbers of equal value match (`1` = `1.0` = `1E0`),
/// the double read through its `double` value (scenario `json_body_match_numbers_as_strings`); a number still never
/// matches a string.
fn numbers_match(expected: &str, actual: &str) -> bool {
    if NUMERIC_TOLERANCE.with(std::cell::Cell::get) {
        return match (jackson_decimal(expected), jackson_decimal(actual)) {
            (Some(e), Some(a)) => e == a,
            _ => expected == actual,
        };
    }
    let is_double = |n: &str| n.contains(['.', 'e', 'E']);
    match (is_double(expected), is_double(actual)) {
        (true, true) => match (expected.parse::<f64>(), actual.parse::<f64>()) {
            (Ok(e), Ok(a)) => e == a,
            _ => expected == actual,
        },
        (false, false) => expected == actual || (expected.trim_start_matches('-') == "0" && actual.trim_start_matches('-') == "0"),
        _ => false,
    }
}

fn object_matches(e: &Map<String, Value>, a: &Map<String, Value>, strict: bool) -> bool {
    if strict && e.len() != a.len() {
        return false;
    }
    e.iter().all(|(k, ev)| match a.get(k) {
        Some(av) => json_matches(ev, av, strict),
        None => ev.as_str().is_some_and(|s| s == "${json-unit.ignore}" || s == "${json-unit.ignore-element}"),
    })
}

/// Each expected item must match a distinct actual item, in any order.
fn array_contains_all(expected: &[Value], actual: &[Value]) -> bool {
    let mut used = vec![false; actual.len()];
    fn assign(i: usize, expected: &[Value], actual: &[Value], used: &mut [bool]) -> bool {
        if i == expected.len() {
            return true;
        }
        for j in 0..actual.len() {
            if !used[j] && json_matches(&expected[i], &actual[j], false) {
                used[j] = true;
                if assign(i + 1, expected, actual, used) {
                    return true;
                }
                used[j] = false;
            }
        }
        false
    }
    expected.len() <= actual.len() && assign(0, expected, actual, &mut used)
}

fn placeholder_matches(placeholder: &str, actual: &Value) -> bool {
    let name = placeholder.trim_end_matches('}');
    if let Some(regex) = placeholder.strip_prefix("regex}") {
        return actual.as_str().is_some_and(|s| StringMatcher::fixed_value(regex).matches(s, false));
    }
    match name {
        "ignore" | "ignore-element" | "any" => true,
        "any-string" => actual.is_string(),
        "any-number" => actual.is_number(),
        "any-boolean" => actual.is_boolean(),
        "any-object" => actual.is_object(),
        "any-array" => actual.is_array(),
        _ => false,
    }
}

/// An XML element as XMLUnit compares it once `XmlStringMatcher`'s sources are prepared: each text, CDATA, attribute
/// and processing-instruction value whitespace-normalised (`xml_normalise`), empty text dropped, then comments
/// stripped, which joins the texts on either side of one.
#[derive(Debug, PartialEq)]
struct XmlNode {
    name: (Option<String>, String),
    /// Sorted by qualified name, as a DOM `NamedNodeMap` lists them.
    attributes: Vec<XmlAttribute>,
    items: Vec<XmlItem>,
}

#[derive(Debug, PartialEq)]
struct XmlAttribute {
    /// Namespace and local name, which XMLUnit pairs attributes by.
    name: (Option<String>, String),
    qualified: String,
    value: String,
}

/// A child node: an element, a text node or a processing instruction (target and data).
#[derive(Debug, PartialEq)]
enum XmlItem {
    Element(XmlNode),
    Text(String),
    Instruction(String, String),
}

impl XmlNode {
    fn parse(text: &str) -> Option<XmlNode> {
        let doc = roxmltree::Document::parse(text.trim()).ok()?;
        Some(Self::from_node(doc.root_element()))
    }

    fn from_node(n: roxmltree::Node) -> XmlNode {
        let mut attributes: Vec<XmlAttribute> = n
            .attributes()
            .map(|a| {
                let prefix = a.namespace().and_then(|ns| n.lookup_prefix(ns)).filter(|p| !p.is_empty());
                XmlAttribute {
                    name: (a.namespace().map(str::to_string), a.name().to_string()),
                    qualified: prefix.map_or_else(|| a.name().to_string(), |p| format!("{p}:{}", a.name())),
                    value: xml_normalise(a.value()),
                }
            })
            .collect();
        attributes.sort_by(|a, b| a.qualified.cmp(&b.qualified));
        let mut items = Vec::new();
        // Each DOM text or CDATA node is trimmed and normalised on its own; comments go afterwards, which joins
        // the normalised texts on either side of one.
        let mut text = String::new();
        let flush = |text: &mut String, items: &mut Vec<XmlItem>| {
            if !text.is_empty() {
                items.push(XmlItem::Text(std::mem::take(text)));
            }
        };
        for c in n.children() {
            match c.node_type() {
                roxmltree::NodeType::Text => {
                    for segment in xml_text_segments(c) {
                        text.push_str(&xml_normalise(&segment));
                    }
                }
                roxmltree::NodeType::Element => {
                    flush(&mut text, &mut items);
                    items.push(XmlItem::Element(Self::from_node(c)));
                }
                roxmltree::NodeType::PI => {
                    flush(&mut text, &mut items);
                    if let Some(pi) = c.pi() {
                        items.push(XmlItem::Instruction(pi.target.to_string(), xml_normalise(pi.value.unwrap_or_default())));
                    }
                }
                _ => {}
            }
        }
        flush(&mut text, &mut items);
        XmlNode { name: (n.tag_name().namespace().map(str::to_string), n.tag_name().name().to_string()), attributes, items }
    }
}

/// What `DiffBuilder.ignoreWhitespace().normalizeWhitespace()` leaves of a text, CDATA, attribute or
/// processing-instruction value: `String.trim()` (every char up to U+0020), then `Nodes.normalize`, which turns each
/// run of `Character.isWhitespace` chars into one space without trimming again. Java's whitespace is not Unicode's:
/// the no-break spaces (U+00A0, U+2007, U+202F) and U+0085 are not whitespace, U+001C..U+001F are.
fn xml_normalise(value: &str) -> String {
    let is_java_whitespace = |c: char| {
        matches!(c, '\t'..='\r' | '\u{1c}'..='\u{20}' | '\u{1680}' | '\u{2000}'..='\u{2006}' | '\u{2008}'..='\u{200a}'
            | '\u{2028}' | '\u{2029}' | '\u{205f}' | '\u{3000}')
    };
    let mut out = String::with_capacity(value.len());
    let mut last_was_whitespace = false;
    for c in value.trim_matches(|c: char| c <= ' ').chars() {
        if is_java_whitespace(c) {
            if !last_was_whitespace {
                out.push(' ');
            }
            last_was_whitespace = true;
        } else {
            out.push(c);
            last_was_whitespace = false;
        }
    }
    out
}

/// The DOM text and CDATA nodes a roxmltree text node merges, in order: a DOM parser keeps a CDATA section apart
/// from the text around it, and XMLUnit trims each on its own. Read back from the source; when the source does not
/// decode to the merged text (an entity declared in a DTD), the merged text as one node.
fn xml_text_segments(node: roxmltree::Node) -> Vec<String> {
    let merged = node.text().unwrap_or_default();
    let source = node.document().input_text();
    let start = node.range().start;
    let end = match node.next_sibling() {
        Some(next) => next.range().start,
        None => node.parent().map_or(source.len(), |p| source[..p.range().end].rfind("</").unwrap_or(p.range().end)),
    };
    let Some(raw) = source.get(start..end).filter(|_| start <= end) else { return vec![merged.to_string()] };
    let mut segments = Vec::new();
    let mut rest = raw;
    while !rest.is_empty() {
        let (text, cdata) = match rest.find("<![CDATA[") {
            Some(open) => {
                let body = &rest[open + 9..];
                let Some(close) = body.find("]]>") else { return vec![merged.to_string()] };
                let cdata = body[..close].replace("\r\n", "\n").replace('\r', "\n");
                let text = &rest[..open];
                rest = &body[close + 3..];
                (text, Some(cdata))
            }
            None => (std::mem::take(&mut rest), None),
        };
        if !text.is_empty() {
            match xml_decode_text(text) {
                Some(decoded) => segments.push(decoded),
                None => return vec![merged.to_string()],
            }
        }
        segments.extend(cdata);
    }
    if segments.concat() == merged { segments } else { vec![merged.to_string()] }
}

/// Character data with the predefined entities and character references resolved and line ends normalised; `None`
/// for anything else (an entity a DTD declares).
fn xml_decode_text(raw: &str) -> Option<String> {
    let raw = raw.replace("\r\n", "\n").replace('\r', "\n");
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw.as_str();
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        let semi = rest[amp..].find(';')? + amp;
        let name = &rest[amp + 1..semi];
        out.push(match name {
            "lt" => '<',
            "gt" => '>',
            "amp" => '&',
            "apos" => '\'',
            "quot" => '"',
            _ => {
                let code = match name.strip_prefix("#x") {
                    Some(hex) => u32::from_str_radix(hex, 16).ok()?,
                    None => name.strip_prefix('#')?.parse().ok()?,
                };
                char::from_u32(code)?
            }
        });
        rest = &rest[semi + 1..];
    }
    out.push_str(rest);
    Some(out)
}

thread_local! {
    static XPATH_TIMEOUT_MILLIS: std::cell::Cell<i64> = const { std::cell::Cell::new(5000) };
}

/// Runs `f` (synchronous) with `xpathMatchingTimeoutMillis` = `millis` for the XPath matchers it compiles
/// (`XPathEvaluator` takes the server's configuration when it is built); elsewhere the default 5000 applies.
pub fn with_xpath_timeout<R>(millis: i64, f: impl FnOnce() -> R) -> R {
    let previous = XPATH_TIMEOUT_MILLIS.with(|c| c.replace(millis));
    let result = f();
    XPATH_TIMEOUT_MILLIS.with(|c| c.set(previous));
    result
}

/// Recent (expression, document, budget) evaluations that outlived their budget, so the re-evaluations of one
/// request (its difference, the closest expectation, the hint) cost the budget once.
static XPATH_TIMED_OUT: std::sync::LazyLock<parking_lot::Mutex<std::collections::VecDeque<(String, String, i64)>>> =
    std::sync::LazyLock::new(Default::default);

/// `XPathEvaluator.evaluateXPathExpression` under `MatchingTimeoutExecutor.callWithTimeout`: the truthiness of `expr`
/// over `body`, or `None` when the evaluation outlives `millis` (0 or less: no timeout). As upstream, a timed-out
/// evaluation is abandoned, not stopped: its thread finishes on its own.
fn xpath_evaluate(expr: &str, body: &str, millis: i64, namespaces: &XPathNamespaces) -> Option<bool> {
    if millis <= 0 {
        return Some(xpath_matches(expr, body, namespaces));
    }
    if XPATH_TIMED_OUT.lock().iter().any(|(e, b, m)| e == expr && b == body && *m >= millis) {
        return None;
    }
    let (sender, receiver) = std::sync::mpsc::channel();
    let (e, b, n) = (expr.to_string(), body.to_string(), namespaces.clone());
    let spawned = std::thread::Builder::new().name("xpath-eval".into()).spawn(move || {
        let _ = sender.send(xpath_matches(&e, &b, &n));
    });
    if spawned.is_err() {
        return Some(xpath_matches(expr, body, namespaces));
    }
    match receiver.recv_timeout(std::time::Duration::from_millis(millis as u64)) {
        Ok(result) => Some(result),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Some(false),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            let mut timed_out = XPATH_TIMED_OUT.lock();
            if timed_out.len() >= 16 {
                timed_out.pop_front();
            }
            timed_out.push_back((expr.to_string(), body.to_string(), millis));
            None
        }
    }
}

/// An XPath matcher's `namespacePrefixes` (prefix, namespace): `None` when it has none, and then `XPathEvaluator`
/// parses the body namespace-unaware.
type XPathNamespaces = Option<Vec<(String, String)>>;

/// The prefixes of the qualified names in an XPath expression (`bar:content`, `child::bar:*`), string literals and
/// axis separators aside.
fn xpath_prefixes(expr: &str) -> Vec<&str> {
    static QNAME: std::sync::LazyLock<regex::Regex> =
        std::sync::LazyLock::new(|| regex::Regex::new(r#"'[^']*'|"[^"]*"|([A-Za-z_][\w.\-]*):([A-Za-z_*])"#).expect("valid"));
    QNAME.captures_iter(expr).filter_map(|c| c.get(1).map(|m| m.as_str())).collect()
}

/// Whether `XPathEvaluator` compiles `expr`: not blank, and with namespaces every prefix it names is one of them (an
/// unknown prefix resolves to no namespace, which the JDK's compiler rejects).
fn xpath_compiles(expr: &str, namespaces: &XPathNamespaces) -> bool {
    !expr.trim().is_empty()
        && namespaces.as_ref().is_none_or(|ns| xpath_prefixes(expr).iter().all(|p| ns.iter().any(|(k, v)| k == p && !v.is_empty())))
}

/// The body as `XPathEvaluator` reads it: namespace-unaware, an unbound prefix is no error, so each one is bound
/// (to a namespace nothing sees, the document being read without namespaces) before parsing.
fn xpath_document(body: &str, aware: bool) -> std::borrow::Cow<'_, str> {
    let mut text = std::borrow::Cow::Borrowed(body);
    if aware {
        return text;
    }
    for _ in 0..32 {
        let Err(roxmltree::Error::UnknownNamespace(prefix, _)) = roxmltree::Document::parse(&text) else { break };
        // after the document element's name
        let Some(start) = text.match_indices('<').map(|(i, _)| i).find(|&i| !matches!(text.as_bytes().get(i + 1), Some(b'?' | b'!'))) else {
            break;
        };
        let end = text[start + 1..].find(|c: char| c.is_whitespace() || c == '>' || c == '/').map_or(text.len(), |e| start + 1 + e);
        let mut bound = text.into_owned();
        bound.insert_str(end, &format!(" xmlns:{prefix}=\"urn:mock-server:unbound\""));
        text = std::borrow::Cow::Owned(bound);
    }
    text
}

/// Why Xerces' document builder (DOCTYPE declarations disallowed, namespace-aware only with `aware`) rejects `body`.
fn xpath_parse_error(body: &str, aware: bool) -> Option<String> {
    xml_parse_error(&xpath_document(body, aware))
}

/// `local-name()` over a namespace-unaware DOM, whose element and attribute names are their qualified names: the part
/// after the prefix, as Xalan's `DOM2DTM.getLocalName` takes it.
struct UnawareLocalName;

impl sxd_xpath::function::Function for UnawareLocalName {
    fn evaluate<'c, 'd>(
        &self,
        context: &sxd_xpath::context::Evaluation<'c, 'd>,
        args: Vec<sxd_xpath::Value<'d>>,
    ) -> Result<sxd_xpath::Value<'d>, sxd_xpath::function::Error> {
        let node = match args.as_slice() {
            [] => Some(context.node),
            [sxd_xpath::Value::Nodeset(nodes)] => nodes.document_order_first(),
            [other] => return Err(sxd_xpath::function::Error::ArgumentNotANodeset { actual: other.into() }),
            _ => return Err(sxd_xpath::function::Error::TooManyArguments { expected: 1, actual: args.len() }),
        };
        let name = node.and_then(|n| n.expanded_name()).map(|q| q.local_part()).unwrap_or("");
        Ok(sxd_xpath::Value::String(name.rsplit(':').next().unwrap_or(name).to_string()))
    }
}

/// An element's or attribute's qualified name.
fn qualified(prefix: Option<&str>, local: &str) -> String {
    prefix.map_or_else(|| local.to_string(), |p| format!("{p}:{local}"))
}

/// A copy of `from`'s attributes and children onto `to` without namespaces: each element and attribute named by its
/// qualified name, as a namespace-unaware DOM names them.
fn copy_unaware<'d>(from: sxd_document::dom::Element, to: sxd_document::dom::Element<'d>, document: &sxd_document::dom::Document<'d>) {
    use sxd_document::dom::ChildOfElement;
    for attribute in from.attributes() {
        to.set_attribute_value(qualified(attribute.preferred_prefix(), attribute.name().local_part()).as_str(), attribute.value());
    }
    for child in from.children() {
        match child {
            ChildOfElement::Element(e) => {
                let copy = document.create_element(qualified(e.preferred_prefix(), e.name().local_part()).as_str());
                to.append_child(copy);
                copy_unaware(e, copy, document);
            }
            ChildOfElement::Text(t) => to.append_child(document.create_text(t.text())),
            ChildOfElement::Comment(c) => to.append_child(document.create_comment(c.text())),
            ChildOfElement::ProcessingInstruction(p) => to.append_child(document.create_processing_instruction(p.target(), p.value())),
        }
    }
}

/// `JsonPathMatcher.anySelectedValueIsMatchingDateTime`: a definite path selects one value (an array's elements
/// each), an indefinite one a list; a string is read as written, a whole number as epoch seconds or millis.
fn json_path_date_time(path: &JaywayPath, document: &Value, date_time: &StringMatcher) -> bool {
    let selected = match path {
        JaywayPath::Definite(tokens) => match read_definite(tokens, document) {
            Ok(Some(Value::Array(items))) => items,
            Ok(Some(value)) => vec![value],
            _ => return false,
        },
        JaywayPath::Segments(_) | JaywayPath::Whole(_) => path.query(document),
        _ => return false,
    };
    selected.iter().any(|value| {
        let text = match value {
            Value::String(s) => s.clone(),
            Value::Number(n) if !n.to_string().contains(['.', 'e', 'E']) => n.to_string(),
            _ => return false,
        };
        date_time.matches(&text, true)
    })
}

/// The text content of each node an XPath selects (`XPathMatcher.anySelectedNodeIsMatchingDateTime`); `None` when
/// the body does not parse or the expression does not select nodes.
fn xpath_node_texts(expr: &str, body: &str, namespaces: &XPathNamespaces) -> Option<Vec<String>> {
    with_xpath(expr, body, namespaces, |evaluated| match evaluated {
        Ok(sxd_xpath::Value::Nodeset(nodes)) => Some(nodes.document_order().iter().map(|n| n.string_value()).collect()),
        _ => None,
    })
    .flatten()
}

fn xpath_matches(expr: &str, body: &str, namespaces: &XPathNamespaces) -> bool {
    with_xpath(expr, body, namespaces, |evaluated| match evaluated {
        Ok(sxd_xpath::Value::Nodeset(nodes)) => nodes.size() > 0,
        Ok(sxd_xpath::Value::Boolean(b)) => b,
        Ok(sxd_xpath::Value::String(s)) => !s.is_empty(),
        Ok(sxd_xpath::Value::Number(n)) => n != 0.0 && !n.is_nan(),
        Err(_) => false,
    })
    .unwrap_or(false)
}

/// Evaluates `expr` over `body` as `XPathEvaluator` does, handing the result to `f`; `None` when the body does not
/// parse or the expression does not build.
fn with_xpath<R>(expr: &str, body: &str, namespaces: &XPathNamespaces, f: impl FnOnce(Result<sxd_xpath::Value<'_>, sxd_xpath::ExecutionError>) -> R) -> Option<R> {
    let Ok(parsed) = sxd_document::parser::parse(&xpath_document(body, namespaces.is_some())) else { return None };
    let package = match namespaces {
        Some(_) => parsed,
        None => {
            let unaware = sxd_document::Package::new();
            let (from, to) = (parsed.as_document(), unaware.as_document());
            for child in from.root().children() {
                use sxd_document::dom::ChildOfRoot;
                match child {
                    ChildOfRoot::Element(e) => {
                        let copy = to.create_element(qualified(e.preferred_prefix(), e.name().local_part()).as_str());
                        to.root().append_child(copy);
                        copy_unaware(e, copy, &to);
                    }
                    ChildOfRoot::Comment(c) => to.root().append_child(to.create_comment(c.text())),
                    ChildOfRoot::ProcessingInstruction(p) => to.root().append_child(to.create_processing_instruction(p.target(), p.value())),
                }
            }
            unaware
        }
    };
    let document = package.as_document();
    let mut context = sxd_xpath::Context::new();
    match namespaces {
        Some(namespaces) => namespaces.iter().for_each(|(prefix, uri)| context.set_namespace(prefix, uri)),
        None => context.set_function("local-name", UnawareLocalName),
    }
    // sxd-xpath panics on a name test whose prefix has no namespace in its context (`//bar:content` without namespaces).
    let evaluated = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let expression = sxd_xpath::Factory::new().build(expr).ok().flatten()?;
        Some(expression.evaluate(&context, document.root()))
    }));
    let Ok(Some(evaluated)) = evaluated else { return None };
    Some(f(evaluated))
}

#[cfg(test)]
mod tests {
    #[test]
    fn json_numbers_compare_as_jackson_reads_them() {
        use super::numbers_match;
        assert!(numbers_match("12.5", "12.50"));
        assert!(numbers_match("1e2", "100.0"));
        assert!(numbers_match("-0", "0"));
        assert!(!numbers_match("1.0", "1"));
        assert!(!numbers_match("1", "1.0"));
        assert!(!numbers_match("12", "13"));
    }

    #[test]
    fn match_numbers_as_strings_compares_numbers_by_value() {
        super::with_numeric_tolerance(true, || {
            assert!(super::numbers_match("1", "1.0"));
            assert!(super::numbers_match("1.5", "15e-1"));
            assert!(super::numbers_match("100", "1E2"));
            assert!(super::numbers_match("-0", "0.0"));
            assert!(!super::numbers_match("1", "2"));
            // the double is read through its `double` value
            assert!(!super::numbers_match("12345678901234567890", "1.2345678901234567890E19"));
        });
        assert!(!super::numbers_match("1", "1.0"));
    }

    use super::BodyMatcher;
    use crate::request::HttpRequest;
    use serde_json::json;

    fn req(body: &str) -> HttpRequest {
        HttpRequest { body: body.to_string().into(), ..HttpRequest::default() }
    }

    #[test]
    fn json_only_matching_fields() {
        let m = BodyMatcher::compile(&json!({"a": 1, "arr": [1, 2]}));
        assert!(m.matches(&req(r#"{"arr":[2,1,3],"a":1,"b":2}"#), false));
        assert!(!m.matches(&req(r#"{"a":2,"arr":[1,2]}"#), false));
        assert!(!m.matches(&req(r#"{"a":1.0,"arr":[1,2]}"#), false));
    }

    /// A request matched against 1,000 JSON body matchers, then described by them, has its body read once; the
    /// next request's body, equal in bytes but not in content type, or differing in one byte, is read again.
    #[test]
    fn a_json_body_is_read_once_for_all_the_matchers_of_a_request() {
        let order = |id: &str| format!(r#"{{"order":{{"id":"{id}","items":[{{"sku":"SKU-1","quantity":2}}]}},"note":"x"}}"#);
        let matchers: Vec<_> = (0..1000)
            .map(|i| BodyMatcher::compile(&json!({"type": "JSON", "json": {"order": {"id": format!("e{i}")}}, "matchType": "ONLY_MATCHING_FIELDS"})))
            .collect();
        let typed = |body: String, content_type: &str| {
            let mut r = req(&body);
            r.headers.push(("Content-Type".into(), vec![content_type.into()]));
            r
        };
        let read = || super::BODIES_READ.with(std::cell::Cell::get);
        let before = read();
        let request = typed(order("e999"), "application/json");
        let matched: Vec<usize> = (0..1000).filter(|&i| matchers[i].matches(&request, false)).collect();
        assert_eq!(matched, [999]);
        assert!(matchers[0].difference(&request).expect("a difference").hint_reason().contains("e0"));
        assert!(matchers[0].recorded_differences(&request).iter().all(|d| !d.contains("exception while perform json match")));
        assert_eq!(read() - before, 1);
        // the next request posting the same document, in a buffer of its own: not read again
        assert!(matchers[999].matches(&typed(order("e999"), "application/json"), false));
        assert_eq!(read() - before, 1);
        // a body differing in one byte, then the same bytes as a form: each read afresh
        let other = typed(order("e998"), "application/json");
        assert!(matchers[998].matches(&other, false) && !matchers[999].matches(&other, false));
        assert_eq!(read() - before, 2);
        assert!(!matchers[999].matches(&typed(order("e999"), "application/x-www-form-urlencoded"), false));
        assert_eq!(read() - before, 3);
        assert!(matchers[999].matches(&request, false));
    }

    /// A body only a lenient reader accepts is matched and described as read leniently, as `JsonStringMatcher` reads
    /// it (oracle scenario `json_body_read_once_per_request`); one no reader accepts is described by the parse failure.
    #[test]
    fn a_lenient_json_body_is_described_as_read_leniently() {
        let m = BodyMatcher::compile(&json!({"type": "JSON", "json": {"a": 1}}));
        assert!(m.matches(&req("{'a': 1}"), false));
        let lenient = req("{'a': 2}");
        assert!(!m.matches(&lenient, false));
        let reason = m.difference(&lenient).expect("a difference").hint_reason();
        assert!(reason.starts_with("  json match failed") && reason.contains("wrong value at \"a\""), "{reason}");
        assert_eq!(m.recorded_differences(&lenient).len(), 1);
        let text = req("a = 1");
        assert!(m.difference(&text).expect("a difference").hint_reason().contains("exception while perform json match failed"));
        assert_eq!(m.recorded_differences(&text).len(), 2);
    }

    #[test]
    fn json_strict() {
        let m = BodyMatcher::compile(&json!({"type": "JSON", "json": {"a": 1, "arr": [1, 2]}, "matchType": "STRICT"}));
        assert!(m.matches(&req(r#"{"a":1,"arr":[1,2]}"#), false));
        assert!(!m.matches(&req(r#"{"a":1,"arr":[2,1]}"#), false));
        assert!(!m.matches(&req(r#"{"a":1,"arr":[1,2],"b":1}"#), false));
    }

    #[test]
    fn json_placeholders() {
        let m = BodyMatcher::compile(&json!({"id": "${json-unit.any-number}", "x": "${json-unit.ignore}"}));
        assert!(m.matches(&req(r#"{"id":5,"x":[1]}"#), false));
        assert!(!m.matches(&req(r#"{"id":"5","x":1}"#), false));
    }

    #[test]
    fn string_bodies_are_case_sensitive_and_regex_is_anchored() {
        assert!(!BodyMatcher::compile(&json!("exact")).matches(&req("EXACT"), false));
        let regex = BodyMatcher::compile(&json!({"type": "REGEX", "regex": "id=[0-9]+"}));
        assert!(regex.matches(&req("id=12"), false));
        assert!(!regex.matches(&req("x id=12"), false));
    }

    #[test]
    fn xml_xpath_and_form() {
        let xml = BodyMatcher::compile(&json!({"type": "XML", "xml": "<a><b>1</b></a>"}));
        assert!(xml.matches(&req("<a>\n  <b>1</b>\n</a>"), false));
        assert!(!xml.matches(&req("<a><b>2</b></a>"), false));
        let xpath = BodyMatcher::compile(&json!({"type": "XPATH", "xpath": "/order/item[@qty > 2]"}));
        assert!(xpath.matches(&req(r#"<order><item qty="3"/></order>"#), false));
        assert!(!xpath.matches(&req(r#"<order><item qty="1"/></order>"#), false));
        let form = BodyMatcher::compile(&json!({"type": "PARAMETERS", "parameters": {"name": ["bob"]}}));
        assert!(form.matches(&req("name=bob&x=1"), false));
        assert!(!form.matches(&req("name=alice"), false));
    }

    /// XMLUnit similarity and Jayway truthiness (oracle scenario `closest_match_body_reasons`).
    #[test]
    fn xml_similarity_and_json_path_truthiness() {
        let xml = |e: &str, a: &str| BodyMatcher::compile(&json!({"type": "XML", "xml": e})).matches(&req(a), false);
        assert!(xml("<a><b>1</b><c>2</c></a>", "<a><c>2</c><b>1</b></a>"));
        assert!(xml(r#"<p:a xmlns:p="urn:x"><p:b/></p:a>"#, r#"<q:a xmlns:q="urn:x"><q:b/></q:a>"#));
        assert!(xml("<a><![CDATA[x]]></a>", "<a>x</a>"));
        assert!(!xml(r#"<a xmlns="urn:x"/>"#, r#"<a xmlns="urn:y"/>"#));
        assert!(!xml("<a><?pi data?></a>", "<a/>"));
        assert!(!xml("<a><b>1</b><b>2</b></a>", "<a><b>2</b><b>1</b></a>"));
        let path = |p: &str, a: &str| BodyMatcher::compile(&json!({"type": "JSON_PATH", "jsonPath": p})).matches(&req(a), false);
        assert!(!path("$.a", r#"{"a":null}"#));
        assert!(!path("$.a", r#"{"a":[]}"#));
        assert!(path("$.a", r#"{"a":false}"#));
        assert!(path("$.a", r#"{"a":{}}"#));
        assert!(path("$['a','b']", r#"{"c":1}"#));
        assert!(path("$.a.length()", r#"{"a":[]}"#));
        assert!(!path("$.a.length()", r#"{"a":1}"#));
        assert!(path("$.a[", r#"{"a":1}"#));
        assert!(!path("$['a", r#"{"a":1}"#));
        assert!(path("$.a[*]", r#"{"a":[null]}"#));
        assert!(!path("$.a[0]", r#"{"a":[null]}"#));
    }

    /// Confirmed against the real oracle: `nullable` is NOT honoured for JSON_SCHEMA body matching
    /// — a literal JSON `null` body is rejected regardless of it, exactly as the plain `jsonschema` crate (which
    /// has no idea what the keyword means) already behaves. A tempting "fix" here would be a real regression.
    #[test]
    fn json_schema_nullable_does_not_make_null_match() {
        let m = BodyMatcher::compile(&json!({"type": "JSON_SCHEMA", "jsonSchema": {"type": "string", "nullable": true}}));
        assert!(!m.matches(&req("null"), false));
        assert!(m.matches(&req("\"hello\""), false));
        assert!(!m.matches(&req("123"), false));
    }

    fn reason(body: serde_json::Value, request: &HttpRequest) -> String {
        BodyMatcher::compile(&body).difference(request).expect("a difference").hint_reason()
    }

    #[test]
    fn string_family_reasons() {
        assert_eq!(
            reason(json!({"type": "REGEX", "regex": "some[a-z]{3}"}), &req("bodysome")),
            "  string or regex match failed expected:     some[a-z]{3}    found:     bodysome "
        );
        assert_eq!(reason(json!("somebody"), &req("")), "  exact string match failed expected:     somebody    found: ");
        assert_eq!(
            reason(json!({"type": "STRING", "string": "x", "subString": true}), &req("y")),
            "  substring match failed expected:     x    found:     y "
        );
    }

    #[test]
    fn json_path_reasons_follow_jayway() {
        let path = |p: &str, body: &str| reason(json!({"type": "JSON_PATH", "jsonPath": p}), &req(body));
        assert_eq!(
            path("$.missing", r#"{"name":"value"}"#),
            "  json path match failed expected:     $.missing    found:     {\"name\":\"value\"}    failed because:     No results for path: $['missing'] "
        );
        assert!(path("$.a.b", r#"{"c":1}"#).ends_with("failed because:     Missing property in path $['a'] "));
        assert!(path("$.a[2].b", r#"{"a":[1]}"#).ends_with("failed because:     No results for path: $['a'][2]['b'] "));
        assert!(path("$.a.b", r#"{"a":"s"}"#).contains(
            "failed because:     Expected to find an object with property ['b'] in path $['a'] but found 'java.lang.String'."
        ));
        assert!(path("$..book[?(@.price > 10)]", r#"{"store":{}}"#).ends_with("failed because:     json path did not evaluate to truthy "));
        assert!(path("$.a", "").contains("found:     null    failed because:     json path did not evaluate to truthy"));
        assert!(path("$.a[0]", r#"{"a":{"b":1,"d":[1,"y"],"e":{"f":null},"g":1.5}}"#)
            .ends_with("failed because:     Filter: [0] can only be applied to arrays. Current context is: {b=1, d=[1,\"y\"], e={f=null}, g=1.5} "));
        assert!(path("$.a[0]", r#"{"a":null}"#).ends_with("failed because:     The path $['a'] is null "));
        assert!(path("$.a.length()", r#"{"b":1}"#).ends_with("failed because:     Missing property in path $['a'] "));
        assert!(path("$['a','b']", "[1]").contains("failed because:     Expected to find an object with property ['a','b'] in path $ but found 'shaded_package.net.minidev.json.JSONArray'."));
        assert!(path("$['a", r#"{"b":1}"#).starts_with("  json path match failed expected:     null    found:"));
        assert!(path("$['a", r#"{"b":1}"#).ends_with("failed because:     json path matcher was null "));
    }

    #[test]
    fn json_schema_reasons() {
        let schema = json!({"type": "JSON_SCHEMA", "jsonSchema": {"type": "string", "pattern": "^someB[a-z]{3}$"}});
        let quoted = reason(schema.clone(), &req("\"someOtherBody\""));
        assert!(quoted.starts_with("  json schema match failed expected:     {       \"type\" : \"string\","), "{quoted}");
        assert!(quoted.contains("found:     \"someOtherBody\"    failed because:     1 error:      - $: "), "{quoted}");
        assert!(reason(schema, &req("someOtherBody")).contains("failed because:     JsonParseException - Unrecognized token 'someOtherBody'"));
    }

    #[test]
    fn xml_and_xpath_reasons() {
        let xml = json!({"type": "XML", "xml": "<element><key>some_key</key><value>some_value</value></element>"});
        assert!(reason(xml.clone(), &req("<element><key>some_key</key></element>")).ends_with(
            "failed because:     Expected child nodelist length '2' but was '1' - comparing <element...> at /element[1] to <element...> at /element[1] "
        ));
        assert!(reason(xml.clone(), &req("<element><key>other</key><value>some_value</value></element>")).ends_with(
            "failed because:     Expected text value 'some_key' but was 'other' - comparing <key ...>some_key</key> at /element[1]/key[1]/text()[1] to <key ...>other</key> at /element[1]/key[1]/text()[1] "
        ));
        assert!(reason(xml.clone(), &req("<other><key>some_key</key><value>some_value</value></other>"))
            .ends_with("failed because:     Expected child 'element' but was 'null' - comparing <element...> at /element[1] to <NULL> "));
        assert!(reason(xml, &req("")).ends_with("found:     null    failed because:     null "));
        let xml = |e: &str, a: &str| reason(json!({"type": "XML", "xml": e}), &req(a));
        assert!(xml(r#"<a xmlns="urn:x"/>"#, r#"<a xmlns="urn:y"/>"#).ends_with("Expected child '{urn:x}a' but was 'null' - comparing <a...> at /a[1] to <NULL> "));
        assert!(xml(r#"<a x="1"/>"#, r#"<a y="1"/>"#).ends_with("Expected attribute name '/a[1]/@x' - comparing <a...> at /a[1]/@x to <a...> at /a[1] "));
        assert!(xml("<a><?pi x?></a>", "<a><?pi y?></a>").ends_with(
            "Expected processing instruction data 'x' but was 'y' - comparing <?pi x?> at /a[1]/processing-instruction()[1] to <?pi y?> at /a[1]/processing-instruction()[1] "
        ));
        assert!(xml("<a/>", "<a>").ends_with("failed because:     XML document structures must start and end within the same entity. "));
        assert!(xml("<a>", "<a/>").ends_with("failed because:     XML document structures must start and end within the same entity. "));
        assert!(xml("<!DOCTYPE a><a/>", "<a/>").contains("failed because:     DOCTYPE is disallowed when the feature"));
        assert_eq!(
            reason(json!({"type": "XPATH", "xpath": "/a[b]"}), &req("<a/>")),
            "  xpath match failed expected:     /a[b]    found:     <a/>    failed because:     xpath did not evaluate to truthy "
        );
    }

    /// Jayway path functions and XMLUnit's per-node comparisons, each against the oracle's full text (the hint in
    /// `closest_match_body_functions` cuts most of these short).
    #[test]
    fn path_function_and_xml_node_reasons_match_the_oracle() {
        let cases = [
            ("JSON_PATH", "$.a.min()", "{\"a\":[]}", "Aggregation function attempted to calculate value using empty array"),
            ("JSON_PATH", "$.a.min()", "{\"a\":\"x\"}", "Aggregation function attempted to calculate value using empty array"),
            ("JSON_PATH", "$.a.min()", "{\"b\":1}", "Missing property in path $['a']"),
            ("JSON_PATH", "$.a.min()", "{\"a\":[\"x\",\"y\"]}", "Aggregation function attempted to calculate value using empty array"),
            ("JSON_PATH", "$.a.min()", "{\"a\":[\"2\",\"1\"]}", "Aggregation function attempted to calculate value using empty array"),
            ("JSON_PATH", "$.a.sum()", "{\"a\":[]}", "Aggregation function attempted to calculate value using empty array"),
            ("JSON_PATH", "$.a.sum()", "{\"a\":{\"x\":1}}", "Aggregation function attempted to calculate value using empty array"),
            ("JSON_PATH", "$.a.sum()", "{\"a\":null}", "Aggregation function attempted to calculate value using empty array"),
            ("JSON_PATH", "$.a.first()", "{\"a\":[]}", "Index 0 out of bounds for length 0"),
            ("JSON_PATH", "$.a.index(5)", "{\"a\":[1,2]}", "Index 5 out of bounds for length 2"),
            ("JSON_PATH", "$.a.length()", "{\"b\":5}", "Missing property in path $['a']"),
            ("JSON_PATH", "$.a.nope()", "{\"a\":[1]}", "Function with name: nope does not exist."),
            ("JSON_PATH", "$.a.min()", "hello", "Expected to find an object with property ['a'] in path $ but found 'java.lang.String'. This is not a json object according to the JsonProvider: 'shaded_package.com.jayway.jsonpath.spi.json.JsonSmartJsonProvider'."),
            ("JSON_PATH", "$.a.length().b", "{\"a\":[1]}", "Expected to find an object with property [')'] in path $['a'] but found 'java.lang.Integer'. This is not a json object according to the JsonProvider: 'shaded_package.com.jayway.jsonpath.spi.json.JsonSmartJsonProvider'."),
            ("XML", "<a>x<b/>y</a>", "<a>x<b/>z</a>", "Expected text value 'y' but was 'z' - comparing <a ...>y</a> at /a[1]/text()[2] to <a ...>z</a> at /a[1]/text()[2]"),
            ("XML", "<a>x<b/>y</a>", "<a>w<b/>y</a>", "Expected text value 'x' but was 'w' - comparing <a ...>x</a> at /a[1]/text()[1] to <a ...>w</a> at /a[1]/text()[1]"),
            ("XML", "<a>x<b/>y</a>", "<a>xy<b/></a>", "Expected child nodelist length '3' but was '2' - comparing <a...> at /a[1] to <a...> at /a[1]"),
            ("XML", "<a>x<b/>y</a>", "<a>x<b/></a>", "Expected child nodelist length '3' but was '2' - comparing <a...> at /a[1] to <a...> at /a[1]"),
            ("XML", "<a xmlns:p=\"urn:p\" p:k=\"1\"/>", "<a xmlns:p=\"urn:p\" p:k=\"2\"/>", "Expected attribute value '1' but was '2' - comparing <a p:k=\"1\"...> at /a[1]/@k to <a p:k=\"2\"...> at /a[1]/@k"),
            ("XML", "<a xmlns:p=\"urn:p\" p:k=\"1\"/>", "<a k=\"1\"/>", "Expected attribute name '/a[1]/@k' - comparing <a...> at /a[1]/@k to <a...> at /a[1]"),
            ("XML", "<a k=\"1\"/>", "<a xmlns:p=\"urn:p\" p:k=\"1\"/>", "Expected attribute name '/a[1]/@k' - comparing <a...> at /a[1]/@k to <a...> at /a[1]"),
            ("XML", "<a xmlns:p=\"urn:p\" p:k=\"1\"/>", "<a xmlns:p=\"urn:q\" p:k=\"1\"/>", "Expected attribute name '/a[1]/@k' - comparing <a...> at /a[1]/@k to <a...> at /a[1]"),
            ("XML", "<a xmlns:p=\"urn:p\" p:k=\"1\" k=\"2\"/>", "<a xmlns:p=\"urn:p\" p:k=\"2\" k=\"1\"/>", "Expected attribute value '2' but was '1' - comparing <a k=\"2\"...> at /a[1]/@k to <a k=\"1\"...> at /a[1]/@k"),
            ("XML", "<a><b xmlns:p=\"urn:p\" p:k=\"1\"/></a>", "<a><b xmlns:p=\"urn:p\" p:k=\"3\"/></a>", "Expected attribute value '1' but was '3' - comparing <b p:k=\"1\"...> at /a[1]/b[1]/@k to <b p:k=\"3\"...> at /a[1]/b[1]/@k"),
            ("JSON_PATH", "$.a.first()", "{\"a\":\"xy\"}", "Aggregation function attempted to calculate value using empty array"),
            ("JSON_PATH", "$.a.first()", "{\"a\":{\"k\":1}}", "Aggregation function attempted to calculate value using empty array"),
            ("JSON_PATH", "$.a.last()", "{\"a\":[]}", "Target index:-1 larger than object count:0"),
            ("JSON_PATH", "$.a.index(-3)", "{\"a\":[1,2]}", "Target index:-3 larger than object count:2"),
            ("JSON_PATH", "$.a.index('x')", "{\"a\":[1,2]}", "Index 0 out of bounds for length 0"),
            ("JSON_PATH", "$.x[*].length()", "{}", "Missing property in path $['x']"),
            ("JSON_PATH", "$.x[*].min()", "{}", "Missing property in path $['x']"),
            ("JSON_PATH", "$.a[*].b.min()", "{\"a\":[{\"b\":2},{\"b\":1}]}", "Aggregation function attempted to calculate value using empty array"),
            ("JSON_PATH", "$..b.first()", "{\"a\":{\"b\":[7]}}", "Aggregation function attempted to calculate value using empty array"),
            ("JSON_PATH", "$..b.first()", "{\"a\":1}", "Aggregation function attempted to calculate value using empty array"),
            ("JSON_PATH", "$.a.sum()", "{\"a\":5}", "Aggregation function attempted to calculate value using empty array"),
            ("JSON_PATH", "$.a.b.min()", "{\"a\":{}}", "Missing property in path $['a']['b']"),
            ("JSON_PATH", "$.a.concat('x')", "{\"b\":1}", "Missing property in path $['a']"),
            ("JSON_PATH", "$.a.min()", "{\"a\":[true]}", "Aggregation function attempted to calculate value using empty array"),
            ("JSON_PATH", "$.a.keys()[0]", "{\"a\":{\"k\":1}}", "Expected to find an object with property [')'] in path $['a'] but found 'java.util.LinkedHashMap$LinkedKeySet'. This is not a json object according to the JsonProvider: 'shaded_package.com.jayway.jsonpath.spi.json.JsonSmartJsonProvider'."),
            ("XML", "<a><x/><b>1</b></a>", "<a><y/><b>2</b></a>", "Expected text value '1' but was '2' - comparing <b ...>1</b> at /a[1]/b[1]/text()[1] to <b ...>2</b> at /a[1]/b[1]/text()[1]"),
            ("XML", "<a><b>1</b>t</a>", "<a><b>2</b>u</a>", "Expected text value '1' but was '2' - comparing <b ...>1</b> at /a[1]/b[1]/text()[1] to <b ...>2</b> at /a[1]/b[1]/text()[1]"),
            ("XML", "<a>t<b>1</b></a>", "<a>u<b>2</b></a>", "Expected text value 't' but was 'u' - comparing <a ...>t</a> at /a[1]/text()[1] to <a ...>u</a> at /a[1]/text()[1]"),
            ("XML", "<a>x<?p d?>y</a>", "<a>x<?p d?>z</a>", "Expected text value 'y' but was 'z' - comparing <a ...>y</a> at /a[1]/text()[2] to <a ...>z</a> at /a[1]/text()[2]"),
            ("XML", "<a>x<?p d?>y</a>", "<a>xy<?p d?></a>", "Expected child nodelist length '3' but was '2' - comparing <a...> at /a[1] to <a...> at /a[1]"),
            ("XML", "<a>x<b/>y</a>", "<a>y<b/>x</a>", "Expected text value 'x' but was 'y' - comparing <a ...>x</a> at /a[1]/text()[1] to <a ...>y</a> at /a[1]/text()[1]"),
            ("XML", "<a><x/><y/></a>", "<a><p/><q/></a>", "Expected child 'x' but was 'null' - comparing <x...> at /a[1]/x[1] to <NULL>"),
            ("XML", "<a><b>1</b><c>2</c></a>", "<a><c>3</c><b>1</b></a>", "Expected text value '2' but was '3' - comparing <c ...>2</c> at /a[1]/c[1]/text()[1] to <c ...>3</c> at /a[1]/c[1]/text()[1]"),
            ("XML", "<a><b>1</b><b>2</b></a>", "<a><b>1</b><b>3</b></a>", "Expected text value '2' but was '3' - comparing <b ...>2</b> at /a[1]/b[2]/text()[1] to <b ...>3</b> at /a[1]/b[2]/text()[1]"),
            ("XML", "<a><b>1</b><b>2</b></a>", "<a><b>2</b><b>1</b></a>", "Expected text value '1' but was '2' - comparing <b ...>1</b> at /a[1]/b[1]/text()[1] to <b ...>2</b> at /a[1]/b[1]/text()[1]"),
            ("XML", "<a xmlns:p=\"urn:p\"><b p:k=\"1\"/></a>", "<a><b k=\"1\"/></a>", "Expected attribute name '/a[1]/b[1]/@k' - comparing <b...> at /a[1]/b[1]/@k to <b...> at /a[1]/b[1]"),
            ("XML", "<a xmlns:z=\"urn:z\" z:a=\"1\" b=\"2\"/>", "<a xmlns:z=\"urn:z\" z:a=\"9\" b=\"8\"/>", "Expected attribute value '2' but was '8' - comparing <a b=\"2\"...> at /a[1]/@b to <a b=\"8\"...> at /a[1]/@b"),
            ("JSON_PATH", "$.a.last()", "{\"a\":[1]}", "Target index:-1 larger than object count:1"),
            ("JSON_PATH", "$.a.index(-2)", "{\"a\":[1,2]}", "Target index:-2 larger than object count:2"),
            ("JSON_PATH", "$.a..b.min()", "{\"a\":{\"c\":{\"b\":4}}}", "Aggregation function attempted to calculate value using empty array"),
            ("JSON_PATH", "$.x..b.length()", "{\"a\":1}", "Missing property in path $['x']"),
            ("JSON_PATH", "$.a[*].first()", "{\"a\":[[1],2]}", "Aggregation function attempted to calculate value using empty array"),
            ("JSON_PATH", "$.a[0].min()", "{\"a\":[]}", "No results for path: $['a'][0].min()"),
            ("JSON_PATH", "$.a[0].min()", "{\"a\":1}", "Filter: [0].min() can only be applied to arrays. Current context is: 1"),
            ("JSON_PATH", "$.a[0].b", "{\"a\":1}", "Filter: [0]['b'] can only be applied to arrays. Current context is: 1"),
            ("JSON_PATH", "$.a[0].b", "{\"a\":[]}", "No results for path: $['a'][0]['b']"),
            ("JSON_PATH", "$.a[0].min()", "{\"a\":null}", "The path $['a'] is null"),
            ("JSON_PATH", "$.a[3].index(1)", "{\"a\":[]}", "No results for path: $['a'][3].index(...)"),
            ("JSON_PATH", "$.a.b.keys()", "{\"a\":1}", "Expected to find an object with property ['b'] in path $['a'] but found 'java.lang.Integer'. This is not a json object according to the JsonProvider: 'shaded_package.com.jayway.jsonpath.spi.json.JsonSmartJsonProvider'."),
            ("XML", "<a k=\"1\"><b/></a>", "<a k=\"2\"></a>", "Expected child nodelist length '1' but was '0' - comparing <a...> at /a[1] to <a...> at /a[1]"),
            ("XML", "<a k=\"1\"><b/></a>", "<a></a>", "Expected child nodelist length '1' but was '0' - comparing <a...> at /a[1] to <a...> at /a[1]"),
            ("XML", "<a>x<b/></a>", "<a><?p d?><b/></a>", "Expected child '#text' but was 'null' - comparing <a ...>x</a> at /a[1]/text()[1] to <NULL>"),
            ("XML", "<a><![CDATA[x]]></a>", "<a>y</a>", "Expected text value 'x' but was 'y' - comparing <a ...>x</a> at /a[1]/text()[1] to <a ...>y</a> at /a[1]/text()[1]"),
            ("XML", "<a><b>1<c/>2</b></a>", "<a><b>1<c/>3</b></a>", "Expected text value '2' but was '3' - comparing <b ...>2</b> at /a[1]/b[1]/text()[2] to <b ...>3</b> at /a[1]/b[1]/text()[2]"),
            ("XML", "<a><b/></a>", "<a>t</a>", "Expected child 'b' but was 'null' - comparing <b...> at /a[1]/b[1] to <NULL>"),
        ];
        for (kind, matcher, body, because) in cases {
            let field = if kind == "XML" { "xml" } else { "jsonPath" };
            let got = reason(json!({"type": kind, field: matcher}), &req(body));
            assert!(got.ends_with(&format!("failed because:     {because} ")), "{matcher} on {body}: {got}");
        }
    }

    #[test]
    fn binary_json_and_parameter_reasons() {
        assert_eq!(
            reason(json!({"type": "BINARY", "base64Bytes": "c29tZSBiaW5hcnkgdmFsdWU="}), &req("")),
            "  binary match failed expected:     base64:       c29tZSBiaW5hcnkgdmFsdWU=     hex:       736f6d652062696e6172792076616c7565    found:     base64:          hex: "
        );
        assert!(reason(json!({"some_field": "some_value"}), &req("")).starts_with(
            "  exception while perform json match failed expected:     {       \"some_field\" : \"some_value\"     }    found:     null    failed because:     java.lang.NullPointerException: Cannot invoke \"String.equals(Object)\" because \"matched\" is null"
        ));
        assert_eq!(
            reason(json!({"type": "PARAMETERS", "parameters": {"nameOne": ["valueOne"]}}), &req("")),
            "  multimap match failed expected:     {       \"nameOne\" : [ \"valueOne\" ]     }    found:     { }    failed because:     multimap is not a subset "
        );
        assert_eq!(
            reason(json!({"not": true, "type": "PARAMETERS", "parameters": {"nameOne": ["valueOne"]}}), &req("nameTwo=valueTwo&nameOne=valueOne")),
            "  string or regex match failed expected:     nameOne    found:     nameTwo "
        );
    }

    #[test]
    fn all_of_reports_the_failing_component() {
        let all_of = json!({"type": "ALL_OF", "bodyAllOf": [{"type": "JSON_PATH", "jsonPath": "$.name"}, {"type": "REGEX", "regex": ".*absent.*"}]});
        assert_eq!(
            reason(all_of, &req(r#"{"name":"value","age":5}"#)),
            "  string or regex match failed expected:     .*absent.*    found:     {\"name\":\"value\",\"age\":5} "
        );
    }
}

/// A Jayway JsonPath on RFC 9535's evaluator: split at its filters, since Jayway applies a filter on an object to
/// the object itself (where RFC 9535 filters the object's members), with `=~` regex filters rewritten.
/// A filter that reads the document root (`$`) keeps the whole path on RFC 9535's evaluator.
#[derive(Debug)]
pub enum JaywayPath {
    Segments(Vec<(serde_json_path::JsonPath, bool)>),
    Whole(serde_json_path::JsonPath),
    /// A definite path, read as Jayway reads it (a single value, truthy unless null or an empty array).
    Definite(Vec<PathToken>),
    /// A path that does not compile: `JsonPathMatcher` keeps no `JsonPath` and never matches.
    Uncompiled,
    /// An indefinite path closed by a function, which Jayway applies to each value the path reads (`$.a[*].min()`).
    /// The definite steps it starts with are read first, and fail as a definite path does.
    Mapped { head: Vec<PathToken>, path: Box<JaywayPath>, function: (String, Vec<String>) },
    /// A deep scan closed by a function (`$..a.sum()`), which Jayway compiles as the function of the document with
    /// the scan as its parameter (`$.sum($..a)`).
    Inverted { path: Box<JaywayPath>, function: (String, Vec<String>) },
    /// A definite path whose function is followed by more steps (`$.a.length().b`): Jayway reads a property named
    /// `)` of what the function returned.
    AfterFunction(Vec<PathToken>),
}

/// `ExpectationFilter.compileJsonPath`: whether a Jayway path compiles, else the message of the exception
/// `PathCompiler` throws (`jayway_syntax` ports its parsing, wording included).
pub fn jayway_compile_check(path: &str) -> Result<(), String> {
    super::jayway_syntax::compile(path)
}

/// `JsonPath.read` over a document: whether it selects a value (a non-empty collection, or a non-null one).
pub fn jayway_truthy(path: &str, document: &Value) -> bool {
    JaywayPath::compile(path).matches(document)
}

impl JaywayPath {
    fn compile(path: &str) -> JaywayPath {
        // `JsonPathMatcher` compiles only a non-blank path; Jayway's `PathCompiler` reads one that starts with neither
        // `$` nor `@` as `$.<path>`.
        if path.trim().is_empty() {
            return JaywayPath::Uncompiled;
        }
        let trimmed = path.trim();
        if !trimmed.starts_with('$') && !trimmed.starts_with('@') {
            return JaywayPath::compile(&format!("$.{trimmed}"));
        }
        // A path rooted at `@` reads the document as `$` does (`JsonPath.read` evaluates both against the model).
        if let Some(rest) = trimmed.strip_prefix('@') {
            return JaywayPath::compile(&format!("${rest}"));
        }
        if let Some(tokens) = definite_path(path) {
            return JaywayPath::Definite(tokens);
        }
        let trimmed = path.trim();
        let after_function = trimmed.match_indices(')').map(|(i, _)| i).filter(|i| i + 1 < trimmed.len()).find_map(|i| {
            definite_path(&trimmed[..=i]).filter(|tokens| matches!(tokens.last(), Some(PathToken::Function(..))))
        });
        if let Some(tokens) = after_function {
            return JaywayPath::AfterFunction(tokens);
        }
        // A closing `.name(args)` on an indefinite path.
        if let Some(open) = trimmed.ends_with(')').then(|| trimmed.rfind('(')).flatten() {
            let dot = trimmed[..open].rfind('.');
            let chars: Vec<char> = trimmed[open..].chars().collect();
            if let (Some(dot), Some(args)) = (dot, function_arguments(&chars)) {
                let name = &trimmed[dot + 1..open];
                let prefix = &trimmed[..dot];
                if !name.is_empty() && name.chars().all(|c| c.is_alphanumeric() || c == '_') && prefix.len() > 1 {
                    let function = (name.to_string(), args);
                    // A prefix ending in `..` is a scan without a name, which does not compile.
                    let Ok(inner) = JaywayPath::parse(prefix) else { return JaywayPath::Uncompiled };
                    if prefix.starts_with("$..") {
                        return JaywayPath::Inverted { path: Box::new(inner), function };
                    }
                    let head = definite_head(prefix);
                    return JaywayPath::Mapped { head, path: Box::new(inner), function };
                }
            }
        }
        JaywayPath::parse(path).unwrap_or(JaywayPath::Uncompiled)
    }

    /// `JsonPath.read` and `JsonPathMatcher`'s truthiness: whether what the path read is truthy, or the message of
    /// the exception reading it throws.
    fn evaluate(&self, document: &Value) -> Result<bool, String> {
        match self {
            JaywayPath::Definite(tokens) => read_definite(tokens, document).map(|read| read.as_ref().is_some_and(json_path_truthy)),
            JaywayPath::Uncompiled => Ok(false),
            JaywayPath::Mapped { head, path, function: (name, args) } => {
                if !head.is_empty() {
                    read_definite_steps(head, document)?;
                }
                let read = path.query(document);
                for value in &read {
                    apply_function(name, args, value, &[])?;
                }
                Ok(!read.is_empty())
            }
            JaywayPath::AfterFunction(tokens) => {
                let Some(PathToken::Function(name, _)) = tokens.last() else { return Ok(false) };
                let class = match (name.as_str(), read_definite(tokens, document)?) {
                    (_, None | Some(Value::Object(_))) => return Ok(false),
                    ("length" | "size", _) => "java.lang.Integer",
                    ("min" | "max" | "avg" | "stddev" | "sum", _) => "java.lang.Double",
                    ("keys", _) => "java.util.LinkedHashMap$LinkedKeySet",
                    (_, Some(value)) => json_smart_class(&value),
                };
                Err(format!(
                    "Expected to find an object with property [')'] in path {} but found '{class}'. This is not a json object according to the JsonProvider: 'shaded_package.com.jayway.jsonpath.spi.json.JsonSmartJsonProvider'.",
                    render_path(&tokens[..tokens.len() - 1])
                ))
            }
            JaywayPath::Inverted { path, function: (name, args) } => {
                let read = apply_function(name, args, document, &[Value::Array(path.query(document))])?;
                Ok(read.as_ref().is_some_and(json_path_truthy))
            }
            _ => Ok(!self.query(document).is_empty()),
        }
    }

    fn parse(path: &str) -> Result<JaywayPath, serde_json_path::ParseError> {
        let path = jayway_regex_filters(path.trim());
        let rest = path.strip_prefix('$').unwrap_or(&path);
        let chars: Vec<char> = rest.chars().collect();
        let mut segments = Vec::new();
        let mut plain = String::new();
        let mut i = 0;
        while i < chars.len() {
            if chars[i] == '[' && chars.get(i + 1) == Some(&'?') {
                // The filter runs to its matching `]`, outside string literals.
                let (mut depth, mut quote, mut j) = (0, None::<char>, i);
                while j < chars.len() {
                    let c = chars[j];
                    match quote {
                        Some(_) if c == '\\' => j += 1,
                        Some(q) if c == q => quote = None,
                        Some(_) => {}
                        None if c == '\'' || c == '"' => quote = Some(c),
                        None if c == '[' => depth += 1,
                        None if c == ']' => {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        None => {}
                    }
                    j += 1;
                }
                if !plain.is_empty() {
                    segments.push((serde_json_path::JsonPath::parse(&format!("${plain}"))?, false));
                    plain.clear();
                }
                let filter: String = chars[i..(j + 1).min(chars.len())].iter().collect();
                if reads_root(&filter) {
                    return Ok(JaywayPath::Whole(serde_json_path::JsonPath::parse(&path)?));
                }
                segments.push((serde_json_path::JsonPath::parse(&format!("${filter}"))?, true));
                i = j + 1;
            } else {
                plain.push(chars[i]);
                i += 1;
            }
        }
        if !plain.is_empty() || segments.is_empty() {
            segments.push((serde_json_path::JsonPath::parse(&format!("${plain}"))?, false));
        }
        Ok(JaywayPath::Segments(segments))
    }

    fn matches(&self, document: &Value) -> bool {
        self.evaluate(document) == Ok(true)
    }

    /// The values an indefinite path reads.
    fn query(&self, document: &Value) -> Vec<Value> {
        let segments = match self {
            JaywayPath::Whole(path) => return path.query(document).all().into_iter().cloned().collect(),
            JaywayPath::Segments(segments) => segments,
            _ => return Vec::new(),
        };
        let mut nodes = vec![document.clone()];
        for (path, filter) in segments {
            nodes = nodes
                .iter()
                .flat_map(|node| {
                    let wrapped;
                    let target = if *filter && node.is_object() {
                        wrapped = Value::Array(vec![node.clone()]);
                        &wrapped
                    } else {
                        node
                    };
                    path.query(target).all().into_iter().cloned().collect::<Vec<_>>()
                })
                .collect();
        }
        nodes
    }
}

/// Whether a filter expression mentions `$` outside its string literals.
fn reads_root(filter: &str) -> bool {
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for c in filter.chars() {
        match quote {
            Some(_) if escaped => escaped = false,
            Some(_) if c == '\\' => escaped = true,
            Some(q) if c == q => quote = None,
            Some(_) => {}
            None if c == '\'' || c == '"' => quote = Some(c),
            None if c == '$' => return true,
            None => {}
        }
    }
    false
}

/// Jayway's `lhs =~ /regex/flags` filter (a whole-value `Pattern` match) as RFC 9535's `match(lhs, 'regex')`; an
/// `i` flag becomes `(?i)`.
fn jayway_regex_filters(path: &str) -> String {
    let chars: Vec<char> = path.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '=' && chars.get(i + 1) == Some(&'~') {
            // The operand before: back to the start of the path expression.
            let trimmed = out.trim_end().len();
            let start = out[..trimmed].rfind(|c: char| c.is_whitespace() || matches!(c, '(' | '&' | '|' | '!')).map_or(0, |p| p + 1);
            let lhs = out[start..trimmed].to_string();
            let mut j = i + 2;
            while j < chars.len() && chars[j].is_whitespace() {
                j += 1;
            }
            if chars.get(j) != Some(&'/') || lhs.is_empty() {
                out.push(chars[i]);
                i += 1;
                continue;
            }
            j += 1;
            let mut regex = String::new();
            while j < chars.len() && chars[j] != '/' {
                if chars[j] == '\\' && chars.get(j + 1) == Some(&'/') {
                    regex.push('/');
                    j += 2;
                } else {
                    regex.push(chars[j]);
                    j += 1;
                }
            }
            j += 1;
            let mut flags = String::new();
            while j < chars.len() && chars[j].is_ascii_alphabetic() {
                flags.push(chars[j]);
                j += 1;
            }
            if flags.contains('i') {
                regex.insert_str(0, "(?i)");
            }
            let literal = regex.replace('\\', "\\\\").replace('\'', "\\'");
            out.truncate(start);
            out.push_str(&format!("match({lhs}, '{literal}')"));
            i = j;
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod jayway_tests {
    #[test]
    fn rewrites_regex_filters() {
        assert_eq!(
            super::jayway_regex_filters("$[?(@.method == 'tasks/send' && @.params.message.parts[0].text =~ /translate.*/)]"),
            "$[?(@.method == 'tasks/send' && match(@.params.message.parts[0].text, 'translate.*'))]"
        );
        assert_eq!(super::jayway_regex_filters("$.a[?(@.b =~ /x\\/y/i)]"), "$.a[?(match(@.b, '(?i)x/y'))]");
    }
}
