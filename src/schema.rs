//! Validation of control-plane JSON against MockServer's own schemas, with its error report format
//! (§3.7): networknt's errors (`crate::networknt`) massaged as `JsonSchemaValidator.formatProcessingReport` does.

use std::sync::LazyLock;

use jsonschema::Validator;
use jsonschema::error::ValidationErrorKind;
use serde_json::{Map, Value};

use crate::json;

/// `JsonSchemaExpectationValidator`'s reference files.
const EXPECTATION_DEFINITIONS: &[&str] = &[
    "requestDefinition", "conditionalRequestDefinition", "anyOfRequestDefinition", "openAPIDefinition",
    "binaryRequestDefinition", "dnsRequestDefinition", "httpRequest", "httpResponse", "httpTemplate", "httpForward",
    "httpClassCallback", "httpObjectCallback", "httpOverrideForwardedRequest", "httpForwardValidateAction",
    "httpForwardWithFallback", "httpError", "httpSseResponse", "httpLlmResponse", "httpWebSocketResponse",
    "grpcStreamResponse", "grpcBidiResponse", "binaryResponse", "dnsResponse", "dnsRecord", "afterAction",
    "captureRule", "expectationStep", "httpChaosProfile", "rateLimit", "times", "timeToLive", "stringOrJsonSchema",
    "body", "bodyWithContentType", "delay", "connectionOptions", "recoverAfter", "keyToMultiValue", "keyToValue",
    "socketAddress", "protocol", "draft-07",
];

/// `JsonSchemaHttpRequestValidator`'s reference files.
const HTTP_REQUEST_DEFINITIONS: &[&str] =
    &["stringOrJsonSchema", "body", "keyToMultiValue", "keyToValue", "socketAddress", "protocol", "draft-07"];

/// `JsonSchemaHttpResponseValidator`'s reference files.
const HTTP_RESPONSE_DEFINITIONS: &[&str] = &[
    "stringOrJsonSchema", "bodyWithContentType", "delay", "connectionOptions", "recoverAfter", "keyToMultiValue",
    "keyToValue", "draft-07",
];

/// `JsonSchemaRequestDefinitionValidator`'s reference files.
const REQUEST_DEFINITION_DEFINITIONS: &[&str] = &[
    "conditionalRequestDefinition", "anyOfRequestDefinition", "httpRequest", "stringOrJsonSchema", "openAPIDefinition",
    "binaryRequestDefinition", "dnsRequestDefinition", "body", "keyToMultiValue", "keyToValue", "socketAddress",
    "protocol", "draft-07",
];

/// `JsonSchemaVerificationValidator`'s reference files (`binaryRequestDefinition` and `dnsRequestDefinition` since
/// upstream #88).
const VERIFICATION_DEFINITIONS: &[&str] = &[
    "expectationId", "requestDefinition", "conditionalRequestDefinition", "anyOfRequestDefinition", "openAPIDefinition",
    "binaryRequestDefinition", "dnsRequestDefinition", "httpRequest", "httpResponse", "stringOrJsonSchema", "body",
    "bodyWithContentType", "keyToMultiValue", "keyToValue", "verificationTimes", "connectionOptions", "delay",
    "socketAddress", "protocol", "draft-07",
];

/// `JsonSchemaVerificationSequenceValidator`'s reference files.
const VERIFICATION_SEQUENCE_DEFINITIONS: &[&str] = &[
    "expectationId", "requestDefinition", "conditionalRequestDefinition", "anyOfRequestDefinition", "openAPIDefinition",
    "binaryRequestDefinition", "dnsRequestDefinition", "httpRequest", "httpResponse", "stringOrJsonSchema", "body",
    "bodyWithContentType", "keyToMultiValue", "keyToValue", "connectionOptions", "delay", "socketAddress", "protocol",
    "draft-07",
];

/// `JsonSchemaHttpRequestAndHttpResponseValidator`'s reference files.
const REQUEST_AND_RESPONSE_DEFINITIONS: &[&str] = &[
    "requestDefinition", "conditionalRequestDefinition", "anyOfRequestDefinition", "openAPIDefinition", "httpRequest",
    "stringOrJsonSchema", "body", "keyToMultiValue", "keyToValue", "socketAddress", "protocol", "httpResponse",
    "bodyWithContentType", "delay", "connectionOptions", "recoverAfter", "draft-07",
];

const OPENAPI_URL: &str = "OpenAPI Specification: https://app.swaggerhub.com/apis/jamesdbloom/mock-server-openapi/9.2.x";
const DOCUMENTATION_URL: &str = "Documentation: https://mock-server.com/mock_server/creating_expectations.html";

const ACTION_ONE_OF: &str = "oneOf of the following must be specified [httpError, httpForward, httpForwardClassCallback, httpForwardObjectCallback, httpForwardTemplate, httpForwardValidateAction, httpForwardWithFallback, httpOverrideForwardedRequest, httpResponse, httpResponseClassCallback, httpResponseObjectCallback, httpResponseTemplate]";

fn load(name: &str) -> Value {
    let text = crate::schema_files::get(name).unwrap_or_else(|| panic!("schema {name}.json is bundled"));
    serde_json::from_str(text).unwrap_or_else(|e| panic!("schema {name}.json is valid JSON: {e}"))
}

/// `JsonSchemaValidator.addReferencesIntoSchema`: every listed file becomes a `#/definitions/<name>` entry of the
/// main schema, followed by its own nested definitions (only when the main schema has a `definitions` object).
fn assemble(root: &str, definitions: &[&str]) -> Value {
    let mut schema = load(root);
    if let Some(defs) = schema.get_mut("definitions").and_then(Value::as_object_mut) {
        for name in definitions {
            let definition = load(name);
            let nested: Option<Map<String, Value>> = definition.get("definitions").and_then(Value::as_object).cloned();
            defs.insert((*name).to_string(), definition);
            for (k, v) in nested.into_iter().flatten() {
                defs.insert(k, v);
            }
        }
    }
    schema
}

/// The model class a validator is built for: `RequestDefinition` widens the `.httpRequest` filter to every path.
#[derive(Clone, Copy, PartialEq)]
enum Kind {
    RequestDefinition,
    Other,
}

struct ControlSchema {
    schema: Value,
    kind: Kind,
}

impl ControlSchema {
    fn new(root: &str, definitions: &[&str], kind: Kind) -> Self {
        ControlSchema { schema: assemble(root, definitions), kind }
    }

    /// `JsonSchemaValidator.isValid`: `Err` carries the report (or the exception text for an unresolvable
    /// reference).
    fn check(&self, value: &Value, with_links: bool) -> Result<(), String> {
        match crate::networknt::validate(&self.schema, value) {
            Ok(errors) if errors.is_empty() => Ok(()),
            Ok(errors) => Err(format_report(errors, self.kind, with_links)),
            Err(crate::networknt::UnresolvedRef(fragment)) => Err(format!("{INVALID_SCHEMA_REF}Reference {fragment} cannot be resolved")),
        }
    }
}

static EXPECTATION: LazyLock<ControlSchema> = LazyLock::new(|| ControlSchema::new("expectation", EXPECTATION_DEFINITIONS, Kind::Other));
static HTTP_REQUEST: LazyLock<ControlSchema> = LazyLock::new(|| ControlSchema::new("httpRequest", HTTP_REQUEST_DEFINITIONS, Kind::Other));
static HTTP_RESPONSE: LazyLock<ControlSchema> =
    LazyLock::new(|| ControlSchema::new("httpResponse", HTTP_RESPONSE_DEFINITIONS, Kind::Other));
static REQUEST_DEFINITION: LazyLock<ControlSchema> =
    LazyLock::new(|| ControlSchema::new("requestDefinition", REQUEST_DEFINITION_DEFINITIONS, Kind::RequestDefinition));
static VERIFICATION: LazyLock<ControlSchema> =
    LazyLock::new(|| ControlSchema::new("verification", VERIFICATION_DEFINITIONS, Kind::Other));
static VERIFICATION_SEQUENCE: LazyLock<ControlSchema> =
    LazyLock::new(|| ControlSchema::new("verificationSequence", VERIFICATION_SEQUENCE_DEFINITIONS, Kind::Other));
static REQUEST_AND_RESPONSE: LazyLock<ControlSchema> =
    LazyLock::new(|| ControlSchema::new("httpRequestAndHttpResponse", REQUEST_AND_RESPONSE_DEFINITIONS, Kind::Other));
static OPEN_API_EXPECTATION: LazyLock<ControlSchema> = LazyLock::new(|| ControlSchema::new("openAPIExpectation", &[], Kind::Other));

/// `HttpRequestAndHttpResponseSerializer`'s validation (a re-imported recording line).
pub fn validate_request_and_response(value: &Value) -> Result<(), String> {
    REQUEST_AND_RESPONSE.check(value, true)
}

/// `JsonSchemaOpenAPIExpectationValidator`: `Err` carries the report.
pub fn validate_openapi_expectation(value: &Value) -> Result<(), String> {
    OPEN_API_EXPECTATION.check(value, true)
}

/// Wraps a report for one invalid OpenAPI expectation, as `OpenAPIExpectationSerializer` does.
pub fn incorrect_openapi_expectation(expectation: &Value, report: &str) -> String {
    format!(
        "incorrect openapi expectation json format for:\n\n{}\n\n schema validation errors:\n\n{}",
        indent(&json::pretty(expectation)),
        indent(report)
    )
}

/// `Err` carries the oracle-style `N error(s):` report.
pub fn validate_expectation(value: &Value) -> Result<(), String> {
    EXPECTATION.check(value, true)
}

/// `JsonSchemaExpectationValidator.isValid(json, false)`: the report without the documentation links (the MCP
/// `raw_expectation` tool reads its ` - ` lines).
pub fn validate_expectation_without_links(value: &Value) -> Result<(), String> {
    EXPECTATION.check(value, false)
}

/// `JsonSchemaHttpResponseValidator` / `JsonSchemaHttpRequestValidator`, as the template output deserializer uses
/// them: `Err` carries the report with the documentation links (`isValid(json)`, which the logged text of the
/// oracle shows).
pub fn validate_http_message(value: &Value, response: bool) -> Result<(), String> {
    let validator = if response { &HTTP_RESPONSE } else { &HTTP_REQUEST };
    validator.check(value, true)
}

pub fn validate_request_definition(value: &Value) -> Result<(), String> {
    REQUEST_DEFINITION.check(value, true)
}

/// Wraps a report for an invalid request matcher (clear/retrieve body), echoing the body as sent.
pub fn incorrect_request_matcher(raw_body: &str, report: &str) -> String {
    incorrect_json_format("request matcher", raw_body, report)
}

/// `formatLogMessage("incorrect <what> json format for:{}schema validation errors:{}", body, errors)` then
/// `removeEnd("\n")`, as the request-definition and verification serializers throw it: the body is echoed as
/// received, surrounding white space included (oracle, `expectation_malformed_json`).
pub fn incorrect_json_format(what: &str, raw_body: &str, report: &str) -> String {
    let format = format!("incorrect {what} json format for:{{}}schema validation errors:{{}}");
    let text = crate::matcher::format_log_message(0, &format, &[raw_body, report]);
    match text.strip_suffix('\n') {
        Some(stripped) => stripped.to_string(),
        None => text,
    }
}

/// `HttpRequestSerializer.deserialize`'s report for an invalid request (the dashboard's request filter).
pub fn incorrect_request(raw_body: &str, report: &str) -> String {
    // `formatLogMessage("incorrect request json format for:{}schema validation errors:{}", body, errors)` then
    // `removeEnd("\n")`: the body is echoed as received, trailing whitespace included (oracle).
    let text = crate::matcher::format_log_message(0, "incorrect request json format for:{}schema validation errors:{}", &[raw_body, report]);
    match text.strip_suffix('\n') {
        Some(stripped) => stripped.to_string(),
        None => text,
    }
}

/// How `JsonSchemaValidator.isValid` reports an unresolvable schema reference (`JsonSchemaVerificationValidator`
/// leaves `binaryRequestDefinition` out of its definitions): the start of the exception's text.
pub const INVALID_SCHEMA_REF: &str = "InvalidSchemaRefException - ";

pub fn validate_verification(value: &Value) -> Result<(), String> {
    VERIFICATION.check(value, true)
}

pub fn validate_verification_sequence(value: &Value) -> Result<(), String> {
    VERIFICATION_SEQUENCE.check(value, true)
}

static ADDITIONAL_PROPERTY: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"(\$[^:]*): property '([^']+)' is not defined in the schema and the schema does not allow additional properties").unwrap()
});
static REQUIRED_PROPERTY: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"(\$[^:]*): required property '([^']+)' not found").unwrap());

/// `normalizeValidationMessageFormat`: networknt 1.5+ wording back to 1.0.x.
fn normalize(text: &str) -> String {
    let text = ADDITIONAL_PROPERTY.replacen(text, 1, "$1.$2: is not defined in the schema and the schema does not allow additional properties");
    let text = REQUIRED_PROPERTY.replacen(&text, 1, "$1.$2: is missing but it is required");
    text.replace("must be valid to one and only one schema", "should be valid to one and only one schema")
}

/// Additional-property messages `formatProcessingReport` drops for a request matcher: the other `anyOf` branches
/// reject the HTTP request's own fields.
const REQUEST_FIELDS_NOT_DEFINED: &[&str] = &[
    "secure", "keepAlive", "method", "path", "pathParameters", "queryStringParameters", "body", "headers", "cookies",
    "socketAddress", "localAddress", "remoteAddress", "specUrlOrPayload", "operationId",
];

const NOT_DEFINED: &str = ": is not defined in the schema and the schema does not allow additional properties";

fn before_colon(text: &str) -> &str {
    text.split(':').next().unwrap_or(text)
}

/// A schema file as `FileReader` reads it, each line break followed by three spaces.
fn schema_dump(name: &str) -> String {
    let text = crate::schema_files::get(name).unwrap_or_default();
    let text = if name == "body" { text.replace("#/definitions/draft-07", "http://json-schema.org/draft-07/schema") } else { text.to_string() };
    text.replace('\n', "\n   ")
}

const COOKIE_EXAMPLES: &str = "invalid cookie format, the following are valid examples: \n  \n     {\n         \"exampleRegexCookie\": \"^some +regex$\", \n         \"exampleNottedRegexCookie\": \"!notThisValue\", \n         \"exampleSimpleStringCookie\": \"simpleStringMatch\"\n     }\n  \n  or:\n  \n     {\n         \"exampleNumberSchemaCookie\": {\n             \"type\": \"number\"\n         }, \n         \"examplePatternSchemaCookie\": {\n             \"type\": \"string\", \n             \"pattern\": \"^some regex$\"\n         }, \n         \"exampleFormatSchemaCookie\": {\n             \"type\": \"string\", \n             \"format\": \"ipv4\"\n         }\n     }";

const HEADER_EXAMPLES: &str = "invalid header format, the following are valid examples: \n  \n     {\n         \"exampleRegexHeader\": [\n             \"^some +regex$\"\n         ], \n         \"exampleNottedAndSimpleStringHeader\": [\n             \"!notThisValue\", \n             \"simpleStringMatch\"\n         ]\n     }\n  \n  or:\n  \n     {\n         \"exampleSchemaHeader\": [\n             {\n                 \"type\": \"number\"\n             }\n         ], \n         \"exampleMultiSchemaHeader\": [\n             {\n                 \"type\": \"string\", \n                 \"pattern\": \"^some +regex$\"\n             }, \n             {\n                 \"type\": \"string\", \n                 \"format\": \"ipv4\"\n             }\n         ]\n     }";

const PARAMETER_EXAMPLES: &str = "invalid parameter format, the following are valid examples: \n  \n     {\n         \"exampleRegexParameter\": [\n             \"^some +regex$\"\n         ], \n         \"exampleNottedAndSimpleStringParameter\": [\n             \"!notThisValue\", \n             \"simpleStringMatch\"\n         ]\n     }\n  \n  or:\n  \n     {\n         \"exampleSchemaParameter\": [\n             {\n                 \"type\": \"number\"\n             }\n         ], \n         \"exampleMultiSchemaParameter\": [\n             {\n                 \"type\": \"string\", \n                 \"pattern\": \"^some +regex$\"\n             }, \n             {\n                 \"type\": \"string\", \n                 \"format\": \"ipv4\"\n             }\n         ]\n     }";

/// One networknt message through `formatProcessingReport`'s rewriting; `None` when it is dropped.
fn reword(text: &str, kind: Kind, extra: &mut Vec<String>) -> Option<String> {
    let text = normalize(text);
    if ((text.starts_with("$.httpRequest") && text.contains(".body: ")) || text.contains("$.body: ")) && !text.contains(NOT_DEFINED) {
        return Some(format!("{}: should match one of its valid types: {}", before_colon(&text), schema_dump("body")));
    }
    if text.contains(".specUrlOrPayload: is missing but it is required") {
        return Some(format!("{}: is missing, but is required, if specifying OpenAPI request matcher", before_colon(&text)));
    }
    if text.starts_with("$.httpResponse.body: ") {
        return Some(format!("$.httpResponse.body: should match one of its valid types: {}", schema_dump("bodyWithContentType")));
    }
    if (text.contains(".httpRequest") || kind == Kind::RequestDefinition)
        && REQUEST_FIELDS_NOT_DEFINED.iter().any(|f| text.contains(&format!(".{f}{NOT_DEFINED}")))
    {
        return None;
    }
    if text.ends_with("cookies: object found, array expected") {
        return Some(format!("{}: {COOKIE_EXAMPLES}", before_colon(&text)));
    }
    if text.ends_with("headers: object found, array expected") {
        return Some(format!("{}: {HEADER_EXAMPLES}", before_colon(&text)));
    }
    if text.ends_with("pathParameters: object found, array expected") || text.ends_with("queryStringParameters: object found, array expected") {
        return Some(format!("{}: {PARAMETER_EXAMPLES}", before_colon(&text)));
    }
    if text.starts_with("$.http") && text.ends_with(": is missing but it is required") {
        extra.push(ACTION_ONE_OF.to_string());
        let path = before_colon(&text);
        return Some(format!("{path}: is missing, but is required, if specifying action of type {}", before_colon(&text["$.http".len()..])));
    }
    if text.starts_with("$.grpc") && text.ends_with(": is missing but it is required") {
        let field = before_colon(&text[2..]);
        let mut chars = field.chars();
        let kind: String = chars.next().map(|c| c.to_uppercase().chain(chars).collect()).unwrap_or_default();
        return Some(format!("{}: is missing, but is required, if specifying action of type {kind}", before_colon(&text)));
    }
    Some(text)
}

/// `formatProcessingReport`: the rewritten messages as a sorted set under an `N error(s):` heading, then the
/// specification links.
fn format_report(errors: Vec<String>, kind: Kind, with_links: bool) -> String {
    let mut extra = Vec::new();
    let mut messages: std::collections::BTreeSet<String> = errors.iter().filter_map(|e| reword(e, kind, &mut extra)).collect();
    messages.extend(extra);
    let messages: Vec<&String> = messages
        .iter()
        .filter(|m| !m.ends_with("object expected") || !messages.contains(&m.replace("object expected", "string expected")))
        .collect();
    let mut out = if messages.len() == 1 { "1 error:".to_string() } else { format!("{} errors:", messages.len()) };
    for m in &messages {
        out.push_str("\n - ");
        out.push_str(m);
    }
    if with_links {
        out.push_str("\n\n");
        out.push_str(OPENAPI_URL);
        out.push('\n');
        out.push_str(DOCUMENTATION_URL);
    }
    out
}

/// Wraps a report for one invalid expectation, as `ExpectationSerializer` does.
pub fn incorrect_expectation(expectation: &Value, report: &str) -> String {
    format!(
        "incorrect expectation json format for:\n\n{}\n\n schema validation errors:\n\n{}",
        indent(&json::pretty_multiline(expectation)),
        indent(report)
    )
}

fn indent(s: &str) -> String {
    s.lines().map(|l| format!("  {l}")).collect::<Vec<_>>().join("\n")
}

fn json_path(root: &str, pointer: &str) -> String {
    let mut out = root.to_string();
    for segment in pointer.split('/').skip(1) {
        let segment = segment.replace("~1", "/").replace("~0", "~");
        if segment.parse::<usize>().is_ok() {
            out.push_str(&format!("[{segment}]"));
        } else {
            out.push('.');
            out.push_str(&segment);
        }
    }
    out
}

fn type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(n) if n.is_i64() || n.is_u64() => "integer",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn pointer<'a>(root: &'a Value, pointer: &str) -> Option<&'a Value> {
    if pointer.is_empty() { Some(root) } else { root.pointer(pointer) }
}

/// Error messages for a user's schema from the `jsonschema` crate, in networknt 1.0.x wording: only for a schema
/// whose remote `$ref` the crate fetched (`mockserver.jsonSchemaAllowRemoteRefs`) but `crate::networknt` has no
/// document for (one built without `networknt::prefetch_remote`, which reads them for the matchers).
fn messages(validator: &Validator, value: &Value) -> Vec<String> {
    let mut out = Vec::new();
    for error in validator.iter_errors(value) {
        let at = error.instance_path().as_str().to_string();
        let path = json_path("$", &at);
        match error.kind() {
            ValidationErrorKind::AdditionalProperties { unexpected } => {
                for key in unexpected {
                    out.push(format!("{path}.{key}{NOT_DEFINED}"));
                }
            }
            ValidationErrorKind::Required { property } => {
                let name = property.as_str().map(str::to_string).unwrap_or_else(|| property.to_string());
                out.push(format!("{path}.{name}: is missing but it is required"));
            }
            ValidationErrorKind::Type { kind } => {
                let found = pointer(value, &at).map(type_name).unwrap_or("null");
                let expected = format!("{kind:?}").to_lowercase();
                let expected = expected
                    .trim_start_matches("single(")
                    .trim_start_matches("multiple(")
                    .trim_end_matches(')')
                    .to_string();
                out.push(format!("{path}: {found} found, {expected} expected"));
            }
            ValidationErrorKind::Enum { options } => {
                // `EnumValidator`: each allowed value as JSON (strings quoted).
                out.push(format!("{path}: does not have a value in the enumeration {}", json_list(options)));
            }
            ValidationErrorKind::OneOfNotValid { context }
                if pointer(value, &at).is_some_and(Value::is_object)
                    && !context.is_empty()
                    && context.iter().all(|branch| !branch.is_empty() && branch.iter().all(|e| matches!(e.kind(), ValidationErrorKind::Required { .. }))) =>
            {
                // A oneOf of `required` branches: each branch's missing property, then the summary.
                for branch in context {
                    for e in branch {
                        if let ValidationErrorKind::Required { property } = e.kind() {
                            out.push(format!("{path}.{}: is missing but it is required", property.as_str().unwrap_or_default()));
                        }
                    }
                }
                out.push(format!("{path}: should be valid to one and only one schema, but 0 are valid"));
            }
            ValidationErrorKind::OneOfNotValid { .. } if !pointer(value, &at).is_some_and(Value::is_object) => {
                let instance = pointer(value, &at).cloned().unwrap_or(Value::Null);
                out.push(format!("{path}: {} found, string expected", type_name(&instance)));
                out.push(format!("{path}: should be valid to one and only one schema, but 0 are valid"));
            }
            ValidationErrorKind::AnyOf { .. } | ValidationErrorKind::OneOfNotValid { .. } => {
                out.push(format!("{path}: should be valid to any of the schemas defined for {}", last_segment(&path)));
            }
            other => out.push(format!("{path}: {}", describe(other))),
        }
    }
    out
}

/// `JsonSchemaValidator.isValid(json, false)` for a user's `schema` (a schema-valued parameter, header or body),
/// evaluated by networknt's rules (`crate::networknt`): the report under its `N error(s):` heading, the
/// `InvalidSchemaRefException` text for a reference that does not resolve, empty when `instance` is valid — which is
/// also the match decision (`JsonSchemaMatcher.matches`). `validator` (the `jsonschema` crate's build of the same
/// schema) reports only when the schema reaches a remote document it fetched.
pub fn value_report(validator: Option<&Validator>, schema: &Value, instance: &Value) -> String {
    let thrown = |report: String| {
        crate::matcher::string::note_schema_exception(&report, &instance.to_string());
        report
    };
    match crate::networknt::validate_user(schema, instance) {
        Ok(errors) if errors.is_empty() => String::new(),
        Ok(errors) => format_report(errors, Kind::Other, false),
        Err(crate::networknt::Halt::Unresolved(reference)) => thrown(format!("{INVALID_SCHEMA_REF}Reference {reference} cannot be resolved")),
        Err(crate::networknt::Halt::Failed(report)) => thrown(report),
        Err(crate::networknt::Halt::Remote(reference)) => match validator {
            Some(validator) => {
                let errors = messages(validator, instance);
                if errors.is_empty() { String::new() } else { format_report(errors, Kind::Other, false) }
            }
            None => thrown(format!("{INVALID_SCHEMA_REF}Reference {reference} cannot be resolved")),
        },
    }
}

/// Whether `instance` satisfies a user's `schema` (`isValid` returned no report).
pub fn value_matches(validator: Option<&Validator>, schema: &Value, instance: &Value) -> bool {
    value_report(validator, schema, instance).is_empty()
}

fn last_segment(path: &str) -> &str {
    path.rsplit('.').next().unwrap_or(path)
}

fn json_list(v: &Value) -> String {
    match v {
        Value::Array(items) => format!("[{}]", items.iter().map(Value::to_string).collect::<Vec<_>>().join(", ")),
        other => other.to_string(),
    }
}

fn describe(kind: &ValidationErrorKind) -> String {
    match kind {
        ValidationErrorKind::Minimum { limit } => format!("must have a minimum value of {limit}"),
        ValidationErrorKind::Maximum { limit } => format!("must have a maximum value of {limit}"),
        ValidationErrorKind::Pattern { pattern } => format!("does not match the regex pattern {pattern}"),
        ValidationErrorKind::MinLength { limit } => format!("must be at least {limit} characters long"),
        other => format!("{other:?}"),
    }
}
