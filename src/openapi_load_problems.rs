//! `OpenAPILoadProblems` (9.1.0): swagger-parser's messages about a spec turned into problems grouped by kind, each
//! located by a JSON pointer (such as `#/paths/~1pets/get/responses/200`) or, for a syntax error, by line and
//! column. swagger-parser names a location as a dotted path (`paths.'/pets'(get).responses.200`); the pointer is
//! derived from it on a best-effort basis, so it names the nearest object swagger-parser reports.

use serde_json::{Map, Value};
use std::sync::LazyLock;

use regex::Regex;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kind {
    Syntax,
    Unreadable,
    Ref,
    WrongType,
    Missing,
    Duplicate,
    InvalidPath,
    Unexpected,
    Other,
}

impl Kind {
    /// The enum constant's name.
    pub fn name(self) -> &'static str {
        match self {
            Kind::Syntax => "SYNTAX",
            Kind::Unreadable => "UNREADABLE",
            Kind::Ref => "REF",
            Kind::WrongType => "WRONG_TYPE",
            Kind::Missing => "MISSING",
            Kind::Duplicate => "DUPLICATE",
            Kind::InvalidPath => "INVALID_PATH",
            Kind::Unexpected => "UNEXPECTED",
            Kind::Other => "OTHER",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Kind::Syntax => "syntax error",
            Kind::Unreadable => "spec could not be read",
            Kind::Ref => "unresolved or mistyped $ref",
            Kind::WrongType => "wrong value type",
            Kind::Missing => "missing required field",
            Kind::Duplicate => "duplicate value",
            Kind::InvalidPath => "invalid path",
            Kind::Unexpected => "unexpected or unsupported field",
            Kind::Other => "other problem",
        }
    }
}

/// One problem; `location` is a JSON pointer, `line N, column M`, or `None` when the message names no location.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Problem {
    pub kind: Kind,
    pub location: Option<String>,
    pub description: String,
    pub hint: Option<String>,
}

impl Problem {
    fn new(kind: Kind, location: Option<String>, description: impl Into<String>, hint: Option<&str>) -> Problem {
        Problem { kind, location, description: description.into(), hint: hint.map(str::to_string) }
    }

    /// `Problem.writeTo`: `kind`, `kindLabel`, `description` and, when known, `location` and `hint`, after whatever
    /// `node` already holds.
    pub fn write_to(&self, node: &mut Map<String, Value>) {
        node.insert("kind".into(), Value::String(self.kind.name().into()));
        node.insert("kindLabel".into(), Value::String(self.kind.label().into()));
        if let Some(location) = &self.location {
            node.insert("location".into(), Value::String(location.clone()));
        }
        node.insert("description".into(), Value::String(self.description.clone()));
        if let Some(hint) = &self.hint {
            node.insert("hint".into(), Value::String(hint.clone()));
        }
    }
}

static ATTRIBUTE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?s)\Aattribute (.+) is (unexpected|missing|unsupported|repeated|reserved by The OpenAPI Initiative|not of type `(.*)`)\z").expect("valid")
});
static YAML_LINE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"line ([0-9]+), column ([0-9]+)").expect("valid"));
static JSON_LINE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"line: ([0-9]+), column: ([0-9]+)").expect("valid"));
static JSON_SYNTAX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\A(Unexpected (end-of-input|character)|Unrecognized (token|character)|Illegal (character|unquoted)|Duplicate field|Invalid UTF)").expect("valid")
});
static YAML_SYNTAX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\A(while (parsing|scanning)|mapping values are not allowed|found character|expected |could not find expected|did not find expected|found undefined alias)").expect("valid")
});
/// Java's `.` stops at any line terminator.
static INVALID_PATH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\AResource ([^\n\r\u{85}\u{2028}\u{2029}]+) should start with /\z").expect("valid"));
const ROOT_FIELDS: &[&str] = &["openapi", "info", "servers", "paths", "components", "webhooks", "security", "tags", "externalDocs", "jsonSchemaDialect"];

const TAB_HINT: &str = "YAML does not allow tabs for indentation: replace each tab with spaces";
const READ_HINT: &str = "check that the file path, classpath resource or URL is correct and that MockServer can read it";
const REF_HINT: &str = "check that the $ref target exists (names are case-sensitive) and that any referenced file can be read";
const PATH_HINT: &str = "each key under paths must start with '/', for example /pets";
const TYPE_HINT: &str = "in OpenAPI 3.0 a schema's type is a single string; a list of types needs OpenAPI 3.1";
const DUPLICATE_OPERATION_ID_HINT: &str = "operationIds must be unique: MockServer keeps both operations but renames the later one by appending \" (2)\"";

/// `Character.isWhitespace`.
fn java_whitespace(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\u{0B}' | '\u{0C}' | '\r' | '\u{1C}'..='\u{1F}' | ' ')
        || matches!(c as u32, 0x1680 | 0x2000..=0x2006 | 0x2008..=0x200A | 0x2028 | 0x2029 | 0x205F | 0x3000)
}

/// `problems`: one problem per distinct non-blank message, in first-seen order.
pub fn problems<S: AsRef<str>>(messages: &[S]) -> Vec<Problem> {
    let mut seen = std::collections::HashSet::new();
    messages
        .iter()
        .map(AsRef::as_ref)
        .filter(|m| seen.insert(*m))
        .filter(|m| !m.chars().all(java_whitespace))
        .map(|m| problem(m.trim_matches(java_whitespace)))
        .collect()
}

/// `describe`: the messages' problems grouped by kind ([`describe_problems`]).
pub fn describe<S: AsRef<str>>(messages: &[S]) -> String {
    describe_problems(&problems(messages))
}

/// `describeProblems`, for example
/// ```text
/// 1 problem found:
///
///   missing required field (1):
///     - #/info: required field 'version' is missing
/// ```
pub fn describe_problems(problems: &[Problem]) -> String {
    let mut by_kind: std::collections::BTreeMap<Kind, Vec<&Problem>> = Default::default();
    for problem in problems {
        by_kind.entry(problem.kind).or_default().push(problem);
    }
    let mut text = format!("{} {} found:", problems.len(), if problems.len() == 1 { "problem" } else { "problems" });
    for (kind, group) in by_kind {
        text.push_str(&format!("\n\n  {} ({}):", kind.label(), group.len()));
        for problem in group {
            let line = match &problem.location {
                Some(location) => format!("{location}: {}", problem.description),
                None => problem.description.clone(),
            };
            text.push_str("\n    - ");
            text.push_str(&line.replace("\r\n", "\n").replace('\n', "\n      "));
            if let Some(hint) = &problem.hint {
                text.push_str("\n      hint: ");
                text.push_str(hint);
            }
        }
    }
    text
}

/// `problem`: one stripped message.
pub fn problem(message: &str) -> Problem {
    if is_syntax_error(message) {
        let hint = message.contains("(TAB)").then_some(TAB_HINT);
        return Problem::new(Kind::Syntax, line_and_column(message), message, hint);
    }
    if message.starts_with("Unable to read location") {
        return Problem::new(Kind::Unreadable, None, message, Some(READ_HINT));
    }
    if message.starts_with("Unable to load RELATIVE ref") || message.starts_with("Unable to load REMOTE ref") || message.starts_with("Could not find") {
        return Problem::new(Kind::Ref, None, message, Some(REF_HINT));
    }
    if let Some(attribute) = ATTRIBUTE.captures(message) {
        return attribute_problem(&attribute[1], &attribute[2], attribute.get(3).map(|m| m.as_str()));
    }
    warning(message)
}

fn attribute_problem(attribute: &str, problem: &str, expected_type: Option<&str>) -> Problem {
    if let Some(ref_start) = attribute.find(".#/").filter(|_| problem == "missing") {
        let reference = &attribute[ref_start + 1..];
        return Problem::new(
            Kind::Ref,
            Some(pointer(&tokens(&attribute[..ref_start]), Some("$ref"))),
            format!("$ref target {reference} does not exist"),
            Some(REF_HINT),
        );
    }
    let tokens = tokens(attribute);
    let field = tokens.last().map_or(attribute, String::as_str).to_string();
    let parent = if tokens.is_empty() { &tokens[..] } else { &tokens[..tokens.len() - 1] };
    match problem {
        "missing" => Problem::new(Kind::Missing, Some(pointer(parent, None)), format!("required field '{field}' is missing"), None),
        "repeated" => {
            let operation_id = field == "operationId";
            Problem::new(
                Kind::Duplicate,
                Some(pointer(&tokens, None)),
                format!("'{field}' is repeated{}", if operation_id { "" } else { ", it must be unique" }),
                operation_id.then_some(DUPLICATE_OPERATION_ID_HINT),
            )
        }
        "unexpected" => Problem::new(Kind::Unexpected, Some(pointer(&tokens, None)), format!("field '{field}' is not allowed here"), None),
        "unsupported" => Problem::new(Kind::Unexpected, Some(pointer(&tokens, None)), format!("field '{field}' is not supported"), None),
        "reserved by The OpenAPI Initiative" => {
            Problem::new(Kind::Unexpected, Some(pointer(&tokens, None)), format!("field '{field}' is reserved by The OpenAPI Initiative"), None)
        }
        _ => {
            let expected_type = expected_type.unwrap_or("null");
            if expected_type == "schema" {
                // swagger-parser's internal $ref check reports a missing #/components/schemas/<name> target this way
                return Problem::new(
                    Kind::Ref,
                    Some(pointer(parent, None)),
                    format!("$ref target #/components/schemas/{field} does not exist"),
                    Some(REF_HINT),
                );
            }
            let hint = (field == "type").then_some(TYPE_HINT);
            Problem::new(Kind::WrongType, Some(pointer(&tokens, None)), format!("'{field}' is not of type `{expected_type}`"), hint)
        }
    }
}

/// swagger-parser writes a warning as its dotted location, a '.', then free text.
fn warning(message: &str) -> Problem {
    if let Some(text_start) = warning_text_start(message).filter(|&s| s > 0) {
        let tokens = tokens(&message[..text_start - 1]);
        if tokens.first().is_some_and(|t| ROOT_FIELDS.contains(&t.as_str())) {
            let text = message[text_start..].trim_matches(java_whitespace);
            if let Some(invalid_path) = INVALID_PATH.captures(text) {
                let path = &invalid_path[1];
                return Problem::new(Kind::InvalidPath, Some(pointer(&tokens, Some(path))), format!("path '{path}' does not start with /"), Some(PATH_HINT));
            } else if text.starts_with("$ref target") {
                return Problem::new(Kind::Ref, Some(pointer(&tokens, None)), text, Some(REF_HINT));
            }
            return Problem::new(Kind::Other, Some(pointer(&tokens, None)), text, None);
        }
    }
    Problem::new(Kind::Other, None, message, None)
}

/// The index just after the separator '.' that precedes the first unquoted segment holding a space, if any.
fn warning_text_start(message: &str) -> Option<usize> {
    let mut segment_start = 0;
    let mut quoted = false;
    for (i, c) in message.char_indices() {
        if c == '\'' {
            quoted = !quoted;
        } else if !quoted && c == '.' {
            segment_start = i + 1;
        } else if !quoted && java_whitespace(c) {
            return Some(segment_start);
        }
    }
    None
}

/// Splits a swagger-parser location such as `paths.'/pets'(get).responses.200` into `[paths, /pets, get, responses, 200]`.
pub fn tokens(location: &str) -> Vec<String> {
    let bytes = location.as_bytes();
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'\'' && current.is_empty() && let Some(close) = closing_quote(bytes, i) {
            current.push_str(&location[i + 1..close]);
            i = close + 1;
        } else if c == b'('
            && let Some(close) = location[i..].find(')').map(|o| o + i)
            && (close + 1 == bytes.len() || bytes[close + 1] == b'.')
        {
            add_token(&mut tokens, &mut current);
            current.push_str(&location[i + 1..close]);
            add_token(&mut tokens, &mut current);
            i = close + 1;
        } else if c == b'.' {
            add_token(&mut tokens, &mut current);
            i += 1;
        } else {
            let ch = location[i..].chars().next().expect("on a char boundary");
            current.push(ch);
            i += ch.len_utf8();
        }
    }
    add_token(&mut tokens, &mut current);
    tokens
}

fn closing_quote(bytes: &[u8], open: usize) -> Option<usize> {
    (open + 1..bytes.len()).find(|&i| bytes[i] == b'\'' && (i + 1 == bytes.len() || bytes[i + 1] == b'.' || bytes[i + 1] == b'('))
}

fn add_token(tokens: &mut Vec<String>, current: &mut String) {
    if !current.is_empty() {
        tokens.push(std::mem::take(current));
    }
}

/// swagger-parser names a parameter list without an index, so a pointer into an operation's or path's parameters
/// stops at the parameters array.
pub fn pointer(tokens: &[String], last: Option<&str>) -> String {
    let mut pointer = String::from("#");
    for (i, token) in tokens.iter().enumerate() {
        pointer.push('/');
        pointer.push_str(&escape(token));
        if token == "parameters" && (i == 0 || tokens[i - 1] != "components") {
            return pointer;
        }
    }
    if let Some(last) = last {
        pointer.push('/');
        pointer.push_str(&escape(last));
    }
    pointer
}

fn escape(token: &str) -> String {
    token.replace('~', "~0").replace('/', "~1")
}

fn is_syntax_error(message: &str) -> bool {
    YAML_SYNTAX.is_match(message) || JSON_SYNTAX.is_match(message) || message.contains(" in 'reader', line ") || message.contains(" in 'string', line ")
}

/// The last `line N, column M` of the message (YAML's form first, then Jackson's `line: N, column: M`).
fn line_and_column(message: &str) -> Option<String> {
    [&*YAML_LINE, &*JSON_LINE]
        .into_iter()
        .find_map(|pattern| pattern.captures_iter(message).last().map(|m| format!("line {}, column {}", &m[1], &m[2])))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `OpenAPILoadProblemsTest.shouldConvertSwaggerParserLocationsToJsonPointers`.
    #[test]
    fn converts_swagger_parser_locations_to_json_pointers() {
        let location = |m: &str| problem(m).location;
        assert_eq!(
            location("attribute paths.'/v1.0/pets~old'(post).requestBody.content.'application/json'.schema.type is not of type `string`").as_deref(),
            Some("#/paths/~1v1.0~1pets~0old/post/requestBody/content/application~1json/schema/type")
        );
        assert_eq!(location("attribute webhooks.'newPet'(post).responses.200.description is missing").as_deref(), Some("#/webhooks/newPet/post/responses/200"));
        assert_eq!(location("attribute paths.'/pets'(get).parameters.schemas.type is not of type `string`").as_deref(), Some("#/paths/~1pets/get/parameters"));
        assert_eq!(
            location("attribute components.parameters.limit.in is not of type `[query|header|path|cookie]`").as_deref(),
            Some("#/components/parameters/limit/in")
        );
        assert_eq!(location("attribute openapi is missing").as_deref(), Some("#"));
        assert_eq!(location("The provided definition does not specify a valid version field"), None);
    }

    #[test]
    fn groups_by_kind_in_declaration_order() {
        let text = describe(&["paths. Resource pets should start with /", "attribute info.version is missing", "attribute info.version is missing"]);
        assert_eq!(
            text,
            "2 problems found:\n\n  missing required field (1):\n    - #/info: required field 'version' is missing\n\n  invalid path (1):\n    - #/paths/pets: path 'pets' does not start with /\n      hint: each key under paths must start with '/', for example /pets"
        );
    }
}
