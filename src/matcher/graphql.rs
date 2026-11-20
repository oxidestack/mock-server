//! `GRAPHQL` bodies (`GraphQLMatcher`, `GraphQLAstMatcher`): the query compared as a normalised string, or by its
//! operation and top-level fields (`AST_EXACT`, `AST_SUBSET`), with the operation name and a variables schema.

use serde_json::Value;

/// `SelectionSetMatchType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    NormalisedString,
    AstExact,
    AstSubset,
}

impl Mode {
    pub fn parse(v: Option<&str>) -> Option<Mode> {
        match v? {
            "NORMALISED_STRING" => Some(Mode::NormalisedString),
            "AST_EXACT" => Some(Mode::AstExact),
            "AST_SUBSET" => Some(Mode::AstSubset),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Mode::NormalisedString => "NORMALISED_STRING",
            Mode::AstExact => "AST_EXACT",
            Mode::AstSubset => "AST_SUBSET",
        }
    }
}

/// `GraphQLAstMatcher`: operation type, name and top-level fields, found by scanning the text.
#[derive(Debug)]
pub struct AstMatcher {
    mode: Mode,
    op_type: String,
    op_name: String,
    fields: Vec<String>,
}

impl AstMatcher {
    pub fn new(query: &str, mode: Mode, fields: &[String]) -> AstMatcher {
        let fields = if fields.is_empty() { top_level_fields(query) } else { dedup(fields.to_vec()) };
        AstMatcher { mode, op_type: operation_type(query), op_name: operation_name(query), fields }
    }

    pub fn matches(&self, body: &str) -> bool {
        if body.trim().is_empty() {
            return false;
        }
        let actual = query_from_body(body);
        if !self.op_type.is_empty() && !self.op_type.eq_ignore_ascii_case(&operation_type(&actual)) {
            return false;
        }
        if !self.op_name.is_empty() && self.op_name != operation_name(&actual) {
            return false;
        }
        let actual_fields = top_level_fields(&actual);
        match self.mode {
            Mode::AstExact => {
                actual_fields.len() == self.fields.len() && self.fields.iter().all(|f| actual_fields.contains(f))
            }
            Mode::AstSubset => self.fields.iter().all(|f| actual_fields.contains(f)),
            Mode::NormalisedString => false,
        }
    }
}

fn dedup(items: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for item in items {
        if !out.contains(&item) {
            out.push(item);
        }
    }
    out
}

/// `extractQueryFromBody`: the `query` of a JSON body, found with a regex and unescaped, else the body itself.
fn query_from_body(body: &str) -> String {
    let trimmed = body.trim();
    if trimmed.starts_with('{') && trimmed.contains("\"query\"") {
        static QUERY: std::sync::LazyLock<regex::Regex> =
            std::sync::LazyLock::new(|| regex::Regex::new(r#""query"\s*:\s*"((?:[^"\\]|\\.)*)""#).expect("valid"));
        if let Some(c) = QUERY.captures(trimmed) {
            return c[1].replace("\\n", "\n").replace("\\t", "\t").replace("\\\"", "\"").replace("\\\\", "\\");
        }
    }
    trimmed.to_string()
}

fn strip_comments(query: &str) -> String {
    query.lines().map(|l| l.split('#').next().unwrap_or_default()).collect::<Vec<_>>().join("\n")
}

/// `extractOperationType`.
fn operation_type(query: &str) -> String {
    let trimmed = strip_comments(query);
    let trimmed = trimmed.trim();
    if trimmed.starts_with('{') {
        return "query".into();
    }
    let word: String = trimmed.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
    let lower = word.to_lowercase();
    if matches!(lower.as_str(), "query" | "mutation" | "subscription") { lower } else { "query".into() }
}

/// `extractOperationName`: the name after `query`/`mutation`/`subscription`.
fn operation_name(query: &str) -> String {
    let stripped = strip_comments(query);
    let trimmed = stripped.trim();
    let word: String = trimmed.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
    if !matches!(word.to_lowercase().as_str(), "query" | "mutation" | "subscription") {
        return String::new();
    }
    let rest = &trimmed[word.len()..];
    if !rest.starts_with(char::is_whitespace) {
        return String::new();
    }
    rest.trim_start().chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect()
}

/// `extractTopLevelFields`: the names at depth one of the first selection set, arguments skipped.
fn top_level_fields(query: &str) -> Vec<String> {
    let body = strip_comments(query);
    let body = body.trim();
    let mut fields: Vec<String> = Vec::new();
    let Some(start) = body.find('{') else { return fields };
    let (mut depth, mut paren, mut in_string, mut escaped) = (0i32, 0i32, false, false);
    let mut name = String::new();
    let add = |name: &mut String, fields: &mut Vec<String>| {
        let n = std::mem::take(name);
        if n != "on" && n != "fragment" && !fields.contains(&n) {
            fields.push(n);
        }
    };
    for c in body[start..].chars() {
        if in_string {
            if c == '"' && !escaped {
                in_string = false;
            }
            escaped = c == '\\' && !escaped;
            continue;
        }
        escaped = false;
        match c {
            '"' => in_string = true,
            '(' => {
                if depth == 1 && !name.is_empty() {
                    add(&mut name, &mut fields);
                }
                paren += 1;
            }
            ')' => paren -= 1,
            _ if paren > 0 => {}
            '{' => {
                if depth == 1 && !name.is_empty() {
                    add(&mut name, &mut fields);
                }
                depth += 1;
            }
            '}' => {
                if depth == 1 && !name.is_empty() {
                    add(&mut name, &mut fields);
                }
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            _ if depth == 1 => {
                if c.is_alphanumeric() || c == '_' {
                    name.push(c);
                } else if !name.is_empty() {
                    add(&mut name, &mut fields);
                }
            }
            _ => {}
        }
    }
    fields
}

/// `GraphQLMatcher.normalizeQuery`: whitespace, commas and comments collapsed, strings kept.
pub fn normalize_query(query: &str) -> String {
    const PUNCTUATION: &[char] = &['{', '}', '(', ')', ':', '!', '@', '[', ']', '=', '|', '&', '.'];
    let chars: Vec<char> = query.chars().collect();
    let mut out = String::with_capacity(query.len());
    let (mut in_string, mut in_block, mut last_ws) = (false, false, false);
    let mut i = 0;
    let triple = |i: usize| i + 2 < chars.len() && chars[i + 1] == '"' && chars[i + 2] == '"';
    while i < chars.len() {
        let c = chars[i];
        if in_block {
            if c == '"' && triple(i) {
                out.push_str("\"\"\"");
                i += 3;
                in_block = false;
            } else {
                out.push(c);
                i += 1;
            }
            continue;
        }
        if in_string {
            out.push(c);
            if c == '\\' && i + 1 < chars.len() {
                out.push(chars[i + 1]);
                i += 1;
            } else if c == '"' {
                in_string = false;
            }
            i += 1;
            continue;
        }
        if c == '"' {
            last_ws = false;
            if triple(i) {
                out.push_str("\"\"\"");
                i += 3;
                in_block = true;
            } else {
                out.push(c);
                in_string = true;
                i += 1;
            }
            continue;
        }
        if c == '#' {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
            last_ws = true;
            continue;
        }
        if c.is_whitespace() || c == ',' {
            last_ws = true;
            i += 1;
            continue;
        }
        if last_ws && !PUNCTUATION.contains(&c) && out.chars().last().is_some_and(|p| !PUNCTUATION.contains(&p)) {
            out.push(' ');
        }
        last_ws = false;
        out.push(c);
        i += 1;
    }
    out
}

/// `GraphQLMatcher`.
#[derive(Debug)]
pub struct GraphQl {
    query: Option<String>,
    operation_name: Option<String>,
    /// `Pattern.compile(…)`, matched with `matcher(…).matches()`.
    pattern: Option<std::sync::Arc<super::java_pattern::JavaRegex>>,
    /// The Java replay of `pattern`, under `regexMatchingTimeoutMillis` (`matchesWithRegexTimeout`).
    java: Option<super::string::DescribedRegex>,
    variables_schema: Option<String>,
    variables: Option<jsonschema::Validator>,
    mode: Option<Mode>,
    ast: Option<AstMatcher>,
}

impl GraphQl {
    pub fn compile(o: &serde_json::Map<String, Value>) -> GraphQl {
        let text = |k: &str| o.get(k).and_then(Value::as_str).map(str::to_string);
        let raw_query = text("query");
        let operation_name = text("operationName").filter(|n| !n.trim().is_empty());
        let literal = |n: &str| n.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '/' | '.' | '-'));
        let pattern = operation_name.as_deref().filter(|n| !literal(n)).and_then(|n| super::java_pattern::compile(n).ok());
        let java = pattern.as_ref().and(operation_name.as_deref()).map(|n| super::string::DescribedRegex::compile("graphql operationName", n));
        let variables_schema = text("variablesSchema").filter(|s| !s.trim().is_empty());
        let variables = variables_schema.as_deref().and_then(|s| serde_json::from_str::<Value>(s).ok()).and_then(|s| super::string::validator(&s).ok());
        let mode = Mode::parse(o.get("selectionSetMatchType").and_then(Value::as_str));
        let fields: Vec<String> = o.get("fields").and_then(Value::as_array).map(|f| f.iter().filter_map(Value::as_str).map(str::to_string).collect()).unwrap_or_default();
        let ast = mode.filter(|m| *m != Mode::NormalisedString).map(|m| AstMatcher::new(raw_query.as_deref().unwrap_or_default(), m, &fields));
        GraphQl { query: raw_query.map(|q| normalize_query(&q)), operation_name, pattern, java, variables_schema, variables, mode, ast }
    }

    /// Whether the body matches, and the difference recorded when it does not.
    pub fn matches(&self, body: &str) -> (bool, Option<String>) {
        let format = |f: &str, args: &[&str]| Some(super::format_log_message(1, f, args));
        let query = self.query.as_deref().filter(|q| !q.trim().is_empty());
        let Some(query) = query else {
            return (false, format("graphql match failed expected query:{}found:{}failed because:{}", &["null", body, "query was null"]));
        };
        if body.trim().is_empty() {
            return (false, format("graphql match failed expected query:{}found:{}failed because:{}", &[query, "null", "request body was empty"]));
        }
        if let Some(ast) = &self.ast {
            if ast.matches(body) {
                return (true, None);
            }
            let mode = self.mode.map(Mode::name).unwrap_or_default();
            return (false, format("graphql AST match failed expected query:{}found:{}mode:{}", &[query, body, mode]));
        }
        // `OBJECT_MAPPER.readTree` (a plain `ObjectMapper`): Jackson's exception text on failure.
        let root = match crate::jnode::read_value_plain(body) {
            Ok(root) => root,
            Err(e) => return (false, format("graphql match failed expected query:{}found:{}failed because:{}", &[query, body, &e])),
        };
        let mut schema_failure = None;
        if self.single(query, &root, &mut schema_failure) {
            return (true, None);
        }
        let failed = super::format_log_message(1, "graphql match failed expected query:{}found:{}failed because:{}", &[query, body, "query did not match or invalid GraphQL format"]);
        (false, Some(schema_failure.map_or(failed.clone(), |s| format!("{s}\n{failed}"))))
    }

    fn single(&self, query: &str, node: &Value, schema_failure: &mut Option<String>) -> bool {
        let text = |v: &Value| v.as_str().map_or_else(|| v.to_string(), str::to_string);
        let Some(actual) = node.get("query").map(text) else { return false };
        if normalize_query(&actual) != query {
            return false;
        }
        if let Some(expected) = &self.operation_name {
            let Some(actual) = node.get("operationName").filter(|n| !n.is_null()).map(text) else { return false };
            let regex_matches = || {
                let linear = || self.pattern.as_ref().is_some_and(|p| p.matches(&actual));
                self.java.as_ref().map_or_else(linear, |j| j.within_budget(&actual, linear))
            };
            if actual != *expected && !regex_matches() {
                return false;
            }
        }
        if let Some(validator) = &self.variables {
            let Some(variables) = node.get("variables") else { return false };
            if !validator.is_valid(variables) {
                let because = validator.iter_errors(variables).map(|e| e.to_string()).collect::<Vec<_>>().join("\n");
                *schema_failure = Some(super::format_log_message(
                    1,
                    "graphql variables schema validation failed expected:{}found:{}failed because:{}",
                    &[self.variables_schema.as_deref().unwrap_or_default(), &variables.to_string(), &because],
                ));
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalises_and_scans_queries() {
        assert_eq!(normalize_query("query  Foo {\n  a,  b # c\n  d(x: 1) { e } }"), "query Foo{a b d(x:1){e}}");
        assert_eq!(top_level_fields("subscription S { onA(id: 1) { x } onB }"), vec!["onA", "onB"]);
        assert_eq!(operation_name("subscription S { a }"), "S");
        assert_eq!(operation_type("{ a }"), "query");
        let m = AstMatcher::new("subscription { onA }", Mode::AstSubset, &[]);
        assert!(m.matches("subscription S { onA { x } onB }"));
        assert!(!m.matches("query { onA }"));
    }
}
