//! `WireMockTemplateTranslator`: the plain request references of WireMock's Handlebars templates as MockServer
//! Mustache (`{{request.query.x}}` → `{{request.queryStringParameters.x.0}}`) or after-action runtime expressions
//! (`{{originalRequest.headers.X}}` → `{$request.header.X}`). Helpers, block sections and triple-stash tags are
//! reported as untranslatable, so the importer keeps the text verbatim and warns.

use std::sync::LazyLock;

use crate::java_text::split;

static TAG: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"(?s)\{\{(\{?)(.*?)(\}?)\}\}").unwrap());
static REQUEST_VALUE: LazyLock<fancy_regex::Regex> =
    LazyLock::new(|| fancy_regex::Regex::new(r"\{\{\{?[ \t\n\x0B\f\r]*request\.(?!method[ \t\n\x0B\f\r]*\}\})").unwrap());
static BRACKETED_SEGMENT: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"\.?\[([^\]]*)\]").unwrap());
static NUMBER: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"^[0-9]{1,4}$").unwrap());
static PATH_INDEX: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"^request\.path\.[0-9]+$").unwrap());
static JSON_PATH_HELPER: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"^jsonPath[ \t\n\x0B\f\r]+originalRequest\.body[ \t\n\x0B\f\r]+'([^']*)'$").unwrap());
static SIMPLE_JSON_PATH: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"^\$((?:\.[A-Za-z_][A-Za-z0-9_-]*|\[[0-9]+\])+)$").unwrap());

/// A translation: the text, whether it had any tag, and the original tags that could not be translated (when any,
/// `text` is not usable).
pub struct Translation {
    pub text: String,
    pub has_tags: bool,
    pub untranslatable: Vec<String>,
}

/// What the request matcher fixes about the path: the exact path (`urlPath` / `url`), and whether the stub
/// matches a `urlPathTemplate`, whose named parameters are MockServer path parameters.
pub struct PathContext {
    pub exact_path: Option<String>,
    pub path_template: bool,
}

pub fn has_tags(text: Option<&str>) -> bool {
    text.is_some_and(|t| TAG.is_match(t))
}

/// True when the text renders a request value a client chooses (anything but the method).
pub fn references_request_values(text: Option<&str>) -> bool {
    text.is_some_and(|t| REQUEST_VALUE.is_match(t).unwrap_or(false))
}

/// `toMustache`.
pub fn to_mustache(text: &str, path: &PathContext) -> Translation {
    translate(text, |triple_stash, expression| if triple_stash { None } else { mustache_replacement(&normalise(expression), path) })
}

/// `toRuntimeExpressions`.
pub fn to_runtime_expressions(text: &str) -> Translation {
    translate(text, |_, expression| {
        let trimmed = java_trim(expression);
        if let Some(c) = JSON_PATH_HELPER.captures(trimmed) {
            return json_pointer(&c[1]).map(|p| format!("{{$request.body#{p}}}"));
        }
        let normalised = normalise(trimmed);
        let parts = split(&normalised, ".");
        match parts.as_slice() {
            ["originalRequest", "method"] => Some("{$request.method}".into()),
            ["originalRequest", "headers", name] => Some(format!("{{$request.header.{name}}}")),
            ["originalRequest", "query", name] => Some(format!("{{$request.query.{name}}}")),
            _ => None,
        }
    })
}

fn translate(text: &str, translator: impl Fn(bool, &str) -> Option<String>) -> Translation {
    let mut out = String::new();
    let mut untranslatable = Vec::new();
    let mut has_tags = false;
    let mut last = 0;
    for c in TAG.captures_iter(text) {
        has_tags = true;
        let whole = c.get(0).unwrap();
        let tag = whole.as_str();
        let triple_stash = !c[1].is_empty() && !c[3].is_empty();
        let replacement = translator(triple_stash, java_trim(&c[2])).unwrap_or_else(|| {
            untranslatable.push(tag.to_string());
            tag.to_string()
        });
        out.push_str(&text[last..whole.start()]);
        out.push_str(&replacement);
        last = whole.end();
    }
    out.push_str(&text[last..]);
    Translation { text: out, has_tags, untranslatable }
}

/// One `request.*` reference on the MockServer Mustache request model; a reference with whitespace is a helper.
fn mustache_replacement(expression: &str, path: &PathContext) -> Option<String> {
    if expression.starts_with("request.pathSegments.") || PATH_INDEX.is_match(expression) {
        let index = &expression[expression.rfind('.').unwrap() + 1..];
        return if NUMBER.is_match(index) { literal_path_segment(index, path) } else { None };
    }
    mustache_expression(expression, path).map(|e| format!("{{{{{e}}}}}"))
}

fn mustache_expression(expression: &str, path: &PathContext) -> Option<String> {
    if expression.is_empty() || !expression.starts_with("request.") || expression.chars().any(char::is_whitespace) {
        return None;
    }
    let parts = split(expression, ".");
    if parts.len() < 2 {
        return None;
    }
    match parts[1] {
        "method" | "body" => (parts.len() == 2).then(|| expression.to_string()),
        "path" if parts.len() == 2 => Some(expression.to_string()),
        "path" => (parts.len() == 3 && path.path_template).then(|| format!("request.pathParameters.{}.0", parts[2])),
        "query" => multi_valued("request.queryStringParameters.", &parts),
        "headers" => multi_valued("request.headers.", &parts),
        "cookies" => (parts.len() == 3).then(|| expression.to_string()),
        _ => None,
    }
}

fn multi_valued(prefix: &str, parts: &[&str]) -> Option<String> {
    match parts.len() {
        3 => Some(format!("{prefix}{}.0", parts[2])),
        4 if NUMBER.is_match(parts[3]) => Some(format!("{prefix}{}.{}", parts[2], parts[3])),
        _ => None,
    }
}

/// A path segment of an exact-path stub is fixed by the matcher, so it renders as a literal.
fn literal_path_segment(index: &str, path: &PathContext) -> Option<String> {
    let exact = path.exact_path.as_deref()?;
    let trimmed = exact.strip_prefix('/').unwrap_or(exact);
    let segments = split(trimmed, "/");
    let i: usize = index.parse().ok()?;
    let segment = segments.get(i)?;
    (!segment.contains('{') && !segment.contains('}')).then(|| segment.to_string())
}

/// Handlebars' `a.[b]` and `a.[0]` segment literals as plain dotted names.
fn normalise(expression: &str) -> String {
    BRACKETED_SEGMENT.replace_all(expression, ".${1}").into_owned()
}

fn json_pointer(json_path: &str) -> Option<String> {
    let c = SIMPLE_JSON_PATH.captures(json_path)?;
    let indexed = regex::Regex::new(r"\[([0-9]+)\]").unwrap().replace_all(&c[1], ".${1}").into_owned();
    Some(indexed.replace('~', "~0").replace('.', "/"))
}

/// `String.trim()`: every leading and trailing char at or below U+0020.
fn java_trim(s: &str) -> &str {
    s.trim_matches(|c: char| c <= ' ')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(exact: Option<&str>, template: bool) -> PathContext {
        PathContext { exact_path: exact.map(str::to_string), path_template: template }
    }

    #[test]
    fn mustache_references() {
        let t = to_mustache("{{request.path}} {{request.query.q}} {{request.headers.[X-A].1}} {{request.pathSegments.[1]}} {{request.path.id}}", &ctx(Some("/a/b"), true));
        assert_eq!(t.text, "{{request.path}} {{request.queryStringParameters.q.0}} {{request.headers.X-A.1}} b {{request.pathParameters.id.0}}");
        assert!(t.untranslatable.is_empty() && t.has_tags);
        let t = to_mustache("{{{request.body}}} {{now}} {{request.path.0}}", &ctx(None, false));
        assert_eq!(t.untranslatable, vec!["{{{request.body}}}", "{{now}}", "{{request.path.0}}"]);
        assert!(references_request_values(Some("{{ request.path }}")) && !references_request_values(Some("{{request.method}}")));
    }

    #[test]
    fn runtime_expressions() {
        let t = to_runtime_expressions("{{originalRequest.method}} {{originalRequest.headers.X}} {{jsonPath originalRequest.body '$.a[0].b'}} {{x}}");
        assert_eq!(t.text, "{$request.method} {$request.header.X} {$request.body#/a/0/b} {{x}}");
        assert_eq!(t.untranslatable, vec!["{{x}}"]);
    }
}
