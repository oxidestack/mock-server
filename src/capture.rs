//! `CaptureProcessor`: an expectation's `capture` rules copy values from the request it matched into scenario
//! state, where a later response template reads them (`scenario.get`). Best effort: a rule that finds nothing,
//! or fails, is skipped.

use java_compat::lang::JValue;
use serde_json::Value;

use crate::request::HttpRequest;
use crate::templates::PathMatch;

/// Applies the `capture` rule (an object) or rules (an array) of an expectation's input to `request`.
pub fn process(state: &crate::state::State, rules: Option<&Value>, request: &HttpRequest, path: &PathMatch) {
    let rules: Vec<&Value> = match rules {
        Some(Value::Array(items)) => items.iter().collect(),
        Some(rule @ Value::Object(_)) => vec![rule],
        _ => return,
    };
    for rule in rules {
        let (Some(source), Some(into)) = (rule.get("source").and_then(Value::as_str), rule.get("into").and_then(Value::as_str)) else { continue };
        if into.trim().is_empty() {
            continue;
        }
        let expression = rule.get("expression").and_then(Value::as_str).unwrap_or_default();
        if let Some(value) = extract(source, expression, request, path).filter(|v| !v.trim().is_empty()) {
            state.scenarios().set(into, &value);
        }
    }
}

fn extract(source: &str, expression: &str, request: &HttpRequest, path: &PathMatch) -> Option<String> {
    match source {
        "jsonPath" if !expression.trim().is_empty() => stringify(crate::templates::extract::json_path(request, expression)),
        "xpath" if !expression.trim().is_empty() => Some(crate::templates::extract::xpath(request, expression)),
        "header" => request.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(expression)).and_then(|(_, vs)| vs.first().map(str::to_string)),
        "queryStringParameter" => request.query.iter().find(|(k, _)| k == expression).and_then(|(_, vs)| vs.first().cloned()),
        "pathParameter" => path.parameters.iter().find(|(k, _)| k == expression).and_then(|(_, vs)| vs.first().cloned()),
        "cookie" => request.cookies.iter().find(|(k, _)| k == expression).map(|(_, v)| v.clone()),
        _ => None,
    }
}

/// `CaptureProcessor.stringify`: a one-element list is unwrapped, anything else is its `toString()`.
fn stringify(value: JValue) -> Option<String> {
    match &value {
        JValue::List(items) if items.len() == 1 => items.get(0).map(|v| v.to_java_string()),
        JValue::Null => None,
        other => Some(other.to_java_string()),
    }
}
