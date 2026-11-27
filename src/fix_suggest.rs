//! `ExpectationFixSuggester` (9.1.0, upstream e97463a08): `"suggestFixes": true` on `PUT /mockserver/explainUnmatched`
//! turns the fields on which a recorded request differs from a close expectation into a minimal RFC 6902 JSON patch of
//! that expectation's `httpRequest`, as `retrieve?type=ACTIVE_EXPECTATIONS` echoes it. Each replace and remove is
//! preceded by a `test` of the value it changes, and each object that gains a member by a `test` of that object, so the
//! patch fails once anything it changes has been edited. Read-only: nothing is applied and no match event is written.
//!
//! The model is the canonical JSON form: a field is fixed on a copy of the echo, which is then echoed again
//! ([`canonical::request_definition`]), as upstream re-serialises its patched model.

use serde_json::{Map, Value, json};

use crate::canonical;
use crate::log_redaction::Redaction;
use crate::matcher::{Mode, RequestMatcher};
use crate::model::{self, NString};
use crate::request::{HttpRequest, MultiMap};

/// `EXPLAIN_UNMATCHED_FIXES_PER_REQUEST`: the closest non-matching expectations that get a fix, per request.
pub(crate) const FIXES_PER_REQUEST: usize = 5;
/// `MAX_COPIED_BODY_CHARACTERS`
const MAX_COPIED_BODY_CHARACTERS: usize = 64 * 1024;
const NO_DERIVED_VALUE: &str = "MockServer cannot derive a value for this field from the recorded request; edit it by hand";
/// `MockServerEventLog.TRUNCATED_BODY_HEADER`
const TRUNCATED_BODY_HEADER: &str = "x-mockserver-body-truncated";
/// `MatchDifference.Field` names in declaration order, the order fields are fixed in.
const FIELDS: &[&str] = &crate::matcher::FIELDS;

/// `differingFields`: the field names of a `compareFields` result's `differences`, in declaration order.
pub(crate) fn differing_fields(comparison: &Map<String, Value>) -> Vec<&'static str> {
    let differences = comparison.get("differences").and_then(Value::as_object);
    FIELDS.iter().copied().filter(|f| differences.is_some_and(|d| d.contains_key(*f))).collect()
}

/// `suggest`: `patch`, `patchedFields`, `unpatchedFields` (each with a `reason`) and `matchesAfterPatch`, whether the
/// patched expectation matches the recorded request.
pub(crate) fn suggest(http_request: &Value, recorded: &HttpRequest, fields: &[&str], sensitive: Option<&Redaction>) -> Value {
    // an expectation without `httpRequest` holds an empty request matcher
    let empty = Value::Object(Map::new());
    let http_request = if http_request.is_null() { &empty } else { http_request };
    let mut patch: Vec<Value> = Vec::new();
    let mut patched: Vec<&str> = Vec::new();
    let mut unpatched: Vec<Value> = Vec::new();
    let mut matches_after_patch = false;
    let reason = |field: &str, reason: &str| json!({"field": field, "reason": reason});
    if !is_plain_http_request(http_request) {
        unpatched.push(reason(
            "httpRequest",
            "the expectation does not match on a plain HTTP request definition (for example it matches an OpenAPI operation), so it cannot be patched field by field",
        ));
    } else {
        let body_truncated = recorded.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(TRUNCATED_BODY_HEADER));
        let mut actual = recorded.clone();
        if body_truncated {
            actual.headers.retain(|(k, _)| !k.eq_ignore_ascii_case(TRUNCATED_BODY_HEADER));
        }
        let mut current = http_request.clone();
        for &field in fields {
            if field == "pathParameters" && patched.contains(&"path") {
                // the path fix replaces the path template with the literal path, which drops its path parameters
                patched.push(field);
                continue;
            }
            let mut candidate = current.as_object().cloned().unwrap_or_default();
            if let Some(why) = fix(field, &mut candidate, &actual, body_truncated) {
                unpatched.push(reason(field, &why));
                continue;
            }
            let next = canonical::request_definition(&Value::Object(candidate));
            let mut operations = Vec::new();
            diff("/httpRequest", &current, &next, &mut operations);
            if operations.is_empty() {
                unpatched.push(reason(field, NO_DERIVED_VALUE));
            } else if operations.iter().any(|o| contains_sensitive(o, sensitive)) {
                unpatched.push(reason(field, "the fix would copy a value that the event log redacts, so it is not shown; edit it by hand"));
            } else {
                patch.extend(operations);
                patched.push(field);
                current = next;
            }
        }
        if !patch.is_empty() {
            matches_after_patch = is_plain_http_request(&current) && matches(&current, &actual);
        }
    }
    json!({"patch": patch, "patchedFields": patched, "unpatchedFields": unpatched, "matchesAfterPatch": matches_after_patch})
}

/// `getHttpRequest() instanceof HttpRequest`: not an OpenAPI, DNS or binary definition.
fn is_plain_http_request(v: &Value) -> bool {
    v.as_object().is_some_and(|o| !o.contains_key("specUrlOrPayload") && !o.contains_key("dnsName")) && !canonical::is_binary_request(v)
}

/// `fix`: changes `candidate` so that `field` accepts `actual`; `Some(reason)` when it cannot.
fn fix(field: &str, candidate: &mut Map<String, Value>, actual: &HttpRequest, body_truncated: bool) -> Option<String> {
    match field {
        "method" => {
            if actual.method.trim().is_empty() {
                return Some(NO_DERIVED_VALUE.into());
            }
            candidate.insert("method".into(), actual.method.clone().into());
        }
        "path" => {
            if actual.path.trim().is_empty() {
                return Some(NO_DERIVED_VALUE.into());
            }
            candidate.insert("path".into(), actual.path.clone().into());
            candidate.remove("pathParameters");
        }
        "pathParameters" => return fix_path_parameters(candidate, actual),
        "queryParameters" => {
            let fixed = fix_entries(candidate.get("queryStringParameters"), &actual.query, false, |entries| json!({"queryStringParameters": entries}), actual);
            set(candidate, "queryStringParameters", fixed);
        }
        "headers" => {
            let fixed = fix_entries(candidate.get("headers"), &actual.headers.to_multimap(), true, |entries| json!({"headers": entries}), actual);
            set(candidate, "headers", fixed);
        }
        "cookies" => {
            let fixed = fix_cookies(candidate.get("cookies"), actual);
            set(candidate, "cookies", fixed);
        }
        "body" => return fix_body(candidate, actual, body_truncated),
        "secure" => {
            candidate.insert("secure".into(), actual.secure.into());
        }
        "keep-alive" => {
            candidate.insert("keepAlive".into(), actual.keep_alive.into());
        }
        "protocol" => {
            let protocol = if actual.protocol.is_empty() { Value::Null } else { actual.protocol.into() };
            candidate.insert("protocol".into(), protocol);
        }
        _ => return Some(NO_DERIVED_VALUE.into()),
    }
    None
}

fn set(candidate: &mut Map<String, Value>, key: &str, value: Option<Value>) {
    match value {
        Some(v) => {
            candidate.insert(key.into(), v);
        }
        None => {
            candidate.remove(key);
        }
    }
}

fn fix_path_parameters(candidate: &mut Map<String, Value>, actual: &HttpRequest) -> Option<String> {
    let template = json!({"path": candidate.get("path").cloned().unwrap_or(Value::Null), "pathParameters": candidate.get("pathParameters").cloned().unwrap_or(Value::Null)});
    let actual_parameters = match RequestMatcher::compile(&template).extract_path_parameters(actual) {
        Some(Ok(parameters)) => parameters,
        Some(Err(_)) => return Some(NO_DERIVED_VALUE.into()),
        None => actual.path_parameters.clone(),
    };
    let path = candidate.get("path").cloned().unwrap_or(Value::Null);
    let fixed = fix_entries(candidate.get("pathParameters"), &actual_parameters, false, |entries| json!({"path": path, "pathParameters": entries}), actual);
    set(candidate, "pathParameters", fixed);
    None
}

/// `fixEntries`: keeps each expected entry the request satisfies on its own; replaces the values of one it does not
/// with the request's values for that name, when that satisfies it; removes it otherwise. `None` when the multimap
/// held no entries to begin with (left as it is).
fn fix_entries(expected: Option<&Value>, actual: &MultiMap, ignore_case: bool, probe: impl Fn(Value) -> Value, request: &HttpRequest) -> Option<Value> {
    let expected = expected.filter(|v| !v.is_null())?;
    let (entries, style) = model::multi_values_with_style(expected);
    if entries.is_empty() {
        return Some(expected.clone());
    }
    let json_of = |entries: &model::Entries| model::multi_values_json(entries, style.as_deref());
    let mut fixed = model::Entries::new();
    for entry in &entries {
        if matches(&probe(json_of(&vec![entry.clone()])), request) {
            fixed.push(entry.clone());
            continue;
        }
        let name = entry.0.value.clone().unwrap_or_default();
        let values: Vec<Option<NString>> = actual
            .iter()
            .filter(|(k, _)| if ignore_case { k.eq_ignore_ascii_case(&name) } else { *k == name })
            .flat_map(|(_, vs)| vs.iter().map(|v| Some(plain(v))))
            .collect();
        if !entry.0.not && !values.is_empty() {
            let replacement = (entry.0.clone(), values);
            if matches(&probe(json_of(&vec![replacement.clone()])), request) {
                fixed.push(replacement);
            }
        }
    }
    Some(json_of(&fixed))
}

/// `NottableString.string(value)`: the value as it is, no markers read.
fn plain(value: &str) -> NString {
    NString { value: Some(value.to_string()), ..NString::default() }
}

/// `fixCookies`: as [`fix_entries`], against the request's first cookie of that exact name.
fn fix_cookies(expected: Option<&Value>, request: &HttpRequest) -> Option<Value> {
    let expected = expected.filter(|v| !v.is_null())?;
    let entries = model::key_values(expected);
    if entries.is_empty() {
        return Some(expected.clone());
    }
    let probe = |entry: &(NString, Vec<Option<NString>>)| json!({"cookies": model::key_values_json(&vec![entry.clone()])});
    let mut fixed = model::Entries::new();
    for entry in &entries {
        if matches(&probe(entry), request) {
            fixed.push(entry.clone());
            continue;
        }
        if entry.0.not {
            continue;
        }
        let name = entry.0.value.as_deref().unwrap_or_default();
        if let Some((_, value)) = request.cookies.iter().find(|(k, _)| k == name) {
            let replacement = (entry.0.clone(), vec![Some(plain(value))]);
            if matches(&probe(&replacement), request) {
                fixed.push(replacement);
            }
        }
    }
    Some(model::key_values_json(&fixed))
}

fn fix_body(candidate: &mut Map<String, Value>, actual: &HttpRequest, body_truncated: bool) -> Option<String> {
    if body_truncated {
        return Some("the event log kept only part of this request's body (maxLoggedBodyBytes), so it cannot be copied into the expectation".into());
    }
    let actual_text = actual.body_str();
    if actual_text.is_empty() {
        // the request has no body: drop the body matcher
        candidate.remove("body");
        return None;
    }
    if actual_text.encode_utf16().count() > MAX_COPIED_BODY_CHARACTERS {
        return Some(format!(
            "the request body is larger than {} KiB, so it is not copied into a patch; edit the body matcher by hand",
            MAX_COPIED_BODY_CHARACTERS / 1024
        ));
    }
    let expected = candidate.get("body").cloned().unwrap_or(Value::Null);
    if expected.get("not").and_then(Value::as_bool) == Some(true) {
        // a negated body matcher rejects this body: drop it
        candidate.remove("body");
        return None;
    }
    // a JSON body: typed (`{"type": "JSON", "json": …}`) or echoed bare (matched on its listed fields only); its value
    // read as JSON, as `readJson(getValue())` does
    let json_body = match &expected {
        Value::Object(o) => match canonical::body_type(o).as_deref() {
            Some("JSON") => match canonical::field(o, "json") {
                Some(Value::String(s)) => crate::json::parse_lenient(s.as_bytes()).ok().map(|j| (j, Some(o))),
                Some(j) => Some((j.clone(), Some(o))),
                None => None,
            },
            None => Some((expected.clone(), None)),
            Some(_) => None,
        },
        Value::Array(_) => Some((expected.clone(), None)),
        _ => None,
    };
    if let (Some((expected_json, typed)), Ok(actual_json)) = (json_body, crate::json::parse_lenient(actual_text.as_bytes())) {
        let strict = typed.and_then(|o| canonical::field(o, "matchType")).and_then(Value::as_str) == Some("STRICT");
        let fixed = if strict { actual_json } else { keep_matching_fields(&expected_json, &actual_json) };
        let body = match typed {
            Some(o) => {
                let mut o = o.clone();
                o.insert("json".into(), fixed);
                o.remove("rawBytes");
                Value::Object(o)
            }
            None => fixed,
        };
        candidate.insert("body".into(), body);
        return None;
    }
    let body = crate::recorded::expectation_body(actual).unwrap_or(Value::Null);
    candidate.insert("body".into(), body);
    None
}

/// `keepMatchingFields`: for a body matched on its listed fields only, the expected structure with each value the
/// request contradicts replaced by the request's and each field the request lacks removed; a json-unit placeholder
/// such as `${json-unit.any-string}` is kept.
fn keep_matching_fields(expected: &Value, actual: &Value) -> Value {
    if expected.as_str().is_some_and(|s| s.starts_with("${json-unit.")) || expected == actual {
        return expected.clone();
    }
    match (expected, actual) {
        (Value::Object(e), Value::Object(a)) => {
            Value::Object(e.iter().filter_map(|(k, v)| a.get(k).map(|av| (k.clone(), keep_matching_fields(v, av)))).collect())
        }
        _ => actual.clone(),
    }
}

/// Matches `definition` (a request matcher's JSON) against `request` on the data plane; nothing is logged.
fn matches(definition: &Value, request: &HttpRequest) -> bool {
    RequestMatcher::compile(definition).matches(request, Mode::DataPlane)
}

/// `diff`: appends the add, remove and replace operations that turn `from` into `to`, each remove and replace preceded
/// by a test of the value it changes, and each object that gains a member by a test of that whole object (an add would
/// otherwise overwrite a member added since). Arrays are replaced whole.
pub(crate) fn diff(path: &str, from: &Value, to: &Value, operations: &mut Vec<Value>) {
    if from == to {
        return;
    }
    match (from, to) {
        (Value::Object(f), Value::Object(t)) => {
            if t.keys().any(|k| !f.contains_key(k)) {
                operations.push(operation("test", path, Some(from)));
            }
            for (k, v) in f {
                let field_path = format!("{path}/{}", escape(k));
                match t.get(k) {
                    Some(tv) => diff(&field_path, v, tv, operations),
                    None => {
                        operations.push(operation("test", &field_path, Some(v)));
                        operations.push(operation("remove", &field_path, None));
                    }
                }
            }
            for (k, v) in t.iter().filter(|(k, _)| !f.contains_key(*k)) {
                operations.push(operation("add", &format!("{path}/{}", escape(k)), Some(v)));
            }
        }
        _ => {
            operations.push(operation("test", path, Some(from)));
            operations.push(operation("replace", path, Some(to)));
        }
    }
}

fn operation(op: &str, path: &str, value: Option<&Value>) -> Value {
    let mut o = Map::new();
    o.insert("op".into(), op.into());
    o.insert("path".into(), path.into());
    if let Some(v) = value {
        o.insert("value".into(), v.clone());
    }
    Value::Object(o)
}

/// RFC 6901 escaping of a member name.
fn escape(key: &str) -> String {
    key.replace('~', "~0").replace('/', "~1")
}

/// `containsSensitive`: whether any name or value in `node` (as its text or its JSON) quotes a redacted value.
fn contains_sensitive(node: &Value, sensitive: Option<&Redaction>) -> bool {
    let Some(sensitive) = sensitive else { return false };
    match node {
        Value::Array(items) => items.iter().any(|i| contains_sensitive(i, Some(sensitive))),
        Value::Object(o) => o.iter().any(|(k, v)| sensitive.quotes_any(k) || contains_sensitive(v, Some(sensitive))),
        Value::String(s) => sensitive.quotes_any(s) || sensitive.quotes_any(&node.to_string()),
        other => sensitive.quotes_any(&other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diff_guards_every_change() {
        let mut ops = Vec::new();
        diff("/httpRequest", &json!({"method": "GET", "headers": {"a": ["1"]}}), &json!({"method": "POST", "headers": {"a": ["1"], "b/~": ["2"]}}), &mut ops);
        assert_eq!(
            ops,
            vec![
                json!({"op": "test", "path": "/httpRequest/method", "value": "GET"}),
                json!({"op": "replace", "path": "/httpRequest/method", "value": "POST"}),
                json!({"op": "test", "path": "/httpRequest/headers", "value": {"a": ["1"]}}),
                json!({"op": "add", "path": "/httpRequest/headers/b~1~0", "value": ["2"]}),
            ]
        );
    }

    #[test]
    fn diff_removes_with_a_test_and_replaces_arrays_whole() {
        let mut ops = Vec::new();
        diff("/r", &json!({"a": [1, 2], "b": 1}), &json!({"a": [2]}), &mut ops);
        assert_eq!(
            ops,
            vec![
                json!({"op": "test", "path": "/r/a", "value": [1, 2]}),
                json!({"op": "replace", "path": "/r/a", "value": [2]}),
                json!({"op": "test", "path": "/r/b", "value": 1}),
                json!({"op": "remove", "path": "/r/b"}),
            ]
        );
    }

    #[test]
    fn listed_fields_keep_placeholders_and_drop_missing_ones() {
        let expected = json!({"id": 1, "any": "${json-unit.any-string}", "gone": true, "same": {"x": 1}});
        let actual = json!({"id": 2, "any": "q", "same": {"x": 1}, "extra": 1});
        assert_eq!(keep_matching_fields(&expected, &actual), json!({"id": 2, "any": "${json-unit.any-string}", "same": {"x": 1}}));
    }
}
