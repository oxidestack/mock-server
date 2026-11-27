//! Response matchers (`HttpResponseMatcher`): does a recorded response satisfy a verification's `httpResponse`?
//! Each field constrains the match only when set; the body, header and cookie matchers are the request side's,
//! applied to the response as if it were a request.

use serde_json::Value;

use super::body::BodyMatcher;
use super::multimap::MultiMapMatcher;
use super::string::StringMatcher;
use crate::canonical;
use crate::request::{HttpRequest, MultiMap};

const MAX_DIFF_LINE_LENGTH: usize = 500;

#[derive(Debug)]
enum Status {
    Exact(i64),
    /// `statusCodeRange`: a class (`2XX`) or a numeric comparison (`>= 400`), kept as written.
    Range(String),
}

#[derive(Debug)]
pub struct ResponseMatcher {
    status: Option<Status>,
    reason_phrase: Option<StringMatcher>,
    headers: Option<MultiMapMatcher>,
    cookies: Option<MultiMapMatcher>,
    body: Option<BodyMatcher>,
    /// `matchExactCase` when compiled: the reason phrase matches case-insensitively unless it is set.
    exact_case: bool,
}

impl ResponseMatcher {
    /// From a verification's `httpResponse` as given (its body keeps the type the canonical form drops).
    pub fn compile(input: &Value) -> ResponseMatcher {
        let canonical = canonical::response(input);
        let range = input.get("statusCodeRange").and_then(Value::as_str).filter(|r| !r.trim().is_empty());
        let status = match (range, input.get("statusCode").and_then(Value::as_i64)) {
            (Some(r), _) => Some(Status::Range(r.to_string())),
            (None, Some(code)) => Some(Status::Exact(code)),
            (None, None) => None,
        };
        let map = |key: &str| canonical.get(key).filter(|v| v.as_object().is_some_and(|o| !o.is_empty()) || v.as_array().is_some_and(|a| !a.is_empty()));
        ResponseMatcher {
            status,
            reason_phrase: input.get("reasonPhrase").and_then(Value::as_str).map(StringMatcher::literal_or_regex),
            headers: map("headers").map(|h| MultiMapMatcher::compile(h).for_headers()),
            cookies: map("cookies").map(MultiMapMatcher::compile_single),
            body: input.get("body").filter(|b| !b.is_null()).map(BodyMatcher::compile),
            exact_case: super::exact_case(),
        }
    }

    pub fn matches(&self, response: &Value) -> bool {
        !response.is_null() && self.field_results(response).iter().all(|(_, d)| d.is_none())
    }

    /// Every failing field with its recorded differences, in `MatchDifference.Field` order (the order
    /// `MatchDifferenceFormatter` prints), for a verification failure's closest-response diff.
    pub fn differences(&self, response: &Value) -> Vec<(&'static str, Vec<String>)> {
        const ORDER: [&str; 4] = ["cookies", "headers", "body", "operation"];
        let mut fields: Vec<(&'static str, Vec<String>)> = Vec::new();
        for (field, lines) in self.field_results(response).into_iter().filter_map(|(f, d)| d.map(|d| (f, d))) {
            match fields.iter_mut().find(|(f, _)| *f == field) {
                Some((_, existing)) => existing.extend(lines),
                None => fields.push((field, lines)),
            }
        }
        fields.retain(|(_, lines)| !lines.is_empty());
        fields.sort_by_key(|(f, _)| ORDER.iter().position(|o| o == f));
        fields
    }

    /// `HttpResponseMatcher.matches` with a `MatchDifference`: every field evaluated, none failing fast. Status
    /// code and reason phrase both record under `operation`.
    fn field_results(&self, response: &Value) -> Vec<(&'static str, Option<Vec<String>>)> {
        let actual = as_request(response);
        // A response recorded without a status (an expectation's bare `httpResponse: {}`) matches no status
        // constraint and prints as `null`.
        let status = response.get("statusCode").and_then(Value::as_i64);
        let mut out = Vec::with_capacity(5);
        if let Some(expected) = &self.status {
            let ok = status.is_some_and(|status| match expected {
                Status::Exact(code) => *code == status,
                Status::Range(range) => range_matches(range, status),
            });
            let printed = match expected {
                Status::Exact(code) => code.to_string(),
                Status::Range(range) => range.clone(),
            };
            out.push((
                "operation",
                (!ok).then(|| vec![super::format_log_message(1, "statusCode match failed expected:{}found:{}", &[&printed, &status.map_or_else(|| "null".to_string(), |s| s.to_string())])]),
            ));
        }
        if let Some(reason) = &self.reason_phrase {
            let found = response.get("reasonPhrase").and_then(Value::as_str).unwrap_or_default();
            out.push((
                "operation",
                (!reason.matches(found, !self.exact_case))
                    .then(|| vec![super::format_log_message(1, "string or regex match failed expected:{}found:{}", &[&reason.printed(), found])]),
            ));
        }
        if let Some(headers) = &self.headers {
            out.push(("headers", (!headers.matches(&actual.headers, true)).then(|| headers.recorded_differences(&actual.headers.to_multimap()))));
        }
        if let Some(cookies) = &self.cookies {
            let found: MultiMap = actual.cookies.iter().map(|(k, v)| (k.clone(), vec![v.clone()])).collect();
            out.push(("cookies", (!cookies.matches(&found, true)).then(|| cookies.cookie_differences(&found))));
        }
        if let Some(body) = &self.body {
            out.push(("body", (!body.matches(&actual, false)).then(|| body.recorded_differences(&actual))));
        }
        out
    }
}

/// `StatusCodeMatcher` with a `statusCodeRange`: a class range (`2XX`) or `NumericComparisonMatcher`.
fn range_matches(range: &str, actual: i64) -> bool {
    let expression = range.trim();
    let bytes = expression.as_bytes();
    if bytes.len() == 3 && bytes[0].is_ascii_digit() && bytes[1..].iter().all(|b| b.eq_ignore_ascii_case(&b'x')) {
        let low = i64::from(bytes[0] - b'0') * 100;
        return (low..=low + 99).contains(&actual);
    }
    let Some(op) = [">=", "<=", "==", ">", "<"].into_iter().find(|op| expression.starts_with(op)) else { return false };
    let number = expression[op.len()..].trim();
    let valid = {
        let digits = number.strip_prefix('-').unwrap_or(number);
        let (whole, fraction) = digits.split_once('.').unwrap_or((digits, "0"));
        !whole.is_empty() && !fraction.is_empty() && whole.bytes().chain(fraction.bytes()).all(|b| b.is_ascii_digit())
    };
    let Some(expected) = number.parse::<f64>().ok().filter(|_| valid) else { return false };
    let actual = actual as f64;
    match op {
        ">" => actual > expected,
        ">=" => actual >= expected,
        "<" => actual < expected,
        "<=" => actual <= expected,
        _ => actual == expected,
    }
}

/// A recorded (canonical) response in the shape the request-side matchers read.
fn as_request(response: &Value) -> HttpRequest {
    let mut headers = MultiMap::new();
    match response.get("headers") {
        Some(Value::Object(o)) => {
            for (k, vs) in o {
                let values = match vs {
                    Value::Array(items) => items.iter().map(|v| v.as_str().unwrap_or_default().to_string()).collect(),
                    other => vec![other.as_str().unwrap_or_default().to_string()],
                };
                headers.push((k.clone(), values));
            }
        }
        Some(Value::Array(items)) => {
            for item in items {
                let name = item.get("name").and_then(Value::as_str).unwrap_or_default().to_string();
                let values = item.get("values").and_then(Value::as_array).into_iter().flatten().map(|v| v.as_str().unwrap_or_default().to_string()).collect();
                headers.push((name, values));
            }
        }
        _ => {}
    }
    let mut cookies = Vec::new();
    match response.get("cookies") {
        Some(Value::Object(o)) => cookies.extend(o.iter().map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_string()))),
        Some(Value::Array(items)) => cookies.extend(items.iter().map(|i| {
            (i.get("name").and_then(Value::as_str).unwrap_or_default().to_string(), i.get("value").and_then(Value::as_str).unwrap_or_default().to_string())
        })),
        _ => {}
    }
    let body = response.get("body").map(|b| crate::action::response_body(b, None).0).unwrap_or_default();
    HttpRequest { headers: headers.into(), cookies, body, ..HttpRequest::default() }
}

/// `MatchDifferenceFormatter.truncateDiffLine`.
pub fn diff_line(diff: &str) -> String {
    let single: String = diff.replace('\n', " ").replace('\r', "");
    match single.char_indices().nth(MAX_DIFF_LINE_LENGTH) {
        Some((i, _)) => format!("{}...[truncated]", &single[..i]),
        None => single,
    }
}
