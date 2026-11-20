//! `RequestBodyExtractionHelper` and `XmlXPathTemplateHelper`: JSONPath and XPath over a request body, with the
//! values Jayway JsonPath (on json-smart) and the JDK's XPath return.

use java_compat::lang::{JError, JList, JMap, JValue, ListKind, MapKind};
use serde_json::Value;

use crate::media_type::{DecodedBody, MediaType};
use crate::request::HttpRequest;

/// `HttpRequest.getBodyAsJsonOrXmlString()`: a text body as its string, `None` without a body.
pub fn body_text(request: &HttpRequest) -> Option<String> {
    let body = DecodedBody::decode(&request.body, request.first_header("content-type"))?;
    Some(match body {
        // `new String(body.toString().getBytes(charset), UTF_8)`.
        DecodedBody::String(s) => {
            let charset = MediaType::parse(request.first_header("content-type")).charset_or_default().map(str::to_string);
            String::from_utf8_lossy(&crate::canonical::encode(&s, charset.map(|c| format!("text/plain; charset={c}")).as_deref())).into_owned()
        }
        other => other.template_string(),
    })
}

/// The `NullPointerException` `getBodyAsJsonOrXmlString()` throws for a `StringBody` whose content type has no
/// default charset (`getBytes((Charset) null)`): a gRPC request converted to JSON keeps `application/grpc`. The
/// helpers' catch blocks call it again to log the body, so it escapes `jsonPath` / `xPath` and fails the render.
fn charsetless_string_body(request: &HttpRequest) -> Result<(), JError> {
    let charset = MediaType::parse(request.first_header("content-type")).charset_or_default().is_some();
    if request.body_kind == crate::request::BodyKind::PlainString && !charset {
        return Err(JError::without_message("java.lang.NullPointerException"));
    }
    Ok(())
}

/// An evaluation `RequestBodyExtractionHelper` logs as failed (`exception evaluating xPath:{}against xml body:{}` or
/// the jsonPath form), at INFO, about the request: the expression and the body text (`None` without a body).
#[derive(Debug, Clone)]
pub struct Failure {
    pub xpath: bool,
    pub expression: String,
    pub body: Option<String>,
}

thread_local! {
    /// The failures of the render in progress on this thread, while [`collect`] runs it.
    static FAILURES: std::cell::RefCell<Option<Vec<Failure>>> = const { std::cell::RefCell::new(None) };
}

/// Runs `render`, returning what it returned and the evaluation failures it met, in order.
pub fn collect<T>(render: impl FnOnce() -> T) -> (T, Vec<Failure>) {
    let outer = FAILURES.with(|f| f.borrow_mut().replace(Vec::new()));
    let out = render();
    let failures = FAILURES.with(|f| std::mem::replace(&mut *f.borrow_mut(), outer)).unwrap_or_default();
    (out, failures)
}

fn failed(xpath: bool, expression: &str, body: Option<String>, times: usize) {
    FAILURES.with(|f| {
        if let Some(list) = f.borrow_mut().as_mut() {
            for _ in 0..times {
                list.push(Failure { xpath, expression: expression.to_string(), body: body.clone() });
            }
        }
    });
}

/// [`json_path`] as the template tools call it: failing as [`charsetless_string_body`] says, and noting a failed
/// evaluation for [`collect`].
pub fn json_path_checked(request: &HttpRequest, path: &str) -> Result<JValue, JError> {
    charsetless_string_body(request)?;
    let text = body_text(request);
    match text.as_deref().map(|t| json_path_result(t, path)) {
        Some(Ok(value)) => Ok(value.unwrap_or_else(|| JValue::str(""))),
        // `JsonPath.read(null)` throws too.
        _ => {
            failed(false, path, text, 1);
            Ok(JValue::str(""))
        }
    }
}

/// [`xpath`] as the template tools call it: failing as [`charsetless_string_body`] says, and noting a failed
/// evaluation for [`collect`]: once for an expression that does not compile or a missing body, twice for a body
/// that is not XML (the parser's error handler, then the exception it throws).
pub fn xpath_checked(request: &HttpRequest, expression: &str) -> Result<String, JError> {
    charsetless_string_body(request)?;
    let text = body_text(request);
    let compiled = sxd_xpath::Factory::new().build(expression).ok().flatten();
    let Some(compiled) = compiled else {
        failed(true, expression, text, 1);
        return Ok(String::new());
    };
    let Some(xml) = text else {
        failed(true, expression, None, 1);
        return Ok(String::new());
    };
    let Ok(package) = sxd_document::parser::parse(&xml) else {
        failed(true, expression, Some(xml), 2);
        return Ok(String::new());
    };
    let document = package.as_document();
    let context = sxd_xpath::Context::new();
    match compiled.evaluate(&context, document.root()) {
        Ok(value) => Ok(xpath_value_string(value)),
        Err(_) => {
            failed(true, expression, Some(xml), 1);
            Ok(String::new())
        }
    }
}

/// `RequestBodyExtractionHelper.jsonPath`: the value at `path`, or `""` when it is missing, `null`, or the body or
/// expression is invalid.
pub fn json_path(request: &HttpRequest, path: &str) -> JValue {
    let Some(text) = body_text(request) else { return JValue::str("") };
    json_path_in(&text, path).unwrap_or_else(|| JValue::str(""))
}

/// The value at `path` in the JSON `text`; `None` when the text or path is invalid, or a definite path finds nothing.
pub fn json_path_in(text: &str, path: &str) -> Option<JValue> {
    json_path_result(text, path).ok().flatten()
}

/// `JsonPath.compile(path).read(text)`: `Err` where Jayway throws (the text or path is invalid, a definite path finds
/// nothing), `Ok(None)` for a `null` it reads.
fn json_path_result(text: &str, path: &str) -> Result<Option<JValue>, ()> {
    let document = crate::json::parse_lenient(text.as_bytes()).map_err(|_| ())?;
    let compiled = serde_json_path::JsonPath::parse(path.trim()).map_err(|_| ())?;
    let nodes = compiled.query(&document).all();
    if is_definite(path) {
        // A definite path that finds nothing throws `PathNotFoundException`.
        let value = nodes.first().ok_or(())?;
        return Ok(Some(smart(value)).filter(|v| !v.is_null()));
    }
    Ok(Some(JValue::List(JList::new(ListKind::JsonArray, nodes.into_iter().map(smart).collect()))))
}

/// Jayway's `Path.isDefinite()`: no deep scan, wildcard, filter, slice or index/property union.
fn is_definite(path: &str) -> bool {
    let mut in_quotes: Option<char> = None;
    let mut in_brackets = false;
    let mut prev = '\0';
    for c in path.chars() {
        match in_quotes {
            Some(q) if c == q => in_quotes = None,
            Some(_) => {}
            None => match c {
                '\'' | '"' => in_quotes = Some(c),
                '[' => in_brackets = true,
                ']' => in_brackets = false,
                '*' | '?' => return false,
                '.' if prev == '.' => return false,
                ',' | ':' if in_brackets => return false,
                _ => {}
            },
        }
        prev = c;
    }
    true
}

/// A JSON value as json-smart builds it: `LinkedHashMap` objects, `JSONArray` arrays, `Integer` / `Long` /
/// `BigInteger` integers and `Double` fractions.
pub fn smart(v: &Value) -> JValue {
    match v {
        Value::Null => JValue::Null,
        Value::Bool(b) => JValue::Bool(*b),
        Value::String(s) => JValue::str(s.as_str()),
        Value::Number(n) => {
            let text = n.to_string();
            if text.contains(['.', 'e', 'E']) {
                JValue::Double(text.parse().unwrap_or(0.0))
            } else if let Ok(i) = text.parse::<i32>() {
                JValue::Int(i)
            } else if let Ok(l) = text.parse::<i64>() {
                JValue::Long(l)
            } else {
                JValue::BigInteger(text.trim_start_matches('+').into())
            }
        }
        Value::Array(items) => JValue::List(JList::new(ListKind::JsonArray, items.iter().map(smart).collect())),
        Value::Object(o) => JValue::Map(JMap::from_entries(MapKind::Linked, o.iter().map(|(k, v)| (JValue::str(k.as_str()), smart(v))))),
    }
}

/// `RequestBodyExtractionHelper.xPath`: the XPath `STRING` result over the body, `""` on any failure.
pub fn xpath(request: &HttpRequest, expression: &str) -> String {
    body_text(request).and_then(|xml| xpath_string(&xml, expression)).unwrap_or_default()
}

/// `xPath.evaluate(expression, document, XPathConstants.STRING)`.
pub fn xpath_string(xml: &str, expression: &str) -> Option<String> {
    let package = sxd_document::parser::parse(xml).ok()?;
    let document = package.as_document();
    let value = sxd_xpath::evaluate_xpath(&document, expression).ok()?;
    Some(xpath_value_string(value))
}

fn xpath_value_string(value: sxd_xpath::Value<'_>) -> String {
    match value {
        sxd_xpath::Value::Number(n) => xpath_number(n),
        other => other.into_string(),
    }
}

/// XPath's `string(number)`: integers without a fraction, `NaN`, `Infinity`.
fn xpath_number(n: f64) -> String {
    if n.is_nan() {
        "NaN".into()
    } else if n.is_infinite() {
        if n > 0.0 { "Infinity".into() } else { "-Infinity".into() }
    } else if n == n.trunc() && n.abs() < 1e18 {
        format!("{}", n as i64)
    } else {
        java_compat::double_to_string(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn definite_paths() {
        assert!(is_definite("$.store.book[0].title"));
        assert!(is_definite("$['a']"));
        assert!(!is_definite("$..k"));
        assert!(!is_definite("$.a[*]"));
        assert!(!is_definite("$.a[0,1]"));
        assert!(!is_definite("$.a[?(@.x)]"));
    }

    #[test]
    fn values_like_jayway() {
        let doc = r#"{"a": [1, 2.50, 1e2, "x/y", {"k": "v\"q"}, [true, null]], "n": 12345678901, "big": 123456789012345678901234567890}"#;
        let get = |p: &str| json_path_in(doc, p).map(|v| v.to_java_string());
        assert_eq!(get("$.a").as_deref(), Some(r#"[1,2.5,100.0,"x\/y",{"k":"v\"q"},[true,null]]"#));
        assert_eq!(get("$.n").as_deref(), Some("12345678901"));
        assert_eq!(get("$.big").as_deref(), Some("123456789012345678901234567890"));
        assert_eq!(get("$.a[4]").as_deref(), Some(r#"{k=v"q}"#));
        assert_eq!(get("$..nope").as_deref(), Some("[]"));
        assert_eq!(get("$.nope"), None);
    }
}
