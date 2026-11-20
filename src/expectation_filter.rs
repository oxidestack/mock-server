//! `ExpectationFilter`: the metadata, `unmatched` and paging parameters of `PUT /mockserver/retrieve` and
//! `PUT /mockserver/clear` (upstream 9.2.0, #33). Parsing fails closed: a request that names any filter must parse into
//! a complete one, and a query string that cannot be decoded is refused, never read as "no filter" (which on clear
//! would clear everything). Evaluation is a linear scan made when the control-plane call is.

use serde_json::Value;

use crate::request::HttpRequest;
use crate::store::Expectation;

const PARAMETERS: [&str; 6] = ["metadataKey", "metadataValue", "metadataJsonPath", "unmatched", "limit", "offset"];

#[derive(Debug, Default)]
pub struct ExpectationFilter {
    metadata_key: Option<String>,
    metadata_value: Option<String>,
    json_path: Option<String>,
    unmatched: bool,
    filter_present: bool,
    blank_namespace: bool,
    limit: Option<usize>,
    offset: Option<usize>,
}

fn canonical(name: &str) -> Option<&'static str> {
    PARAMETERS.iter().copied().find(|known| known.eq_ignore_ascii_case(name))
}

fn is_filter_like(name: &str) -> bool {
    if canonical(name).is_some() {
        return true;
    }
    let normalised: String = name.to_lowercase().chars().filter(|c| c.is_ascii_lowercase() || c.is_ascii_digit()).collect();
    normalised.starts_with("metadata") || normalised.starts_with("unmatched")
}

/// Java's `String.isBlank`-like check used by `StringUtils.isBlank`.
fn is_blank(value: &str) -> bool {
    value.chars().all(char::is_whitespace)
}

impl ExpectationFilter {
    /// `fromControlPlaneRequest`: decided from the raw query string, decoded strictly.
    pub fn from_request(request: &HttpRequest) -> Result<ExpectationFilter, String> {
        match request.raw_query.as_deref().filter(|raw| !raw.is_empty()) {
            Some(raw) => Self::from_pairs(&strictly_decode(raw)?),
            None => {
                let pairs: Vec<(String, String)> =
                    request.query.iter().flat_map(|(name, values)| values.iter().map(move |v| (name.clone(), v.clone()))).collect();
                Self::from_pairs(&pairs)
            }
        }
    }

    fn from_pairs(pairs: &[(String, String)]) -> Result<ExpectationFilter, String> {
        let mut filter = ExpectationFilter::default();
        let mut parameters: Vec<(&'static str, &str)> = Vec::new();
        for (name, value) in pairs {
            if name.eq_ignore_ascii_case("namespace") && is_blank(value) {
                filter.blank_namespace = true;
            }
            if !is_filter_like(name) {
                continue;
            }
            filter.filter_present = true;
            let Some(known) = canonical(name) else {
                return Err(format!("\"{name}\" is not a recognised expectation filter parameter, the supported parameters are [{}]", PARAMETERS.join(", ")));
            };
            if parameters.iter().any(|(k, _)| *k == known) {
                return Err(format!("\"{known}\" must be given at most once"));
            }
            parameters.push((known, value));
        }
        let get = |name: &str| parameters.iter().find(|(k, _)| *k == name).map(|(_, v)| *v);
        let not_blank = |name: &str| -> Result<Option<String>, String> {
            match get(name) {
                None => Ok(None),
                Some(v) if is_blank(v) => Err(format!("\"{name}\" must not be blank; omit it to select every expectation")),
                Some(v) => Ok(Some(v.to_string())),
            }
        };
        if get("metadataKey").is_some() {
            filter.metadata_key = not_blank("metadataKey")?;
            filter.metadata_value = get("metadataValue").map(str::to_string);
        } else if get("metadataValue").is_some() {
            return Err("\"metadataValue\" requires \"metadataKey\"".to_string());
        }
        if get("metadataJsonPath").is_some() {
            let path = not_blank("metadataJsonPath")?.unwrap_or_default();
            crate::matcher::jayway_compile_check(&path).map_err(|why| format!("\"{path}\" is not a valid JSONPath for \"metadataJsonPath\": {why}"))?;
            filter.json_path = Some(path);
        }
        if let Some(value) = get("unmatched") {
            if value.eq_ignore_ascii_case("true") {
                filter.unmatched = true;
            } else if !value.eq_ignore_ascii_case("false") {
                return Err(format!("\"{value}\" is not a valid value for \"unmatched\", only true or false are supported"));
            }
        }
        let integer = |name: &str| -> Result<Option<usize>, String> {
            let Some(value) = get(name) else { return Ok(None) };
            match value.trim_matches(|c: char| c <= ' ').parse::<i32>() {
                Ok(n) if n >= 0 => Ok(Some(n as usize)),
                _ => Err(format!("\"{value}\" is not a valid value for \"{name}\", it must be an integer of zero or more")),
            }
        };
        filter.limit = integer("limit")?;
        filter.offset = integer("offset")?;
        Ok(filter)
    }

    /// The filter as upstream's `ObjectWithJsonToString` prints it (properties alphabetical, nulls left out), for the
    /// `cleared … expectations that match filter:{}` entry.
    pub fn to_json(&self) -> Value {
        let mut o = serde_json::Map::new();
        if let Some(limit) = self.limit {
            o.insert("limit".into(), Value::from(limit));
        }
        if let Some(path) = &self.json_path {
            o.insert("metadataJsonPath".into(), Value::from(path.clone()));
        }
        if let Some(key) = &self.metadata_key {
            o.insert("metadataKey".into(), Value::from(key.clone()));
        }
        if let Some(value) = &self.metadata_value {
            o.insert("metadataValue".into(), Value::from(value.clone()));
        }
        if let Some(offset) = self.offset {
            o.insert("offset".into(), Value::from(offset));
        }
        o.insert("unmatched".into(), Value::Bool(self.unmatched));
        Value::Object(o)
    }

    pub fn has_selection(&self) -> bool {
        self.metadata_key.is_some() || self.json_path.is_some() || self.unmatched
    }

    pub fn has_paging(&self) -> bool {
        self.limit.is_some() || self.offset.is_some()
    }

    /// Whether the request named any filter parameter.
    pub fn is_filtered(&self) -> bool {
        self.filter_present
    }

    /// `requireComplete`: a request that names a filter must select, or page (retrieve only).
    pub fn require_complete(self, clear: bool) -> Result<ExpectationFilter, String> {
        if clear && self.blank_namespace {
            return Err("\"namespace\" must not be blank; omit it to clear every namespace".to_string());
        }
        if !self.filter_present {
            return Ok(self);
        }
        if clear {
            if self.has_paging() {
                return Err("limit and offset are not supported for clear".to_string());
            }
            if !self.has_selection() {
                return Err("the filter parameters select no expectations to clear (for example unmatched=false on its own); use a metadata filter or unmatched=true, or send no filter parameters to clear without one".to_string());
            }
        } else if !self.has_selection() && !self.has_paging() {
            return Err("the filter parameters select nothing (for example unmatched=false on its own); omit them to retrieve without a filter".to_string());
        }
        Ok(self)
    }

    /// Whether the expectation satisfies every selection (paging is not one).
    pub fn matches(&self, expectation: &Expectation) -> bool {
        if self.unmatched && expectation.match_count() != 0 {
            return false;
        }
        if self.metadata_key.is_none() && self.json_path.is_none() {
            return true;
        }
        let Some(metadata) = expectation.canonical.get("metadata").and_then(Value::as_object) else { return false };
        if let Some(key) = &self.metadata_key {
            let Some(stored) = metadata.get(key) else { return false };
            if let Some(expected) = &self.metadata_value
                && !value_matches(stored, expected)
            {
                return false;
            }
        }
        match &self.json_path {
            Some(path) => crate::matcher::jayway_truthy(path, &Value::Object(metadata.clone())),
            None => true,
        }
    }

    /// The page of `items` this filter selects.
    pub fn page<T>(&self, items: Vec<T>) -> Vec<T> {
        if !self.has_paging() {
            return items;
        }
        let from = self.offset.unwrap_or(0).min(items.len());
        let to = self.limit.map_or(items.len(), |l| from.saturating_add(l).min(items.len()));
        items.into_iter().skip(from).take(to - from).collect()
    }
}

fn value_matches(stored: &Value, expected: &str) -> bool {
    let mut stream = serde_json::Deserializer::from_str(expected).into_iter::<Value>();
    let expected_node = stream.next().and_then(Result::ok);
    if let Value::String(text) = stored {
        return text == expected || matches!(&expected_node, Some(Value::String(e)) if e == text);
    }
    expected_node.is_some_and(|e| numeric_equal(stored, &e))
}

/// `JsonNode.equals(NUMERIC_EQUALITY, other)`: numbers compare by value, whatever their written form.
fn numeric_equal(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => match (x.as_i64(), y.as_i64()) {
            (Some(x), Some(y)) => x == y,
            _ => x.as_f64() == y.as_f64(),
        },
        (Value::Array(x), Value::Array(y)) => x.len() == y.len() && x.iter().zip(y).all(|(x, y)| numeric_equal(x, y)),
        (Value::Object(x), Value::Object(y)) => x.len() == y.len() && x.iter().all(|(k, v)| y.get(k).is_some_and(|w| numeric_equal(v, w))),
        _ => a == b,
    }
}

/// `strictlyDecode`: `&` separates, `+` is a space, `;` is ordinary, a `#` ends the query; a `%` not followed by two
/// hex digits, or percent-encoded bytes that are not UTF-8, are refused.
fn strictly_decode(raw: &str) -> Result<Vec<(String, String)>, String> {
    let query = raw.split('#').next().unwrap_or_default();
    let mut pairs = Vec::new();
    for part in query.split('&') {
        if part.is_empty() {
            continue;
        }
        let (name, value) = match part.split_once('=') {
            Some((n, v)) => (decode_component(n, raw)?, decode_component(v, raw)?),
            None => (decode_component(part, raw)?, String::new()),
        };
        pairs.push((name, value));
    }
    Ok(pairs)
}

fn decode_component(component: &str, raw: &str) -> Result<String, String> {
    let bytes = component.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let digit = |at: usize| bytes.get(at).and_then(|b| (*b as char).to_digit(16));
                match (digit(i + 1), digit(i + 2)) {
                    (Some(h), Some(l)) => out.push((h * 16 + l) as u8),
                    _ => return Err(format!("the query string \"{raw}\" cannot be decoded: a % must be followed by two hex digits (send a literal % as %25)")),
                }
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|_| format!("the query string \"{raw}\" cannot be decoded: percent-encoded bytes are not valid UTF-8"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoding_is_strict() {
        assert_eq!(strictly_decode("a=b+c&d=%41&e").unwrap(), vec![("a".into(), "b c".into()), ("d".into(), "A".into()), ("e".into(), String::new())]);
        assert!(strictly_decode("a=%").unwrap_err().contains("two hex digits"));
        assert!(strictly_decode("a=%FF").unwrap_err().contains("not valid UTF-8"));
    }

    #[test]
    fn paging_clamps() {
        let filter = ExpectationFilter::from_pairs(&[("limit".into(), "2".into()), ("OFFSET".into(), "1".into())]).unwrap();
        assert_eq!(filter.page(vec![1, 2, 3, 4]), vec![2, 3]);
        assert_eq!(filter.page(vec![1]), Vec::<i32>::new());
    }

    #[test]
    fn values_compare_as_text_or_json() {
        assert!(value_matches(&serde_json::json!(42), "42"));
        assert!(value_matches(&serde_json::json!("42"), "42"));
        assert!(value_matches(&serde_json::json!(1.5), "1.50"));
        assert!(value_matches(&serde_json::json!("a"), "\"a\""));
        assert!(!value_matches(&serde_json::json!(true), "false"));
    }
}
