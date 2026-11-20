//! `ConfigurationDTO` fields that hold an object rather than a scalar: `connectionDelay` (a `DelayDTO`) and
//! `proxyPassMappings` (a list of `ProxyPassMapping`). Each is read the way Jackson fills the Java class and written
//! back the way it prints it, so what `PUT /mockserver/configuration` stores is already the form `GET` answers.

use serde_json::{Map, Value};

/// `TimeUnit` in declaration order (Jackson also reads an enum by ordinal, numeric or as text).
const TIME_UNITS: &[&str] = &["NANOSECONDS", "MICROSECONDS", "MILLISECONDS", "SECONDS", "MINUTES", "HOURS", "DAYS"];
/// `DelayDistribution.Type`.
const DISTRIBUTION_TYPES: &[&str] = &["UNIFORM", "LOG_NORMAL", "GAUSSIAN"];
/// `HttpTemplate.TemplateType`.
const TEMPLATE_TYPES: &[&str] = &["JAVASCRIPT", "VELOCITY", "MUSTACHE"];

/// An enum field: a name in any case or an ordinal; anything else reads as null (`READ_UNKNOWN_ENUM_VALUES_AS_NULL`)
/// except a value of the wrong JSON kind, which fails.
fn enum_value(value: &Value, names: &[&'static str]) -> Result<Option<&'static str>, ()> {
    let pick = |i: usize| names.get(i).copied();
    match value {
        Value::Null => Ok(None),
        Value::String(s) => {
            let text = s.trim();
            if let Some(i) = names.iter().position(|n| n.eq_ignore_ascii_case(text)) {
                return Ok(pick(i));
            }
            Ok(text.parse::<usize>().ok().and_then(pick))
        }
        Value::Number(n) if n.is_i64() || n.is_u64() => Ok(n.as_u64().and_then(|i| pick(i as usize))),
        _ => Err(()),
    }
}

/// A `long`/`Long` field: a number (a fraction cut off), numeric text of whole digits, or null/blank.
fn long_value(value: &Value) -> Result<Option<i64>, ()> {
    match value {
        Value::Null => Ok(None),
        Value::String(s) if s.trim().is_empty() => Ok(None),
        Value::String(s) => s.trim().parse::<i64>().map(Some).map_err(|_| ()),
        Value::Number(n) => match (n.as_i64(), n.as_u64(), n.as_f64()) {
            (Some(i), _, _) => Ok(Some(i)),
            (None, Some(_), _) => Err(()),
            (_, _, Some(f)) if f.is_finite() && f.abs() < 9.2e18 => Ok(Some(f.trunc() as i64)),
            _ => Err(()),
        },
        _ => Err(()),
    }
}

/// A `String` field: text, or a number or boolean as its text.
fn text_value(value: &Value) -> Result<Option<String>, ()> {
    match value {
        Value::Null => Ok(None),
        Value::String(s) => Ok(Some(s.clone())),
        Value::Number(n) => Ok(Some(n.to_string())),
        Value::Bool(b) => Ok(Some(b.to_string())),
        _ => Err(()),
    }
}

fn is_blank(value: &Value) -> bool {
    matches!(value, Value::Null) || matches!(value, Value::String(s) if s.trim().is_empty())
}

/// `connectionDelay` as `DelayDTO` reads it and `new DelayDTO(delay)` prints it (alphabetical, absent parts left out).
/// `Ok(None)` is a null or blank value, which changes nothing; `Err` one Jackson cannot read.
pub fn connection_delay(value: &Value) -> Result<Option<Value>, ()> {
    if is_blank(value) {
        return Ok(None);
    }
    let Value::Object(o) = value else { return Err(()) };
    let mut out = Map::new();
    if let Some(d) = o.get("distribution").filter(|d| !is_blank(d)) {
        let Value::Object(d) = d else { return Err(()) };
        let mut dist = Map::new();
        // `DelayDistributionDTO.buildObject` floors each member
        for (key, floor) in [("max", 0), ("mean", 0), ("median", 1), ("min", 0), ("p99", 1), ("stdDev", 0)] {
            if let Some(n) = d.get(key).map(long_value).transpose()?.flatten() {
                dist.insert(key.into(), Value::from(n.max(floor)));
            }
        }
        if let Some(t) = d.get("type").map(|t| enum_value(t, DISTRIBUTION_TYPES)).transpose()?.flatten() {
            dist.insert("type".into(), Value::from(t));
        }
        out.insert("distribution".into(), Value::Object(dist));
    }
    let template = o.get("template").map(text_value).transpose()?.flatten();
    let template_type = o.get("templateType").map(|t| enum_value(t, TEMPLATE_TYPES)).transpose()?.flatten();
    // a template survives only with its type; an empty one is not printed
    if let (Some(template), Some(kind)) = (template, template_type) {
        if !template.is_empty() {
            out.insert("template".into(), Value::String(template));
        }
        out.insert("templateType".into(), Value::from(kind));
    }
    if let Some(unit) = o.get("timeUnit").map(|u| enum_value(u, TIME_UNITS)).transpose()?.flatten() {
        out.insert("timeUnit".into(), Value::from(unit));
    }
    let seconds = o.get("value").map(long_value).transpose()?.flatten().unwrap_or(0);
    out.insert("value".into(), Value::from(seconds));
    out.sort_keys();
    Ok(Some(Value::Object(out)))
}

/// A `boolean` field: true/false in any of the spellings Jackson accepts, a whole number (zero is false), null/blank false.
fn bool_value(value: &Value) -> Result<bool, ()> {
    match value {
        Value::Null => Ok(false),
        Value::Bool(b) => Ok(*b),
        Value::String(s) if s.trim().is_empty() => Ok(false),
        Value::String(s) => match s.trim() {
            "true" | "True" | "TRUE" => Ok(true),
            "false" | "False" | "FALSE" => Ok(false),
            _ => Err(()),
        },
        Value::Number(n) if n.is_i64() || n.is_u64() => Ok(n.as_i64() != Some(0) && n.as_u64() != Some(0)),
        _ => Err(()),
    }
}

/// One `ProxyPassMapping` as Jackson reads it: the three members it sets (it writes the private fields, so
/// `withTargetUri` never parses the target here). Derived members are worked out when the mapping is printed.
fn proxy_pass_mapping(value: &Value) -> Result<Value, ()> {
    let Value::Object(o) = value else { return Err(()) };
    let mut out = Map::new();
    if let Some(p) = o.get("pathPrefix").map(text_value).transpose()?.flatten() {
        out.insert("pathPrefix".into(), Value::String(p));
    }
    if let Some(u) = o.get("targetUri").map(text_value).transpose()?.flatten() {
        out.insert("targetUri".into(), Value::String(u));
    }
    out.insert("preserveHost".into(), Value::Bool(o.get("preserveHost").map(bool_value).transpose()?.unwrap_or(false)));
    Ok(Value::Object(out))
}

/// A stored mapping as Jackson prints it: the configured members, then what parsing `targetUri` derives
/// (`getTargetHost`, `getTargetPort`, `getTargetPath`, `isTargetSecure`). A `targetUri` that `URI.create` refuses
/// makes the getter throw, so the mapping (and the configuration holding it) cannot be printed: `Err`.
fn print_mapping(stored: &Value) -> Result<Value, ()> {
    let Value::Object(o) = stored else { return Ok(Value::Null) };
    let path_prefix = o.get("pathPrefix").and_then(Value::as_str).map(str::to_string);
    let target_uri = o.get("targetUri").and_then(Value::as_str).map(str::to_string);
    let preserve_host = o.get("preserveHost").and_then(Value::as_bool).unwrap_or(false);
    let (mut host, mut port, mut path, mut secure) = (None, 0i64, None, false);
    if let Some(uri) = &target_uri {
        let parsed = crate::java_uri::parse(uri).map_err(|_| ())?;
        secure = parsed.scheme.as_deref().is_some_and(|s| s.eq_ignore_ascii_case("https"));
        port = if parsed.port > 0 { parsed.port as i64 } else if secure { 443 } else { 80 };
        host = parsed.host.clone();
        path = Some(crate::java_uri::path(&parsed).unwrap_or_default().trim_end_matches('/').to_string());
    }
    let mut out = Map::new();
    let mut text = |key: &str, value: Option<String>| {
        if let Some(v) = value.filter(|v| !v.is_empty()) {
            out.insert(key.into(), Value::String(v));
        }
    };
    text("pathPrefix", path_prefix);
    text("targetHost", host);
    text("targetPath", path);
    text("targetUri", target_uri);
    out.insert("preserveHost".into(), Value::Bool(preserve_host));
    out.insert("targetPort".into(), Value::from(port));
    out.insert("targetSecure".into(), Value::Bool(secure));
    out.sort_keys();
    Ok(Value::Object(out))
}

/// The stored `proxyPassMappings` as `GET /mockserver/configuration` prints them; `Err` when one cannot be printed.
pub fn print_proxy_pass_mappings(stored: &Value) -> Result<Value, ()> {
    let Value::Array(items) = stored else { return Ok(Value::Null) };
    items.iter().map(print_mapping).collect::<Result<Vec<_>, _>>().map(Value::Array)
}

/// The first mapping of the stored list that `print_mapping` refuses: its position, its `targetUri` and the
/// `URISyntaxException` message.
pub fn first_print_failure(stored: &Value) -> Option<(usize, String, String)> {
    let Value::Array(items) = stored else { return None };
    items.iter().enumerate().find_map(|(at, item)| {
        let uri = item.as_object()?.get("targetUri")?.as_str()?;
        crate::java_uri::parse(uri).err().map(|message| (at, uri.to_string(), message))
    })
}

/// `proxyPassMappings`: a list of mappings (one mapping alone is read as a list of one; a null element stays), or
/// `Ok(None)` for a null or blank value. An empty list is a value of its own: it switches the `proxyPass` property off.
pub fn proxy_pass_mappings(value: &Value) -> Result<Option<Value>, ()> {
    if is_blank(value) {
        return Ok(None);
    }
    let items: Vec<&Value> = match value {
        Value::Array(items) => items.iter().collect(),
        Value::Object(_) => vec![value],
        _ => return Err(()),
    };
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        out.push(if item.is_null() { Value::Null } else { proxy_pass_mapping(item)? });
    }
    Ok(Some(Value::Array(out)))
}

/// `ConfigurationProperties.proxyPass()`: the `proxyPass` property read as a list of (stored) mappings, an empty list
/// when it does not read.
pub fn proxy_pass_property(text: &str) -> Value {
    serde_json::from_str::<Value>(text).ok().and_then(|v| proxy_pass_mappings(&v).ok().flatten()).unwrap_or_else(|| Value::Array(Vec::new()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn delay_reads_like_delay_dto() {
        assert_eq!(connection_delay(&json!({})), Ok(Some(json!({"value": 0}))));
        assert_eq!(connection_delay(&json!({"timeUnit": "seconds", "value": "7"})), Ok(Some(json!({"timeUnit": "SECONDS", "value": 7}))));
        assert_eq!(connection_delay(&json!({"timeUnit": 9, "value": -1.5})), Ok(Some(json!({"value": -1}))));
        assert_eq!(connection_delay(&json!({"template": "x"})), Ok(Some(json!({"value": 0}))));
        assert_eq!(connection_delay(&json!({"value": "1.5"})), Err(()));
        assert_eq!(connection_delay(&json!("5")), Err(()));
        assert_eq!(connection_delay(&json!("")), Ok(None));
        assert_eq!(
            connection_delay(&json!({"distribution": {"type": "log_normal", "median": 0, "p99": 0, "sigma": 1}})),
            Ok(Some(json!({"distribution": {"median": 1, "p99": 1, "type": "LOG_NORMAL"}, "value": 0})))
        );
    }

    #[test]
    fn mappings_read_like_proxy_pass_mapping() {
        let printed = |v: Value| proxy_pass_mappings(&v).map(|held| held.map(|h| print_proxy_pass_mappings(&h)));
        assert_eq!(
            printed(json!({"pathPrefix": "/a", "targetUri": "https://u:p@h:0/p/?q"})),
            Ok(Some(Ok(json!([{"pathPrefix": "/a", "preserveHost": false, "targetHost": "h", "targetPath": "/p", "targetPort": 443, "targetSecure": true, "targetUri": "https://u:p@h:0/p/?q"}]))))
        );
        assert_eq!(printed(json!([{}])), Ok(Some(Ok(json!([{"preserveHost": false, "targetPort": 0, "targetSecure": false}])))));
        assert_eq!(printed(json!([null])), Ok(Some(Ok(json!([null])))));
        // read, but not printable
        assert_eq!(printed(json!([{"targetUri": "not a uri"}])), Ok(Some(Err(()))));
        assert_eq!(proxy_pass_mappings(&json!(["a"])), Err(()));
        assert_eq!(proxy_pass_mappings(&json!("x")), Err(()));
        assert_eq!(proxy_pass_mappings(&json!([])), Ok(Some(json!([]))));
    }
}
