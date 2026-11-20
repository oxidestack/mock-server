//! MockServer property files: `mockserver.properties` and any `*.properties` with `mockserver.` keys, and
//! the JSON property files (`mockserver*.json`, an object of keys without the `mockserver.` prefix). Every key goes
//! through [`rules::config_setting`]; nothing here is rewritten.

use super::rules::{self, Source};
use super::Finding;

/// Whether a `.properties` text has MockServer keys.
pub fn has_mockserver_keys(text: &str) -> bool {
    entries(text).iter().any(|(_, key, _)| key.starts_with("mockserver."))
}

/// Each `key=value` line: its line number, key and value (one logical line per physical line; continuation lines
/// are read as their own entries, which only matters for values).
fn entries(text: &str) -> Vec<(usize, String, String)> {
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim_start();
        if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
            continue;
        }
        let end = line.find(['=', ':', ' ', '\t']).unwrap_or(line.len());
        let key = line[..end].to_string();
        let rest = line[end..].trim_start();
        let value = rest.strip_prefix(['=', ':']).unwrap_or(rest).trim_start().to_string();
        out.push((n + 1, key, value));
    }
    out
}

/// The findings of a `.properties` file.
pub fn scan(text: &str) -> Vec<Finding> {
    entries(text)
        .into_iter()
        .filter(|(_, key, _)| key.starts_with("mockserver."))
        .flat_map(|(line, key, value)| rules::config_setting(&key, &value, Source::Property).into_iter().map(move |f| Finding { line, ..f }.key(key.clone())))
        .collect()
}

/// Whether `text` is a JSON property file: an object whose keys include a recognised configuration key, and no
/// expectation.
pub fn is_json_properties(text: &str) -> bool {
    !text.contains("\"httpRequest\"") && matches!(serde_json::from_str::<serde_json::Value>(text), Ok(serde_json::Value::Object(map)) if map.keys().any(|k| rules::is_recognised(k)))
}

/// The findings of a JSON property file.
pub fn scan_json(text: &str) -> Vec<Finding> {
    let Ok(serde_json::Value::Object(map)) = serde_json::from_str::<serde_json::Value>(text) else { return Vec::new() };
    let mut cursor = 0;
    let mut findings = Vec::new();
    for (key, value) in &map {
        if value.is_null() {
            continue;
        }
        let quoted = format!("\"{key}\"");
        let line = match text[cursor..].find(&quoted) {
            Some(i) => {
                cursor += i + quoted.len();
                super::line_of(text, cursor)
            }
            None => 1,
        };
        let value = value.as_str().map_or_else(|| value.to_string(), String::from);
        findings.extend(rules::config_setting(&format!("mockserver.{key}"), &value, Source::Property).into_iter().map(|f| Finding { line, ..f }.key(key.clone())));
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrate::Severity;

    #[test]
    fn properties_keys() {
        let text = "# MockServer\nmockserver.logLevel=INFO\nmockserver.useNativeTransport : true\nmockserver.typoThing 1\nother.key=1\n";
        assert!(has_mockserver_keys(text));
        let found: Vec<(&str, Severity, usize)> = scan(text).iter().map(|f| (f.rule, f.severity, f.line)).collect();
        assert_eq!(found, [(rules::CONFIG_KEY, Severity::Info, 2), (rules::CONFIG_KEY, Severity::Info, 3), (rules::CONFIG_KEY, Severity::Warn, 4)]);
        assert!(!has_mockserver_keys("a=b\n"));
    }

    #[test]
    fn json_property_files() {
        let text = "{\n  \"logLevel\": \"WARN\",\n  \"javascriptAllowedClasses\": \"x\",\n  \"maxExpectations\": 5\n}\n";
        assert!(is_json_properties(text));
        let found: Vec<(Severity, usize, String)> = scan_json(text).into_iter().map(|f| (f.severity, f.line, f.found)).collect();
        assert_eq!(found, [(Severity::Info, 2, "mockserver.logLevel=WARN".to_string()), (Severity::Warn, 3, "mockserver.javascriptAllowedClasses=x".into()), (Severity::Info, 4, "mockserver.maxExpectations=5".into())]);
        assert!(!is_json_properties("{\"panels\": []}"));
    }
}
