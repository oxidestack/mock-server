//! Expectation files: JSON with `httpRequest` expectations (the `initializationJsonPath` targets,
//! persisted expectations), read for `JAVASCRIPT` templates, Velocity templates that reach for classes, and
//! `callbackClass` names.

use std::collections::HashMap;

use serde_json::Value;

use super::rules;
use super::{Finding, Severity};

/// Whether `text` is a JSON document of expectations.
pub fn is_expectations(text: &str) -> bool {
    text.contains("\"httpRequest\"") && serde_json::from_str::<Value>(text).is_ok_and(|v| v.is_array() || v.is_object())
}

/// The findings of one expectation file (an unparsable one has none).
pub fn scan(text: &str) -> Vec<Finding> {
    let Ok(document) = serde_json::from_str::<Value>(text) else { return Vec::new() };
    let mut walker = Walker { text, cursors: HashMap::new(), findings: Vec::new() };
    walker.value(&document, "");
    walker.findings
}

struct Walker<'a> {
    text: &'a str,
    cursors: HashMap<&'static str, usize>,
    findings: Vec<Finding>,
}

impl Walker<'_> {
    fn value(&mut self, value: &Value, parent: &str) {
        match value {
            Value::Array(items) => items.iter().for_each(|v| self.value(v, parent)),
            Value::Object(map) => {
                for (key, v) in map {
                    match (key.as_str(), v) {
                        ("templateType", Value::String(kind)) => self.template(map, kind, parent),
                        ("callbackClass", Value::String(class)) => {
                            let line = self.locate("callbackClass", class);
                            self.findings.push(Finding::new(rules::CLASSPATH_CALLBACK, Severity::Action, line, format!("{parent}.callbackClass {class}"), format!("Java classes are not loaded: rebuild {class} as a callback plugin ({}); the name stays the same here", rules::PLUGIN_SDK)).key(format!("{parent}.callbackClass")));
                        }
                        _ => self.value(v, key),
                    }
                }
            }
            _ => {}
        }
    }

    fn template(&mut self, map: &serde_json::Map<String, Value>, kind: &str, parent: &str) {
        let template = map.get("template").and_then(Value::as_str).unwrap_or("");
        if kind.eq_ignore_ascii_case("JAVASCRIPT") {
            let line = self.locate("templateType", kind);
            self.findings.push(
                Finding::new(rules::TEMPLATE_JAVASCRIPT, Severity::Blocker, line, format!("{parent} templateType {kind}"), format!("no JavaScript engine: rewrite the template in Velocity or Mustache. The MockServer {} image fails it the same way, so it only ran on the graaljs variant", crate::control::VERSION))
                    .key(format!("{parent}.templateType")),
            );
        } else if kind.eq_ignore_ascii_case("VELOCITY") && (template.contains(".class") || template.contains("loadClass") || template.contains(".getClass(")) {
            let line = self.locate("templateType", kind);
            self.findings.push(
                Finding::new(rules::TEMPLATE_VELOCITY_CLASS, Severity::Action, line, format!("{parent} Velocity template using .class"), "the Velocity sandbox stays on (velocityDisallowClassLoading has no effect): JDK classes are out of reach; the foreign runtime is the only way")
                    .key(format!("{parent}.template")),
            );
        }
    }

    /// The line of the next `"key": "value"` in the text.
    fn locate(&mut self, key: &'static str, value: &str) -> usize {
        let quoted_key = format!("\"{key}\"");
        let quoted_value = serde_json::to_string(value).unwrap_or_default();
        let mut at = *self.cursors.get(key).unwrap_or(&0);
        while let Some(i) = self.text[at..].find(&quoted_key) {
            let start = at + i;
            at = start + quoted_key.len();
            let rest = self.text[at..].trim_start();
            if let Some(rest) = rest.strip_prefix(':') && rest.trim_start().starts_with(&quoted_value) {
                self.cursors.insert(key, at);
                return super::line_of(self.text, start);
            }
        }
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn templates_and_callbacks_are_found_on_their_lines() {
        let text = r#"[
  {
    "httpRequest": {"path": "/js"},
    "httpResponseTemplate": {
      "templateType": "JAVASCRIPT",
      "template": "return { statusCode: 200 };"
    }
  },
  {
    "httpRequest": {"path": "/mustache"},
    "httpResponseTemplate": {"templateType": "MUSTACHE", "template": "{}"}
  },
  {
    "httpRequest": {"path": "/velocity"},
    "httpForwardTemplate": {
      "templateType": "VELOCITY",
      "template": "$request.class.forName('java.lang.Runtime')"
    }
  },
  {
    "httpRequest": {"path": "/cb"},
    "httpResponseClassCallback": {"callbackClass": "com.acme.Greeter"}
  }
]"#;
        assert!(is_expectations(text));
        let found: Vec<(&str, Severity, usize)> = scan(text).iter().map(|f| (f.rule, f.severity, f.line)).collect();
        assert_eq!(found, [(rules::TEMPLATE_JAVASCRIPT, Severity::Blocker, 5), (rules::TEMPLATE_VELOCITY_CLASS, Severity::Action, 16), (rules::CLASSPATH_CALLBACK, Severity::Action, 22)]);
        assert_eq!(scan(text)[0].found, "httpResponseTemplate templateType JAVASCRIPT");
    }

    #[test]
    fn other_json_is_not_expectations() {
        assert!(!is_expectations("{\"panels\": [], \"schemaVersion\": 39}"));
        assert!(!is_expectations("{\"httpRequest\": "));
    }
}
