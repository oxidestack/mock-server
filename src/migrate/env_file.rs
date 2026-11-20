//! Environment files: `.env` files (`[export ]NAME=value` lines) and, with `--env`, this process's
//! environment. Variables go through [`rules::env_var`]; in a file a mapped JVM option becomes a line of its own.

use super::rules::{self, EnvBlock, EnvVar};
use super::{Context, Finding};

/// Whether a file name is an environment file.
pub fn is_env_file(name: &str) -> bool {
    name == ".env" || name.starts_with(".env.") || name.ends_with(".env")
}

/// The variables of an environment file.
fn variables(text: &str) -> Vec<EnvVar> {
    let mut vars = Vec::new();
    let mut offset = 0;
    for (n, raw) in text.split_inclusive('\n').enumerate() {
        let start = offset;
        offset += raw.len();
        let line = raw.trim_end_matches(['\n', '\r']);
        let body = line.trim_start();
        if body.is_empty() || body.starts_with('#') {
            continue;
        }
        let lead = line.len() - body.len();
        let (body, lead) = match body.strip_prefix("export ") {
            Some(rest) => (rest.trim_start(), lead + (body.len() - rest.trim_start().len())),
            None => (body, lead),
        };
        let Some((name, value)) = body.split_once('=') else { continue };
        let value_start = start + lead + name.len() + 1;
        let (value, span) = match value.as_bytes().first() {
            Some(&q @ (b'"' | b'\'')) if value.len() >= 2 && value.ends_with(q as char) => {
                let inner = &value[1..value.len() - 1];
                (inner.to_string(), (!inner.contains('\\')).then_some((value_start + 1, value_start + value.len() - 1)))
            }
            _ => {
                let value = value.split(" #").next().unwrap_or(value).trim_end();
                (value.to_string(), Some((value_start, value_start + value.len())))
            }
        };
        vars.push(EnvVar { name: name.trim().to_string(), value, line: n + 1, key: name.trim().to_string(), span, entry: Some((start, offset)) });
    }
    vars
}

/// The findings of an environment file.
pub fn scan(text: &str, ctx: &Context) -> Vec<Finding> {
    let vars = variables(text);
    let missing_newline = std::cell::Cell::new(!text.is_empty() && !text.ends_with('\n'));
    let render = |name: &str, value: &str| {
        let value = if value.chars().any(|c| c.is_whitespace() || "#\"'$".contains(c)) { format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\"")) } else { value.to_string() };
        let prefix = if missing_newline.replace(false) { "\n" } else { "" };
        format!("{prefix}{name}={value}\n")
    };
    let existing = |name: &str| vars.iter().find(|v| v.name == name).and_then(|v| v.span);
    let block = EnvBlock { insert_at: text.len(), render: &render, existing: &existing };
    vars.iter().flat_map(|var| rules::env_var(var, Some(&block), ctx)).collect()
}

/// The findings of this process's environment (`--env`), sorted by name; nothing to rewrite.
pub fn scan_process(env: &[(String, String)], ctx: &Context) -> Vec<Finding> {
    let mut env: Vec<&(String, String)> = env.iter().collect();
    env.sort();
    env.iter().flat_map(|(name, value)| rules::env_var(&EnvVar { name: name.clone(), value: value.clone(), line: 0, key: name.clone(), span: None, entry: None }, None, ctx)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrate::Severity;

    #[test]
    fn env_files_are_rewritten() {
        let text = "# mock\nexport JAVA_TOOL_OPTIONS=\"-Xmx64m -Dmockserver.logLevel=WARN\"\nMOCKSERVER_TYPO=1\nPATH=/bin";
        let found = scan(text, &Context::default());
        let summary: Vec<(&str, Severity, usize)> = found.iter().map(|f| (f.rule, f.severity, f.line)).collect();
        assert_eq!(summary, [(rules::JVM_MEMORY, Severity::Info, 2), (rules::JVM_PROPERTY, Severity::Rewrite, 2), (rules::CONFIG_KEY, Severity::Info, 2), (rules::CONFIG_KEY, Severity::Warn, 3)]);
        let edits: Vec<_> = found.into_iter().flat_map(|f| f.edits).collect();
        assert_eq!(super::super::apply_edits(text, &edits).unwrap(), "# mock\nexport JAVA_TOOL_OPTIONS=\"-Xmx64m\"\nMOCKSERVER_TYPO=1\nPATH=/bin\nMOCKSERVER_LOG_LEVEL=WARN\n");
    }

    #[test]
    fn the_process_environment_is_reported_only() {
        let env = vec![("MOCKSERVER_USE_NATIVE_TRANSPORT".to_string(), "true".to_string()), ("JAVA_OPTS".to_string(), "-Dmockserver.logLevel=INFO".to_string()), ("HOME".to_string(), "/root".to_string())];
        let found = scan_process(&env, &Context::default());
        assert_eq!(found.iter().map(|f| (f.rule, f.mechanical)).collect::<Vec<_>>(), [(rules::JVM_PROPERTY, false), (rules::CONFIG_KEY, false), (rules::CONFIG_KEY, false)]);
        assert!(is_env_file(".env") && is_env_file(".env.production") && is_env_file("mock.env") && !is_env_file("env.yaml"));
    }
}
